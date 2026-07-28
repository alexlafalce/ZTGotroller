package peer

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

var (
	ErrNotFound          = errors.New("peer not found")
	ErrInvalidIdentity   = errors.New("peer identity is invalid")
	ErrIdentityCollision = errors.New("peer identity collision")
)

const (
	sessionIdleTTL      = 10 * time.Minute
	sessionPruneEvery   = time.Minute
	maxRegistrySessions = 16384
)

type Session struct {
	Identity        identity.Identity
	SharedKey       packet.SessionKey
	Endpoint        netip.AddrPort
	ExternalSurface *packet.InetAddress
	ProtocolVersion byte
	Major           byte
	Minor           byte
	Revision        uint16
	LastSeen        time.Time
	configured      bool
}

type Registry struct {
	mu        sync.RWMutex
	sessions  map[domain.NodeID]Session
	lastPrune time.Time
}

func NewRegistry() *Registry {
	return &Registry{sessions: make(map[domain.NodeID]Session)}
}

func (registry *Registry) RegisterConfigured(
	peerIdentity identity.Identity,
	sharedKey packet.SessionKey,
	endpoint netip.AddrPort,
	now time.Time,
) (Session, error) {
	if !peerIdentity.LocallyValidate() {
		return Session{}, ErrInvalidIdentity
	}
	if !endpoint.IsValid() || now.IsZero() {
		return Session{}, errors.New("configured peer endpoint and observation time are required")
	}
	session := Session{
		Identity:   peerIdentity.Public(),
		SharedKey:  sharedKey,
		Endpoint:   endpoint,
		LastSeen:   now.UTC(),
		configured: true,
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if existing, ok := registry.sessions[peerIdentity.Address()]; ok &&
		existing.Identity.String() != session.Identity.String() {
		return Session{}, fmt.Errorf("%w for address %s", ErrIdentityCollision, peerIdentity.Address())
	}
	registry.sessions[peerIdentity.Address()] = session
	return cloneSession(session), nil
}

func (registry *Registry) LearnHello(
	hello packet.Hello,
	sharedKey packet.SessionKey,
	endpoint netip.AddrPort,
	now time.Time,
) (Session, error) {
	if !endpoint.IsValid() {
		return Session{}, errors.New("peer endpoint is invalid")
	}
	if now.IsZero() {
		return Session{}, errors.New("peer observation time is required")
	}
	if !hello.Identity.LocallyValidate() {
		return Session{}, ErrInvalidIdentity
	}
	return registry.LearnValidatedHello(hello, sharedKey, endpoint, now)
}

// LearnValidatedHello records a HELLO whose identity proof and packet MAC were
// already verified by packet.AuthenticateHello.
func (registry *Registry) LearnValidatedHello(
	hello packet.Hello,
	sharedKey packet.SessionKey,
	endpoint netip.AddrPort,
	now time.Time,
) (Session, error) {
	if !endpoint.IsValid() {
		return Session{}, errors.New("peer endpoint is invalid")
	}
	if now.IsZero() {
		return Session{}, errors.New("peer observation time is required")
	}
	nodeID := hello.Identity.Address()
	if err := nodeID.Validate(); err != nil {
		return Session{}, ErrInvalidIdentity
	}
	session := Session{
		Identity:        hello.Identity.Public(),
		SharedKey:       sharedKey,
		Endpoint:        endpoint,
		ExternalSurface: cloneInetAddress(hello.ExternalSurface),
		ProtocolVersion: hello.ProtocolVersion,
		Major:           hello.Major,
		Minor:           hello.Minor,
		Revision:        hello.Revision,
		LastSeen:        now.UTC(),
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.pruneLocked(now.UTC(), false)
	if existing, ok := registry.sessions[nodeID]; ok &&
		existing.Identity.String() != session.Identity.String() {
		return Session{}, fmt.Errorf("%w for address %s", ErrIdentityCollision, nodeID)
	}
	if _, exists := registry.sessions[nodeID]; !exists && len(registry.sessions) >= maxRegistrySessions {
		return Session{}, errors.New("peer session capacity exhausted")
	}
	registry.sessions[nodeID] = session
	return cloneSession(session), nil
}

// Prune removes inactive learned sessions while preserving configured
// upstreams. It is safe to call periodically or opportunistically.
func (registry *Registry) Prune(now time.Time) int {
	if now.IsZero() {
		return 0
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return registry.pruneLocked(now.UTC(), true)
}

func (registry *Registry) pruneLocked(now time.Time, force bool) int {
	if !force && !registry.lastPrune.IsZero() && now.Sub(registry.lastPrune) < sessionPruneEvery {
		return 0
	}
	removed := 0
	for nodeID, session := range registry.sessions {
		if !session.configured && now.Sub(session.LastSeen) >= sessionIdleTTL {
			delete(registry.sessions, nodeID)
			removed++
		}
	}
	registry.lastPrune = now
	return removed
}

func (registry *Registry) Get(nodeID domain.NodeID) (Session, error) {
	if err := nodeID.Validate(); err != nil {
		return Session{}, err
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	session, ok := registry.sessions[nodeID]
	if !ok {
		return Session{}, ErrNotFound
	}
	return cloneSession(session), nil
}

func (registry *Registry) List() []Session {
	registry.mu.RLock()
	sessions := make([]Session, 0, len(registry.sessions))
	for _, session := range registry.sessions {
		sessions = append(sessions, cloneSession(session))
	}
	registry.mu.RUnlock()
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Identity.Address() < sessions[j].Identity.Address()
	})
	return sessions
}

func (registry *Registry) Authenticate(
	armored []byte,
	destination domain.NodeID,
	endpoint netip.AddrPort,
	now time.Time,
) (packet.Decoded, Session, error) {
	routing, err := packet.ParseRouting(armored)
	if err != nil {
		return packet.Decoded{}, Session{}, err
	}
	if routing.Destination != destination {
		return packet.Decoded{}, Session{}, errors.New("packet is addressed to another identity")
	}
	registry.mu.RLock()
	session, ok := registry.sessions[routing.Source]
	registry.mu.RUnlock()
	if !ok {
		return packet.Decoded{}, Session{}, ErrNotFound
	}
	decoded, err := packet.DearmorSession(armored, session.SharedKey)
	if err != nil {
		return packet.Decoded{}, Session{}, err
	}
	if now.IsZero() {
		return packet.Decoded{}, Session{}, errors.New("packet observation time is required")
	}
	if !endpoint.IsValid() {
		return packet.Decoded{}, Session{}, errors.New("packet endpoint is invalid")
	}
	session.LastSeen = now.UTC()
	session.Endpoint = endpoint
	registry.mu.Lock()
	current, stillPresent := registry.sessions[routing.Source]
	if stillPresent && current.Identity.String() == session.Identity.String() {
		current.LastSeen = session.LastSeen
		current.Endpoint = endpoint
		registry.sessions[routing.Source] = current
		session = current
	}
	registry.mu.Unlock()
	return decoded, cloneSession(session), nil
}

func cloneSession(session Session) Session {
	session.Identity = session.Identity.Public()
	session.ExternalSurface = cloneInetAddress(session.ExternalSurface)
	return session
}

func cloneInetAddress(address *packet.InetAddress) *packet.InetAddress {
	if address == nil {
		return nil
	}
	cloned := *address
	return &cloned
}
