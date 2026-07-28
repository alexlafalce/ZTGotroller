package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
)

type Upstream struct {
	Identity  identity.Identity
	Endpoints []netip.AddrPort
}

type upstreamFile struct {
	Upstreams []struct {
		Identity  string   `json:"identity"`
		Endpoints []string `json:"endpoints"`
	} `json:"upstreams"`
}

func LoadUpstreams(path string) ([]Upstream, error) {
	serialized, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var source upstreamFile
	if err := json.Unmarshal(serialized, &source); err != nil {
		return nil, fmt.Errorf("decode upstreams: %w", err)
	}
	result := make([]Upstream, 0, len(source.Upstreams))
	for index, item := range source.Upstreams {
		peerIdentity, err := identity.Parse(item.Identity)
		if err != nil || peerIdentity.HasPrivate() || !peerIdentity.LocallyValidate() {
			return nil, fmt.Errorf("upstream %d has an invalid public identity", index)
		}
		if len(item.Endpoints) == 0 {
			return nil, fmt.Errorf("upstream %d has no endpoints", index)
		}
		upstream := Upstream{Identity: peerIdentity}
		for _, value := range item.Endpoints {
			endpoint, err := netip.ParseAddrPort(value)
			if err != nil {
				return nil, fmt.Errorf("upstream %d endpoint %q: %w", index, value, err)
			}
			upstream.Endpoints = append(upstream.Endpoints, endpoint)
		}
		result = append(result, upstream)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one upstream is required")
	}
	return result, nil
}

type UpstreamManager struct {
	connection *net.UDPConn
	local      identity.Identity
	peers      *peer.Registry
	upstreams  []Upstream
	interval   time.Duration
	random     io.Reader
	now        func() time.Time
	mu         sync.Mutex
	pending    map[uint64]pendingHello
	status     map[string]UpstreamStatus
}

type UpstreamStatus struct {
	Peer        domain.NodeID `json:"peer"`
	Endpoint    string        `json:"endpoint"`
	LastAttempt time.Time     `json:"lastAttempt,omitempty"`
	LastSuccess time.Time     `json:"lastSuccess,omitempty"`
	Pending     bool          `json:"pending"`
}

type pendingHello struct {
	peer      domain.NodeID
	endpoint  netip.AddrPort
	timestamp uint64
	expires   time.Time
}

func NewUpstreamManager(
	connection *net.UDPConn,
	local identity.Identity,
	peers *peer.Registry,
	upstreams []Upstream,
	interval time.Duration,
) (*UpstreamManager, error) {
	if connection == nil || !local.HasPrivate() || peers == nil || len(upstreams) == 0 {
		return nil, errors.New("connection, private identity, registry, and upstreams are required")
	}
	if interval <= 0 {
		return nil, errors.New("upstream announcement interval must be positive")
	}
	return &UpstreamManager{
		connection: connection, local: local, peers: peers, upstreams: upstreams,
		interval: interval, random: rand.Reader, now: time.Now,
		pending: make(map[uint64]pendingHello), status: make(map[string]UpstreamStatus),
	}, nil
}

func (manager *UpstreamManager) Run(ctx context.Context) error {
	if err := manager.announce(); err != nil {
		return err
	}
	ticker := time.NewTicker(manager.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := manager.announce(); err != nil {
				return err
			}
		}
	}
}

func (manager *UpstreamManager) announce() error {
	now := manager.now()
	for _, upstream := range manager.upstreams {
		agreed, err := manager.local.Agree(upstream.Identity, packet.SessionKeyLength)
		if err != nil {
			return err
		}
		var key packet.SessionKey
		copy(key[:], agreed)
		for _, endpoint := range upstream.Endpoints {
			if _, err := manager.peers.RegisterConfigured(upstream.Identity, key, endpoint, now); err != nil {
				return err
			}
			packetID, err := randomPacketID(manager.random)
			if err != nil {
				return err
			}
			timestamp := uint64(now.UnixMilli())
			hello, err := packet.BuildHello(packetID, upstream.Identity, manager.local,
				packet.LocalVersion{Protocol: packet.ProtocolVersionCurrent, Major: 0, Minor: 1},
				timestamp, 0, 0, key)
			if err != nil {
				return err
			}
			manager.mu.Lock()
			manager.pending[packetID] = pendingHello{
				peer: upstream.Identity.Address(), endpoint: endpoint,
				timestamp: timestamp, expires: now.Add(manager.interval),
			}
			key := upstreamStatusKey(upstream.Identity.Address(), endpoint)
			current := manager.status[key]
			current.Peer = upstream.Identity.Address()
			current.Endpoint = endpoint.String()
			current.LastAttempt = now.UTC()
			current.Pending = true
			manager.status[key] = current
			for id, pending := range manager.pending {
				if !pending.expires.After(now) {
					delete(manager.pending, id)
				}
			}
			manager.mu.Unlock()
			if _, err := manager.connection.WriteToUDPAddrPort(hello, endpoint); err != nil {
				return fmt.Errorf("announce to upstream %s: %w", endpoint, err)
			}
		}
	}
	return nil
}

func (manager *UpstreamManager) Handle(datagram []byte, remote netip.AddrPort) (bool, error) {
	routing, err := packet.ParseRouting(datagram)
	if err != nil || routing.Destination != manager.local.Address() {
		return false, err
	}
	manager.mu.Lock()
	isUpstream := false
	for _, upstream := range manager.upstreams {
		if upstream.Identity.Address() == routing.Source {
			isUpstream = true
			break
		}
	}
	manager.mu.Unlock()
	if !isUpstream {
		return false, nil
	}
	decoded, _, err := manager.peers.Authenticate(datagram, manager.local.Address(), remote, manager.now())
	if err != nil {
		return true, err
	}
	if decoded.Verb != packet.VerbOK {
		return false, nil
	}
	reply, err := packet.ParseHelloOK(decoded)
	if err != nil {
		return true, err
	}
	manager.mu.Lock()
	pending, ok := manager.pending[reply.RequestPacketID]
	if ok {
		delete(manager.pending, reply.RequestPacketID)
	}
	manager.mu.Unlock()
	if !ok || pending.peer != routing.Source || pending.endpoint != remote ||
		pending.timestamp != reply.Timestamp {
		return true, errors.New("HELLO OK does not match a pending upstream announcement")
	}
	manager.mu.Lock()
	key := upstreamStatusKey(routing.Source, remote)
	current := manager.status[key]
	current.Peer = routing.Source
	current.Endpoint = remote.String()
	current.LastSuccess = manager.now().UTC()
	current.Pending = false
	manager.status[key] = current
	manager.mu.Unlock()
	return true, nil
}

func (manager *UpstreamManager) Status() []UpstreamStatus {
	manager.mu.Lock()
	result := make([]UpstreamStatus, 0, len(manager.status))
	for _, status := range manager.status {
		result = append(result, status)
	}
	manager.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Peer == result[j].Peer {
			return result[i].Endpoint < result[j].Endpoint
		}
		return result[i].Peer < result[j].Peer
	})
	return result
}

func upstreamStatusKey(peer domain.NodeID, endpoint netip.AddrPort) string {
	return string(peer) + "@" + endpoint.String()
}

func randomPacketID(source io.Reader) (uint64, error) {
	var buffer [8]byte
	for {
		if _, err := io.ReadFull(source, buffer[:]); err != nil {
			return 0, err
		}
		if value := binary.BigEndian.Uint64(buffer[:]); value != 0 {
			return value, nil
		}
	}
}
