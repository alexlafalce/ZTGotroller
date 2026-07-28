package transport

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
)

type Handler struct {
	service  *controller.Service
	identity identity.Identity
	peers    *peer.Registry
	random   io.Reader
	now      func() time.Time
	version  packet.LocalVersion
	hellos   *helloLimiter
}

func NewHandler(
	service *controller.Service,
	controllerIdentity identity.Identity,
	peers *peer.Registry,
) (*Handler, error) {
	if service == nil {
		return nil, errors.New("controller service is required")
	}
	if !controllerIdentity.HasPrivate() {
		return nil, errors.New("controller identity must include its private key")
	}
	if peers == nil {
		peers = peer.NewRegistry()
	}
	return &Handler{
		service:  service,
		identity: controllerIdentity,
		peers:    peers,
		random:   rand.Reader,
		now:      time.Now,
		version: packet.LocalVersion{
			Protocol: packet.ProtocolVersionCurrent,
			Major:    0,
			Minor:    1,
		},
		hellos: newHelloLimiter(),
	}, nil
}

func (handler *Handler) Registry() *peer.Registry {
	return handler.peers
}

// Handle processes one complete UDP datagram and returns complete datagrams to
// send to the authenticated source endpoint.
func (handler *Handler) Handle(
	ctx context.Context,
	datagram []byte,
	remote netip.AddrPort,
) ([][]byte, error) {
	if !remote.IsValid() {
		return nil, errors.New("remote endpoint is invalid")
	}
	if packet.IsFragment(datagram) {
		return nil, errors.New("fragment reassembly is not yet available")
	}
	routing, err := packet.ParseRouting(datagram)
	if err != nil {
		return nil, err
	}
	if routing.Destination != handler.identity.Address() {
		return nil, errors.New("datagram is addressed to another controller")
	}
	if routing.Cipher == packet.CipherC25519Poly1305Clear &&
		len(datagram) > 27 && packet.Verb(datagram[27]&0x1f) == packet.VerbHello {
		if !handler.hellos.allow(remote.Addr(), handler.now()) {
			return nil, errors.New("HELLO rate limit exceeded")
		}
		return handler.handleHello(datagram, remote)
	}
	decoded, session, err := handler.peers.Authenticate(
		datagram, handler.identity.Address(), remote, handler.now(),
	)
	if err != nil {
		return nil, err
	}
	decoded, err = packet.Decompress(decoded, packet.MaxPacketLength-packet.HeaderLength)
	if err != nil {
		return nil, err
	}
	switch decoded.Verb {
	case packet.VerbNetworkConfigRequest:
		replies, err := handler.service.HandleConfigRequest(
			ctx, decoded, session.Identity, handler.identity,
		)
		if err != nil {
			return nil, err
		}
		datagrams := make([][]byte, 0, len(replies))
		for _, reply := range replies {
			packetID, err := handler.packetID()
			if err != nil {
				return nil, err
			}
			draft, err := packet.Build(
				packetID,
				session.Identity.Address(),
				handler.identity.Address(),
				reply.Verb,
				reply.Payload,
			)
			if err != nil {
				return nil, err
			}
			armored, err := packet.ArmorSessionAndFragment(
				draft,
				session.SharedKey,
				true,
				session.ProtocolVersion >= 12,
				packet.DefaultPhysicalMTU,
			)
			if err != nil {
				return nil, err
			}
			datagrams = append(datagrams, armored...)
		}
		return datagrams, nil
	default:
		return nil, fmt.Errorf("unsupported authenticated verb %d", decoded.Verb)
	}
}

func (handler *Handler) handleHello(datagram []byte, remote netip.AddrPort) ([][]byte, error) {
	hello, sharedKey, err := packet.AuthenticateHello(datagram, handler.identity)
	if err != nil {
		return nil, err
	}
	if _, err := handler.peers.LearnHello(hello, sharedKey, remote, handler.now()); err != nil {
		return nil, err
	}
	packetID, err := handler.packetID()
	if err != nil {
		return nil, err
	}
	reply, err := packet.BuildHelloOK(
		packetID,
		hello,
		handler.identity,
		packet.InetAddress{Address: remote.Addr(), Port: remote.Port()},
		handler.version,
		sharedKey,
	)
	if err != nil {
		return nil, err
	}
	// HELLO OK is small, but route it through the same MTU enforcement.
	if len(reply) > packet.DefaultPhysicalMTU {
		return nil, errors.New("HELLO OK unexpectedly exceeds physical MTU")
	}
	return [][]byte{reply}, nil
}

func (handler *Handler) packetID() (uint64, error) {
	var serialized [8]byte
	for {
		if _, err := io.ReadFull(handler.random, serialized[:]); err != nil {
			return 0, fmt.Errorf("generate packet ID: %w", err)
		}
		value := binary.BigEndian.Uint64(serialized[:])
		if value != 0 {
			return value, nil
		}
	}
}
