package peer

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

func TestRegistryLearnsAndAuthenticatesPeer(t *testing.T) {
	controller := registryIdentity(t, 0x11)
	remote := registryIdentity(t, 0x22)
	keyBytes, err := controller.Agree(remote.Public(), 32)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], keyBytes)
	now := time.Unix(1_700_000_000, 0).UTC()
	registry := NewRegistry()
	session, err := registry.LearnHello(packet.Hello{
		Identity: remote.Public(), ProtocolVersion: 13, Major: 1, Minor: 14,
		ExternalSurface: &packet.InetAddress{Address: netip.MustParseAddr("192.0.2.1"), Port: 9993},
	}, key, netip.MustParseAddrPort("198.51.100.1:40000"), now)
	if err != nil {
		t.Fatal(err)
	}
	if session.Identity.HasPrivate() || session.Endpoint.String() != "198.51.100.1:40000" {
		t.Fatalf("unexpected learned session: %+v", session)
	}

	draft, err := packet.Build(1, controller.Address(), remote.Address(), packet.VerbEcho, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	armored, err := packet.Armor(draft, key, true)
	if err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Second)
	decoded, authenticated, err := registry.Authenticate(
		armored, controller.Address(), netip.MustParseAddrPort("198.51.100.2:40001"), later,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Verb != packet.VerbEcho || !bytes.Equal(decoded.Payload, []byte("ping")) ||
		!authenticated.LastSeen.Equal(later) {
		t.Fatalf("unexpected authenticated packet/session: %+v %+v", decoded, authenticated)
	}
}

func TestRegistryRejectsUnknownAndTamperedPackets(t *testing.T) {
	controller := registryIdentity(t, 0x33)
	remote := registryIdentity(t, 0x44)
	var key [32]byte
	draft, err := packet.Build(1, controller.Address(), remote.Address(), packet.VerbEcho, nil)
	if err != nil {
		t.Fatal(err)
	}
	armored, err := packet.Armor(draft, key, true)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	if _, _, err := registry.Authenticate(
		armored, controller.Address(), netip.MustParseAddrPort("192.0.2.1:9993"), time.Now(),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want peer not found", err)
	}
}

func TestRegistryRejectsUnvalidatedIdentity(t *testing.T) {
	remote := registryIdentity(t, 0x55).Public()
	collidingText := remote.String()
	replacement := "0"
	if collidingText[len(collidingText)-1] == '0' {
		replacement = "1"
	}
	colliding, err := identity.Parse(collidingText[:len(collidingText)-1] + replacement)
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry()
	hello := packet.Hello{Identity: remote, ProtocolVersion: 13}
	if _, err := registry.LearnHello(hello, [32]byte{}, netip.MustParseAddrPort("192.0.2.1:1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	hello.Identity = colliding
	if _, err := registry.LearnHello(hello, [32]byte{}, netip.MustParseAddrPort("192.0.2.2:2"), time.Now()); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("got %v, want invalid identity", err)
	}
}

func registryIdentity(t *testing.T, fill byte) identity.Identity {
	t.Helper()
	value, err := identity.Generate(
		context.Background(),
		bytes.NewReader(bytes.Repeat([]byte{fill}, identity.PrivateKeyLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
