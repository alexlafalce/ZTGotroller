package packet

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

func TestHelloBootstrapAndReply(t *testing.T) {
	controller := helloController(t)
	peer, err := identity.Generate(
		context.Background(),
		bytes.NewReader(bytes.Repeat([]byte{0x42}, identity.PrivateKeyLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, err := peer.Public().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{ProtocolVersionCurrent, 1, 14, 0, 2}
	payload = binary.BigEndian.AppendUint64(payload, 1_700_000_000_000)
	payload = append(payload, peerPublic...)
	payload = append(payload, 4, 192, 0, 2, 10, 0x27, 0x0f)
	draft, err := Build(77, controller.Address(), peer.Address(), VerbHello, payload)
	if err != nil {
		t.Fatal(err)
	}
	agreed, err := peer.Agree(controller.Public(), 32)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], agreed)
	armored, err := Armor(draft, key, false)
	if err != nil {
		t.Fatal(err)
	}

	hello, derived, err := AuthenticateHello(armored, controller)
	if err != nil {
		t.Fatal(err)
	}
	if derived != key || hello.Identity.Address() != peer.Address() ||
		hello.ExternalSurface == nil ||
		hello.ExternalSurface.Address.String() != "192.0.2.10" ||
		hello.ExternalSurface.Port != 9999 {
		t.Fatalf("unexpected HELLO: %+v", hello)
	}

	reply, err := BuildHelloOK(
		88,
		hello,
		controller,
		InetAddress{Address: netip.MustParseAddr("198.51.100.20"), Port: 4321},
		LocalVersion{Protocol: ProtocolVersionCurrent, Major: 0, Minor: 1},
		derived,
	)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Dearmor(reply, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Verb != VerbOK || decoded.Payload[0] != byte(VerbHello) ||
		binary.BigEndian.Uint64(decoded.Payload[1:9]) != 77 ||
		binary.BigEndian.Uint64(decoded.Payload[9:17]) != hello.Timestamp {
		t.Fatalf("unexpected HELLO OK: %+v", decoded)
	}
}

func TestHelloRejectsTamperedIdentity(t *testing.T) {
	controller := helloController(t)
	peer := controller.Public()
	public, err := peer.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{ProtocolVersionCurrent, 1, 0, 0, 0}
	payload = binary.BigEndian.AppendUint64(payload, 1)
	payload = append(payload, public...)
	draft, err := Build(1, controller.Address(), peer.Address(), VerbHello, payload)
	if err != nil {
		t.Fatal(err)
	}
	agreed, err := controller.Agree(peer, 32)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], agreed)
	armored, err := Armor(draft, key, false)
	if err != nil {
		t.Fatal(err)
	}
	armored[len(armored)-2] ^= 1
	if _, _, err := AuthenticateHello(armored, controller); err == nil {
		t.Fatal("tampered HELLO passed authentication")
	}
}

func helloController(t *testing.T) identity.Identity {
	t.Helper()
	const secret = "8e4df28b72:0:" +
		"ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843" +
		"fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:" +
		"bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bdd" +
		"d63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e"
	value, err := identity.Parse(secret)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
