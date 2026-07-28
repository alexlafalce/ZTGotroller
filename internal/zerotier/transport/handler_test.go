package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/networkconfig"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/peer"
)

func TestHandlerHelloAndConfigLifecycle(t *testing.T) {
	ctx := context.Background()
	controllerIdentity := transportController(t)
	remoteIdentity, err := identity.Generate(
		ctx,
		bytes.NewReader(bytes.Repeat([]byte{0x66}, identity.PrivateKeyLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	service, err := controller.New(controllerIdentity.Address(), memory.New(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(ctx, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, controllerIdentity, peer.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return now }
	handler.random = bytes.NewReader(bytes.Repeat([]byte{0x7a}, 64))
	remote := netip.MustParseAddrPort("192.0.2.20:40000")

	helloDatagram, sharedKey := buildHelloDatagram(t, controllerIdentity, remoteIdentity)
	replies, err := handler.Handle(ctx, helloDatagram, remote)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 {
		t.Fatalf("HELLO replies = %d", len(replies))
	}
	helloOK, err := packet.DearmorSession(replies[0], sharedKey)
	if err != nil || helloOK.Verb != packet.VerbOK {
		t.Fatalf("invalid HELLO OK: %+v, %v", helloOK, err)
	}

	request := buildConfigDatagram(t, controllerIdentity, remoteIdentity, network.ID, sharedKey, 2)
	replies, err = handler.Handle(ctx, request, remote)
	if err != nil {
		t.Fatal(err)
	}
	denial, err := packet.DearmorSession(replies[0], sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	if denial.Verb != packet.VerbError || denial.Payload[9] != byte(networkconfig.ErrorAccessDenied) {
		t.Fatalf("unexpected denial: %+v", denial)
	}

	member, err := service.RegisterMember(ctx, network.ID, remoteIdentity.Address())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.SetMemberAuthorization(ctx, network.ID, member.NodeID, true, member.Revision); err != nil {
		t.Fatal(err)
	}
	replies, err = handler.Handle(ctx, request, remote)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := packet.DearmorSession(replies[0], sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	if ok.Verb != packet.VerbOK || ok.Payload[0] != byte(packet.VerbNetworkConfigRequest) {
		t.Fatalf("unexpected config OK: %+v", ok)
	}
	if _, err := networkconfig.ParseSignedChunk(ok.Payload[9:], controllerIdentity.Public()); err != nil {
		t.Fatal(err)
	}

	handler.random = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64))
	revocations, err := handler.BuildCOMRevocationBroadcast(
		ctx, network.ID, remoteIdentity.Address(), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(revocations) != 1 || revocations[0].Endpoint != remote {
		t.Fatalf("unexpected revocation destinations: %+v", revocations)
	}
	decodedRevocation, err := packet.DearmorSession(revocations[0].Payload, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	if decodedRevocation.Verb != packet.VerbNetworkCredentials ||
		len(decodedRevocation.Payload) != 161 ||
		decodedRevocation.Payload[6] != 1 {
		t.Fatalf("unexpected revocation packet: %+v", decodedRevocation)
	}
}

func buildHelloDatagram(
	t *testing.T,
	controllerIdentity identity.Identity,
	remoteIdentity identity.Identity,
) ([]byte, packet.SessionKey) {
	t.Helper()
	public, err := remoteIdentity.Public().MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{packet.ProtocolVersionCurrent, 1, 14, 0, 2}
	payload = binary.BigEndian.AppendUint64(payload, 1_700_000_000_000)
	payload = append(payload, public...)
	draft, err := packet.Build(
		1, controllerIdentity.Address(), remoteIdentity.Address(), packet.VerbHello, payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	agreed, err := remoteIdentity.Agree(controllerIdentity.Public(), packet.SessionKeyLength)
	if err != nil {
		t.Fatal(err)
	}
	var key packet.SessionKey
	copy(key[:], agreed)
	armored, err := packet.ArmorSession(draft, key, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return armored, key
}

func buildConfigDatagram(
	t *testing.T,
	controllerIdentity identity.Identity,
	remoteIdentity identity.Identity,
	networkID domain.NetworkID,
	key packet.SessionKey,
	packetID uint64,
) []byte {
	t.Helper()
	networkBytes, _ := hex.DecodeString(string(networkID))
	payload := make([]byte, 10)
	copy(payload, networkBytes)
	draft, err := packet.Build(
		packetID,
		controllerIdentity.Address(),
		remoteIdentity.Address(),
		packet.VerbNetworkConfigRequest,
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	armored, err := packet.ArmorSession(draft, key, true, true)
	if err != nil {
		t.Fatal(err)
	}
	return armored
}

func transportController(t *testing.T) identity.Identity {
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
