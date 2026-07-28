package controller

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/networkconfig"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

const configTestSecret = "8e4df28b72:0:" +
	"ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843" +
	"fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:" +
	"bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bdd" +
	"d63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e"

func TestConfigRequestRegistersThenDeniesMember(t *testing.T) {
	ctx := context.Background()
	service, signer, network := newConfigTestService(t)
	request := decodedConfigRequest(t, network.ID, signer.Address(), 42)

	replies, err := service.HandleConfigRequest(ctx, request, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0].Verb != packet.VerbError ||
		replies[0].Payload[9] != byte(networkconfig.ErrorAccessDenied) {
		t.Fatalf("unexpected denial reply: %+v", replies)
	}
	member, err := service.store.GetMember(ctx, network.ID, signer.Address())
	if err != nil {
		t.Fatal(err)
	}
	if member.Authorized {
		t.Fatal("first contact must not authorize member")
	}
}

func TestConfigRequestIssuesSignedConfigForAuthorizedMember(t *testing.T) {
	ctx := context.Background()
	service, signer, network := newConfigTestService(t)
	member, err := service.RegisterMember(ctx, network.ID, signer.Address())
	if err != nil {
		t.Fatal(err)
	}
	member, err = service.SetMemberAuthorization(ctx, network.ID, signer.Address(), true, member.Revision)
	if err != nil {
		t.Fatal(err)
	}
	request := decodedConfigRequest(t, network.ID, signer.Address(), 99)
	replies, err := service.HandleConfigRequest(ctx, request, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) == 0 || replies[0].Verb != packet.VerbOK {
		t.Fatalf("unexpected config replies: %+v", replies)
	}
	payload := replies[0].Payload
	if payload[0] != byte(packet.VerbNetworkConfigRequest) ||
		binary.BigEndian.Uint64(payload[1:9]) != 99 {
		t.Fatalf("unexpected OK correlation: %x", payload[:9])
	}
	chunk, err := networkconfig.ParseSignedChunk(payload[9:], signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	expectedRevision, err := configRevision(network.Revision, member.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if chunk.UpdateID != expectedRevision {
		t.Fatalf("update ID = %d, want %d", chunk.UpdateID, expectedRevision)
	}
}

func TestConfigRequestReturnsNotFound(t *testing.T) {
	service, signer, _ := newConfigTestService(t)
	unknown, _ := domain.ParseNetworkID(string(signer.Address()) + "000002")
	replies, err := service.HandleConfigRequest(
		context.Background(),
		decodedConfigRequest(t, unknown, signer.Address(), 7),
		signer.Public(),
		signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 || replies[0].Verb != packet.VerbError ||
		replies[0].Payload[9] != byte(networkconfig.ErrorObjectNotFound) {
		t.Fatalf("unexpected not-found reply: %+v", replies)
	}
}

func newConfigTestService(t *testing.T) (*Service, identity.Identity, domain.Network) {
	t.Helper()
	signer, err := identity.Parse(configTestSecret)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(
		signer.Address(),
		memory.New(),
		func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	)
	if err != nil {
		t.Fatal(err)
	}
	network, err := service.CreateNetwork(context.Background(), 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	return service, signer, network
}

func decodedConfigRequest(
	t *testing.T,
	networkID domain.NetworkID,
	source domain.NodeID,
	packetID uint64,
) packet.Decoded {
	t.Helper()
	networkBytes, err := hex.DecodeString(string(networkID))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 10)
	copy(payload, networkBytes)
	return packet.Decoded{
		Routing: packet.RoutingHeader{
			PacketID: packetID, Source: source, Destination: domain.NodeID(string(networkID)[:10]),
		},
		Verb:    packet.VerbNetworkConfigRequest,
		Payload: payload,
	}
}
