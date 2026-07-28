package networkconfig

import (
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

func TestIssueAuthorizedConfig(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	now := time.Unix(1_700_000_000, 0).UTC()
	network := domain.NewNetwork(networkID, now)
	network.Name = "private"
	network.Routes = []domain.Route{{Target: netip.MustParsePrefix("10.10.0.0/16")}}
	member := domain.NewMember(networkID, controller.Address(), now)
	member.Authorized = true
	member.IPAssignments = []netip.Addr{netip.MustParseAddr("10.10.0.2")}

	issued, err := IssueAuthorizedConfig(IssueInput{
		Network:    network,
		Member:     member,
		Recipient:  controller.Public(),
		Controller: controller,
		IssuedAt:   now,
		Revision:   12,
	})
	if err != nil {
		t.Fatal(err)
	}
	if issued.COO == nil || !issued.COO.Owns(member.IPAssignments[0]) {
		t.Fatal("issued config has no ownership credential for assigned IP")
	}
	if err := issued.COM.Verify(networkID, controller.Public()); err != nil {
		t.Fatal(err)
	}
	if err := issued.COO.Verify(controller.Public()); err != nil {
		t.Fatal(err)
	}
	dictionary, err := ParseMetadata(issued.Dictionary)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"C", "COO", "RT", "I", "R", "DNS"} {
		if len(dictionary[key]) == 0 {
			t.Errorf("dictionary is missing %s", key)
		}
	}
	chunk, err := ParseSignedChunk(issued.Chunks[0], controller.Public())
	if err != nil {
		t.Fatal(err)
	}
	if chunk.UpdateID != 12 || chunk.TotalLength != uint32(len(issued.Dictionary)) {
		t.Fatalf("unexpected chunk metadata: %+v", chunk)
	}
}

func TestIssueAuthorizedConfigRejectsUnauthorizedMember(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	now := time.Now().UTC()
	network := domain.NewNetwork(networkID, now)
	member := domain.NewMember(networkID, controller.Address(), now)
	_, err = IssueAuthorizedConfig(IssueInput{
		Network: network, Member: member, Recipient: controller.Public(),
		Controller: controller, IssuedAt: now, Revision: 1,
	})
	if err == nil {
		t.Fatal("expected unauthorized member error")
	}
}

func TestIssueAuthorizedConfigRejectsRecipientMismatch(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	now := time.Now().UTC()
	network := domain.NewNetwork(networkID, now)
	otherNode, _ := domain.ParseNodeID("0123456789")
	member := domain.NewMember(networkID, otherNode, now)
	member.Authorized = true
	_, err = IssueAuthorizedConfig(IssueInput{
		Network: network, Member: member, Recipient: controller.Public(),
		Controller: controller, IssuedAt: now, Revision: 1,
	})
	if err == nil {
		t.Fatal("expected recipient mismatch error")
	}
}
