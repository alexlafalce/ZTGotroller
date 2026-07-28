package controller

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store/memory"
)

func TestAutomaticIPAMAllocatesUniqueAddresses(t *testing.T) {
	ctx := context.Background()
	service := newIPAMTestService(t)
	network := createIPAMNetwork(t, service)
	nodeIDs := []domain.NodeID{"0000000001", "0000000002", "0000000003"}

	var group sync.WaitGroup
	group.Add(len(nodeIDs))
	for _, nodeID := range nodeIDs {
		go func() {
			defer group.Done()
			member, err := service.RegisterMember(ctx, network.ID, nodeID)
			if err != nil {
				t.Error(err)
				return
			}
			member, err = service.SetMemberAuthorization(ctx, network.ID, nodeID, true, member.Revision)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := service.ensureAutomaticAssignments(ctx, network, member); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()

	seen := make(map[netip.Addr]struct{})
	for _, nodeID := range nodeIDs {
		member, err := service.GetMember(ctx, network.ID, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if len(member.IPAssignments) != 1 {
			t.Fatalf("%s has assignments %v", nodeID, member.IPAssignments)
		}
		address := member.IPAssignments[0]
		if _, duplicate := seen[address]; duplicate {
			t.Fatalf("duplicate assignment %s", address)
		}
		seen[address] = struct{}{}
	}
}

func TestAutomaticIPAMRespectsFlagsAndExistingAssignment(t *testing.T) {
	ctx := context.Background()
	service := newIPAMTestService(t)
	network := createIPAMNetwork(t, service)

	member, err := service.RegisterMember(ctx, network.ID, "0000000010")
	if err != nil {
		t.Fatal(err)
	}
	member.NoAutoAssign = true
	member.UpdatedAt = time.Now().UTC()
	if err := service.store.SaveMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	member, _ = service.GetMember(ctx, network.ID, member.NodeID)
	member, err = service.ensureAutomaticAssignments(ctx, network, member)
	if err != nil || len(member.IPAssignments) != 0 {
		t.Fatalf("no-auto-assign member changed: %v, %v", member.IPAssignments, err)
	}

	explicit, err := service.RegisterMember(ctx, network.ID, "0000000011")
	if err != nil {
		t.Fatal(err)
	}
	explicit.IPAssignments = []netip.Addr{netip.MustParseAddr("10.55.0.99")}
	explicit.UpdatedAt = time.Now().UTC()
	if err := service.store.SaveMember(ctx, explicit); err != nil {
		t.Fatal(err)
	}
	explicit, _ = service.GetMember(ctx, network.ID, explicit.NodeID)
	explicit, err = service.ensureAutomaticAssignments(ctx, network, explicit)
	if err != nil || len(explicit.IPAssignments) != 1 || explicit.IPAssignments[0].String() != "10.55.0.99" {
		t.Fatalf("explicit assignment changed: %v, %v", explicit.IPAssignments, err)
	}
}

func newIPAMTestService(t *testing.T) *Service {
	t.Helper()
	service, err := New("8056c2e21c", memory.New(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func createIPAMNetwork(t *testing.T, service *Service) domain.Network {
	t.Helper()
	ctx := context.Background()
	network, err := service.CreateNetwork(ctx, 1, "ipam")
	if err != nil {
		t.Fatal(err)
	}
	network, err = service.UpdateNetwork(ctx, network.ID, NetworkUpdate{
		Name: "ipam", Private: true, MTU: domain.DefaultMTU,
		MulticastLimit: domain.DefaultMulticastLimit, EnableBroadcast: true,
		Assignment: domain.AssignmentModes{IPv4ZeroTier: true},
		Routes:     []domain.Route{{Target: netip.MustParsePrefix("10.55.0.0/24")}},
		IPPools: []domain.IPPool{{
			Start: netip.MustParseAddr("10.55.0.10"),
			End:   netip.MustParseAddr("10.55.0.20"),
		}},
		Rules: []domain.Rule{{Type: "ACTION_ACCEPT"}},
	}, network.Revision)
	if err != nil {
		t.Fatal(err)
	}
	return network
}
