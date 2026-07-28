package memory

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	controllerstore "github.com/alexlafalce/ZTGotroller/internal/store"
)

const testNetworkID domain.NetworkID = "8056c2e21c000001"

func TestNetworkLifecycleAndIsolation(t *testing.T) {
	ctx := context.Background()
	memory := New()
	network := domain.NewNetwork(testNetworkID, time.Now())
	network.Name = "home"
	network.Rules[0].Parameters = map[string]json.RawMessage{"value": json.RawMessage(`1`)}

	if err := memory.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	stored, err := memory.GetNetwork(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != 1 {
		t.Fatalf("got revision %d, want 1", stored.Revision)
	}

	stored.Name = "changed"
	stored.Rules[0].Parameters["value"][0] = '2'
	unchanged, err := memory.GetNetwork(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Name != "home" || string(unchanged.Rules[0].Parameters["value"]) != "1" {
		t.Fatal("read result mutated persisted network")
	}

	stored = unchanged
	stored.Name = "updated"
	if err := memory.SaveNetwork(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if err := memory.SaveNetwork(ctx, stored); !errors.Is(err, controllerstore.ErrConflict) {
		t.Fatalf("got %v, want revision conflict", err)
	}
	updated, err := memory.GetNetwork(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.Name != "updated" {
		t.Fatalf("unexpected updated network: %+v", updated)
	}
}

func TestMemberLifecycleAndCascade(t *testing.T) {
	ctx := context.Background()
	memory := New()
	network := domain.NewNetwork(testNetworkID, time.Now())
	if err := memory.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	member := domain.NewMember(testNetworkID, "abcdef1234", time.Now())
	member.IPAssignments = []netip.Addr{netip.MustParseAddr("10.10.0.1")}
	if err := memory.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	stored, err := memory.GetMember(ctx, member.NetworkID, member.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Revision != 1 {
		t.Fatalf("got revision %d, want 1", stored.Revision)
	}
	stored.IPAssignments[0] = netip.MustParseAddr("10.10.0.2")
	unchanged, err := memory.GetMember(ctx, member.NetworkID, member.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.IPAssignments[0].String() != "10.10.0.1" {
		t.Fatal("read result mutated persisted member")
	}

	persistedNetwork, err := memory.GetNetwork(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.DeleteNetwork(ctx, network.ID, persistedNetwork.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := memory.GetMember(ctx, member.NetworkID, member.NodeID); !errors.Is(err, controllerstore.ErrNotFound) {
		t.Fatalf("got %v, want member to be cascade-deleted", err)
	}
}

func TestCreateMemberRequiresNetwork(t *testing.T) {
	memory := New()
	member := domain.NewMember(testNetworkID, "abcdef1234", time.Now())
	err := memory.CreateMember(context.Background(), member)
	if !errors.Is(err, controllerstore.ErrNotFound) {
		t.Fatalf("got %v, want not found", err)
	}
}

func TestCanceledContextDoesNotMutate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	memory := New()
	network := domain.NewNetwork(testNetworkID, time.Now())
	if err := memory.CreateNetwork(ctx, network); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context canceled", err)
	}
	networks, err := memory.ListNetworks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 0 {
		t.Fatal("canceled operation mutated the store")
	}
}
