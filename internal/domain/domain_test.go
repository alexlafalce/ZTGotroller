package domain

import (
	"net/netip"
	"testing"
	"time"
)

func TestNetworkIDControllerID(t *testing.T) {
	controller, err := ParseNodeID("8056c2e21c")
	if err != nil {
		t.Fatal(err)
	}
	networkID := NewNetworkID(controller, 1)
	if networkID != "8056c2e21c000001" {
		t.Fatalf("unexpected network ID: %s", networkID)
	}
	extracted, err := networkID.ControllerID()
	if err != nil {
		t.Fatal(err)
	}
	if extracted != controller {
		t.Fatalf("got controller %s, want %s", extracted, controller)
	}
}

func TestNewNetworkMatchesLegacyDefaults(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.FixedZone("test", -4*60*60))
	network := NewNetwork("8056c2e21c000001", now)
	if err := network.Validate(); err != nil {
		t.Fatal(err)
	}
	if !network.Private || !network.EnableBroadcast || network.MTU != DefaultMTU {
		t.Fatalf("unexpected defaults: %+v", network)
	}
	if len(network.Rules) != 1 || network.Rules[0].Type != "ACTION_ACCEPT" {
		t.Fatalf("unexpected default rules: %+v", network.Rules)
	}
	if network.CreatedAt.Location() != time.UTC {
		t.Fatal("timestamps must be normalized to UTC")
	}
}

func TestNetworkRejectsMixedFamilyRoute(t *testing.T) {
	network := NewNetwork("8056c2e21c000001", time.Now())
	network.Routes = []Route{{
		Target: netip.MustParsePrefix("10.0.0.0/8"),
		Via:    netip.MustParseAddr("2001:db8::1"),
	}}
	if err := network.Validate(); err == nil {
		t.Fatal("expected route validation error")
	}
}

func TestMemberRejectsDuplicateAssignments(t *testing.T) {
	member := NewMember("8056c2e21c000001", "abcdef1234", time.Now())
	address := netip.MustParseAddr("10.0.0.1")
	member.IPAssignments = []netip.Addr{address, address}
	if err := member.Validate(); err == nil {
		t.Fatal("expected duplicate assignment validation error")
	}
}
