package networkconfig

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

func TestDictionaryBuilderRoundTrip(t *testing.T) {
	var builder DictionaryBuilder
	value := []byte{'a', 0, '\r', '\n', '\\', '=', 'z'}
	if err := builder.Add("binary", value); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseMetadata(builder.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed["binary"], value) {
		t.Fatalf("round trip = %x, want %x", parsed["binary"], value)
	}
}

func TestBuildDictionary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	networkID, _ := domain.ParseNetworkID("8056c2e21c000001")
	nodeID, _ := domain.ParseNodeID("abcdef1234")
	network := domain.NewNetwork(networkID, now)
	network.Name = "home=lab"
	network.Routes = []domain.Route{
		{Target: netip.MustParsePrefix("10.20.0.0/16")},
		{Target: netip.MustParsePrefix("10.20.30.0/24"), Via: netip.MustParseAddr("10.20.0.1")},
	}
	network.DNS = &domain.DNSConfig{
		Domain:  "internal.example",
		Servers: []netip.Addr{netip.MustParseAddr("10.20.0.53"), netip.MustParseAddr("2001:db8::53")},
	}
	member := domain.NewMember(networkID, nodeID, now)
	member.Authorized = true
	member.IPAssignments = []netip.Addr{netip.MustParseAddr("10.20.30.42")}

	serialized, err := BuildDictionary(ConfigInput{
		Network:  network,
		Member:   member,
		IssuedAt: now,
		Revision: 9,
	})
	if err != nil {
		t.Fatal(err)
	}
	dictionary, err := ParseMetadata(serialized)
	if err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]uint64{
		"v": 7, "nwid": 0x8056c2e21c000001, "ts": uint64(now.UnixMilli()),
		"ctmd": uint64((24 * time.Hour).Milliseconds()), "r": 9,
		"f": 2, "ml": 32, "t": 0, "mtu": 2800,
	} {
		if actual, ok := dictionary.HexUint(key); !ok || actual != expected {
			t.Errorf("%s = %x, %v; want %x", key, actual, ok, expected)
		}
	}
	if string(dictionary["id"]) != string(nodeID) || string(dictionary["n"]) != "home=lab" {
		t.Fatalf("unexpected identity or name: %q, %q", dictionary["id"], dictionary["n"])
	}

	// The most-specific /24 route is carried in the serialized assignment.
	expectedIP := []byte{4, 10, 20, 30, 42, 0, 24}
	if !bytes.Equal(dictionary["I"], expectedIP) {
		t.Fatalf("static IP = %x, want %x", dictionary["I"], expectedIP)
	}
	if len(dictionary["DNS"]) != 128+7+19+1+1 {
		t.Fatalf("DNS length = %d", len(dictionary["DNS"]))
	}
}

func TestBuildDictionaryRejectsAssignmentWithoutRoute(t *testing.T) {
	now := time.Now().UTC()
	networkID, _ := domain.ParseNetworkID("8056c2e21c000001")
	nodeID, _ := domain.ParseNodeID("abcdef1234")
	network := domain.NewNetwork(networkID, now)
	member := domain.NewMember(networkID, nodeID, now)
	member.IPAssignments = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	_, err := BuildDictionary(ConfigInput{Network: network, Member: member, IssuedAt: now})
	if err == nil {
		t.Fatal("expected assignment error")
	}
}
