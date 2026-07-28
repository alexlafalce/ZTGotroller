package networkconfig

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestCertificateOfOwnershipRoundTrip(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	addresses := []netip.Addr{
		netip.MustParseAddr("10.20.30.40"),
		netip.MustParseAddr("2001:db8::40"),
	}
	certificate, err := NewCertificateOfOwnership(
		networkID, 1_700_000_000_000, 1, controller.Address(), addresses, controller,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.Owns(addresses[0]) || !certificate.Owns(addresses[1]) {
		t.Fatal("certificate does not own its assigned addresses")
	}
	serialized, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCertificateOfOwnership(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(controller.Public()); err != nil {
		t.Fatal(err)
	}
	remarshaled, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remarshaled, serialized) {
		t.Fatal("ownership certificate did not round trip")
	}
}

func TestCertificateOfOwnershipDetectsModification(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	certificate, err := NewCertificateOfOwnership(
		networkID, 100, 1, controller.Address(),
		[]netip.Addr{netip.MustParseAddr("10.0.0.2")}, controller,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Things[0].Value[3]++
	if err := certificate.Verify(controller.Public()); err == nil {
		t.Fatal("modified ownership certificate passed verification")
	}
}

func TestCertificateOfOwnershipRejectsWrongController(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, "0123456789000001")
	_, err = NewCertificateOfOwnership(
		networkID, 100, 1, controller.Address(),
		[]netip.Addr{netip.MustParseAddr("10.0.0.2")}, controller,
	)
	if err == nil {
		t.Fatal("expected signer/controller mismatch")
	}
}
