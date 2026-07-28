package networkconfig

import (
	"bytes"
	"testing"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const membershipTestSecret = "8e4df28b72:0:" +
	"ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843" +
	"fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:" +
	"bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bdd" +
	"d63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e"

func TestCertificateOfMembershipRoundTrip(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")

	certificate, err := NewCertificateOfMembership(
		1_700_000_000_000,
		86_400_000,
		networkID,
		controller.Public(),
		controller,
	)
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := certificate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) != 3+7*24+5+96 {
		t.Fatalf("serialized length = %d", len(serialized))
	}
	parsed, err := ParseCertificateOfMembership(serialized)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(networkID, controller.Public()); err != nil {
		t.Fatal(err)
	}
	remarshaled, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remarshaled, serialized) {
		t.Fatal("COM did not round trip")
	}

	// Lock down the upstream wire layout: version, 7 qualifiers, signer, signature.
	if serialized[0] != 1 || !bytes.Equal(serialized[1:3], []byte{0, 7}) {
		t.Fatalf("unexpected COM header: %x", serialized[:3])
	}
	if !bytes.Equal(serialized[3+7*24:3+7*24+5], []byte{0x8e, 0x4d, 0xf2, 0x8b, 0x72}) {
		t.Fatalf("unexpected COM signer bytes: %x", serialized[3+7*24:3+7*24+5])
	}
}

func testIdentity() (identity.Identity, error) {
	return identity.Parse(membershipTestSecret)
}

func domainNetworkID(t *testing.T, value string) domain.NetworkID {
	t.Helper()
	networkID, err := domain.ParseNetworkID(value)
	if err != nil {
		t.Fatal(err)
	}
	return networkID
}

func TestCertificateOfMembershipDetectsModification(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	certificate, err := NewCertificateOfMembership(100, 20, networkID, controller.Public(), controller)
	if err != nil {
		t.Fatal(err)
	}
	certificate.Qualifiers[0].Value++
	if err := certificate.Verify(networkID, controller.Public()); err == nil {
		t.Fatal("modified COM passed verification")
	}
}

func TestCertificateOfMembershipRejectsWrongController(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, "0123456789000001")
	if _, err := NewCertificateOfMembership(100, 20, networkID, controller.Public(), controller); err == nil {
		t.Fatal("expected signer/controller mismatch")
	}
}
