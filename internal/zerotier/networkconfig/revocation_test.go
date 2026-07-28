package networkconfig

import (
	"bytes"
	"testing"
	"time"
)

func TestCOMRevocationLayoutAndSignature(t *testing.T) {
	controller, err := testIdentity()
	if err != nil {
		t.Fatal(err)
	}
	networkID := domainNetworkID(t, string(controller.Address())+"000001")
	revocation, err := NewCOMRevocation(
		networkID, controller.Address(), time.Unix(1_700_000_000, 0),
		controller, bytes.NewReader([]byte{1, 2, 3, 4}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if revocation.ID != 0x01020304 || !revocation.Verify(controller.Public()) {
		t.Fatalf("invalid revocation: %+v", revocation)
	}
	serialized, err := revocation.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(serialized) != 152 || serialized[50] != credentialTypeCOM ||
		serialized[51] != 1 {
		t.Fatalf("unexpected revocation layout: %x", serialized)
	}
	payload := BuildRevocationCredentialsPayload(serialized)
	if len(payload) != 161 || !bytes.Equal(payload[:7], []byte{0, 0, 0, 0, 0, 0, 1}) ||
		!bytes.Equal(payload[len(payload)-2:], []byte{0, 0}) {
		t.Fatalf("unexpected credentials payload: %x", payload)
	}
}
