package identity

import (
	"encoding/hex"
	"testing"
)

const knownSecret = "8e4df28b72:0:" +
	"ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843" +
	"fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:" +
	"bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bdd" +
	"d63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e"

const referenceSignature = "ae40a9650a9a41cbad407e9b6fe2c0f63bcbde09fdff53bfff7a852e41479fe0" +
	"150057872ae58da6abe7abc27df723c814bbf4c5ebd87b5e56e32daa1f856c079b" +
	"c20ce84c12a0d91d0f77c8d069eba5cfdbcf3aefd594f267e3d98576aef5ff"

func TestKnown1142IdentityRoundTrip(t *testing.T) {
	identity, err := Parse(knownSecret)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Address() != "8e4df28b72" || !identity.HasPrivate() {
		t.Fatalf("unexpected identity metadata: %s", identity.String())
	}
	secretString, err := identity.SecretString()
	if err != nil {
		t.Fatal(err)
	}
	if secretString != knownSecret {
		t.Fatal("text identity did not round trip")
	}

	binary, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(binary) != SecretBinaryLength || binary[5] != 0 || binary[70] != 64 {
		t.Fatalf("unexpected binary identity framing: %x", binary)
	}
	decoded, err := ParseBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	decodedSecret, err := decoded.SecretString()
	if err != nil {
		t.Fatal(err)
	}
	if decodedSecret != knownSecret {
		t.Fatal("binary identity did not round trip")
	}
}

func TestPublicIdentityOmitsPrivateMaterial(t *testing.T) {
	secret, err := Parse(knownSecret)
	if err != nil {
		t.Fatal(err)
	}
	public := secret.Public()
	if public.HasPrivate() || len(public.String()) != 10+3+PublicKeyLength*2 {
		t.Fatalf("unexpected public identity: %s", public.String())
	}
	if _, err := public.SecretString(); err == nil {
		t.Fatal("public identity must not export a secret")
	}
	binary, err := public.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(binary) != PublicBinaryLength || binary[len(binary)-1] != 0 {
		t.Fatalf("unexpected public binary identity: %x", binary)
	}
}

func TestRejectsMalformedIdentities(t *testing.T) {
	for _, value := range []string{
		"0000000000:0:" + knownSecret[13:141],
		"ff00000001:0:" + knownSecret[13:141],
		"8e4df28b72:1:" + knownSecret[13:141],
		"8E4DF28B72:0:" + knownSecret[13:141],
	} {
		if _, err := Parse(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestRejectsInconsistentBinaryPrivateLength(t *testing.T) {
	identity, err := Parse(knownSecret)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary[70] = 0
	if _, err := ParseBinary(binary); err == nil {
		t.Fatal("expected inconsistent private length to be rejected")
	}
}

func TestSignatureMatches1142Reference(t *testing.T) {
	identity, err := Parse(knownSecret)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("ZTGotroller cross-language signature vector")
	signature, err := identity.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(signature[:]) != referenceSignature {
		t.Fatalf("signature mismatch: %x", signature)
	}
	if !identity.Public().Verify(message, signature) {
		t.Fatal("public identity rejected valid signature")
	}
	message[0] ^= 1
	if identity.Verify(message, signature) {
		t.Fatal("accepted signature for modified message")
	}
}

func TestPublicIdentityCannotSign(t *testing.T) {
	identity, err := Parse(knownSecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Public().Sign([]byte("message")); err == nil {
		t.Fatal("expected signing without private key to fail")
	}
}
