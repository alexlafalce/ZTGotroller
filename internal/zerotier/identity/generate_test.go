package identity

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

const deterministicIdentity = "a7fa8660c2:0:" +
	"38bf359f10fcbf91b985cb2385c3c0cae1393d870ca029da25d152ef1b3f2323" +
	"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29:" +
	"00000000000000000700000000000000f9ffffffffffffff0000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"

func TestDeterministicGeneration(t *testing.T) {
	generated, err := Generate(context.Background(), bytes.NewReader(make([]byte, PrivateKeyLength)))
	if err != nil {
		t.Fatal(err)
	}
	if !generated.HasPrivate() || !generated.LocallyValidate() {
		t.Fatal("generated identity is not locally valid")
	}
	generatedSecret, err := generated.SecretString()
	if err != nil {
		t.Fatal(err)
	}
	if generatedSecret != deterministicIdentity {
		t.Fatalf("generation vector changed: %s", generatedSecret)
	}
	signature, err := generated.Sign([]byte("generated identity"))
	if err != nil {
		t.Fatal(err)
	}
	if !generated.Public().Verify([]byte("generated identity"), signature) {
		t.Fatal("generated signing keys do not agree")
	}
	agreed, err := generated.Agree(generated.Public(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(agreed) != 32 {
		t.Fatalf("got agreement length %d", len(agreed))
	}
}

func TestGenerationCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Generate(ctx, bytes.NewReader(make([]byte, PrivateKeyLength)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context canceled", err)
	}
}

func TestGenerationRandomFailure(t *testing.T) {
	_, err := Generate(context.Background(), bytes.NewReader(nil))
	if err == nil {
		t.Fatal("expected random source failure")
	}
}
