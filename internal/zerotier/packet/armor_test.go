package packet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

func TestEncryptedArmorRoundTrip(t *testing.T) {
	unarmored, err := Build(
		0x0102030405060708,
		domain.NodeID("8056c2e21c"),
		domain.NodeID("abcdef1234"),
		VerbOK,
		[]byte("configuration"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	for index := range key {
		key[index] = byte(index)
	}
	armored, err := Armor(unarmored, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(armored[27:], unarmored[27:]) {
		t.Fatal("encrypted payload equals plaintext")
	}
	const reference = "01020304050607088056c2e21cabcdef123488d7c54b472c7dd3b8c3863b5d28ea41ad524c868132cc"
	if hex.EncodeToString(armored) != reference {
		t.Fatalf("armor differs from ZeroTier 1.14.2 reference: %x", armored)
	}
	decoded, err := Dearmor(armored, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Verb != VerbOK || !bytes.Equal(decoded.Payload, []byte("configuration")) {
		t.Fatalf("unexpected decoded packet: %+v", decoded)
	}
}

func TestClearArmorAuthenticatesWithoutEncryption(t *testing.T) {
	unarmored, err := Build(1, "8056c2e21c", "abcdef1234", VerbHello, []byte("identity"))
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	armored, err := Armor(unarmored, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(armored[27:], unarmored[27:]) {
		t.Fatal("clear armor encrypted payload")
	}
	decoded, err := Dearmor(armored, key)
	if err != nil || decoded.Verb != VerbHello {
		t.Fatalf("clear armor failed: %+v, %v", decoded, err)
	}
}

func TestDearmorRejectsTampering(t *testing.T) {
	unarmored, err := Build(1, "8056c2e21c", "abcdef1234", VerbOK, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	armored, err := Armor(unarmored, key, true)
	if err != nil {
		t.Fatal(err)
	}
	armored[len(armored)-1] ^= 1
	if _, err := Dearmor(armored, key); err == nil {
		t.Fatal("tampered packet passed authentication")
	}
}

func TestBuildRejectsOversizedPacket(t *testing.T) {
	if _, err := Build(1, "8056c2e21c", "abcdef1234", VerbOK, make([]byte, MaxPacketLength)); err == nil {
		t.Fatal("expected oversized packet error")
	}
}
