package packet

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESArmorMatches1142Reference(t *testing.T) {
	draft, err := Build(
		0x0102030405060708,
		"8056c2e21c",
		"abcdef1234",
		VerbOK,
		[]byte("configuration"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var key SessionKey
	for index := range key {
		key[index] = byte(index)
	}
	armored, err := ArmorAES(draft, key)
	if err != nil {
		t.Fatal(err)
	}
	const reference = "092649b0b979c5a18056c2e21cabcdef12341805220abb6c95ae8df72cb34e3519c43e5347dc7fade8"
	if hex.EncodeToString(armored) != reference {
		t.Fatalf("AES armor differs from ZeroTier 1.14.2: %x", armored)
	}
	decoded, err := DearmorAES(armored, key)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Verb != VerbOK || !bytes.Equal(decoded.Payload, []byte("configuration")) {
		t.Fatalf("unexpected AES decoded packet: %+v", decoded)
	}
	armored[len(armored)-1] ^= 1
	if _, err := DearmorAES(armored, key); err == nil {
		t.Fatal("tampered AES packet passed authentication")
	}
}
