package packet

import (
	"bytes"
	"testing"
)

func TestArmorAndFragmentReassembles(t *testing.T) {
	payload := bytes.Repeat([]byte("fragmented"), 400)
	draft, err := Build(0x0102030405060708, "8056c2e21c", "abcdef1234", VerbOK, payload)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	fragments, err := ArmorAndFragment(draft, key, true, 600)
	if err != nil {
		t.Fatal(err)
	}
	if len(fragments) < 2 {
		t.Fatal("packet was not fragmented")
	}
	routing, err := ParseRouting(fragments[0])
	if err != nil {
		t.Fatal(err)
	}
	if !routing.Fragmented {
		t.Fatal("first fragment lacks authenticated fragmented flag")
	}
	assembled := append([]byte(nil), fragments[0]...)
	for number, serialized := range fragments[1:] {
		fragment, err := ParseFragment(serialized)
		if err != nil {
			t.Fatal(err)
		}
		if fragment.Number != uint8(number+1) ||
			fragment.TotalFragments != uint8(len(fragments)) {
			t.Fatalf("unexpected fragment metadata: %+v", fragment)
		}
		assembled = append(assembled, fragment.Payload...)
	}
	decoded, err := Dearmor(assembled, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Fatal("reassembled payload differs")
	}
}
