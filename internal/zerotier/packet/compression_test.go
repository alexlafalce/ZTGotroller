package packet

import (
	"bytes"
	"testing"
)

func TestDecompressLZ4Block(t *testing.T) {
	// Five literals followed by an overlapping match at distance five.
	decoded, err := Decompress(Decoded{
		Compressed: true,
		Payload:    []byte{0x56, 'h', 'e', 'l', 'l', 'o', 0x05, 0x00},
	}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Compressed || !bytes.Equal(decoded.Payload, []byte("hellohellohello")) {
		t.Fatalf("unexpected output %q", decoded.Payload)
	}
}

func TestDecompressRejectsInvalidBlocks(t *testing.T) {
	tests := [][]byte{
		{0x10},                  // missing literal
		{0x00, 0x00, 0x00},      // zero match offset
		{0xf0},                  // truncated extended literal length
		{0x10, 'x', 0x02, 0x00}, // match before output
	}
	for _, payload := range tests {
		if _, err := Decompress(Decoded{Compressed: true, Payload: payload}, 32); err == nil {
			t.Fatalf("invalid block %x was accepted", payload)
		}
	}
}

func TestDecompressEnforcesOutputLimit(t *testing.T) {
	if _, err := Decompress(Decoded{
		Compressed: true,
		Payload:    []byte{0x56, 'h', 'e', 'l', 'l', 'o', 0x05, 0x00},
	}, 10); err == nil {
		t.Fatal("output limit was not enforced")
	}
}
