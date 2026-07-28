package packet

import (
	"encoding/hex"
	"testing"
)

func TestPacketHeaderIndexes(t *testing.T) {
	data := make([]byte, HeaderLength+3)
	copy(data[0:8], mustHex(t, "0102030405060708"))
	copy(data[8:13], mustHex(t, "8056c2e21c"))
	copy(data[13:18], mustHex(t, "abcdef1234"))
	data[18] = FlagExtendedArmor | FlagFragmented | byte(CipherAESGMACSIV<<3) | 5
	copy(data[19:27], mustHex(t, "1122334455667788"))
	data[27] = FlagCompressed | byte(VerbNetworkConfigRequest)
	copy(data[28:], []byte{1, 2, 3})

	routing, err := ParseRouting(data)
	if err != nil {
		t.Fatal(err)
	}
	if routing.PacketID != 0x0102030405060708 ||
		routing.Destination != "8056c2e21c" ||
		routing.Source != "abcdef1234" ||
		routing.Cipher != CipherAESGMACSIV ||
		routing.Hops != 5 ||
		!routing.Fragmented ||
		!routing.ExtendedArmor {
		t.Fatalf("unexpected routing header: %+v", routing)
	}
	decoded, err := ParseDecoded(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Verb != VerbNetworkConfigRequest || !decoded.Compressed ||
		len(decoded.Payload) != 3 {
		t.Fatalf("unexpected decoded packet: %+v", decoded)
	}
	data[28] = 9
	if decoded.Payload[0] != 1 {
		t.Fatal("decoded payload aliases input buffer")
	}
}

func TestFragmentFraming(t *testing.T) {
	data := make([]byte, FragmentLength+2)
	copy(data[:8], mustHex(t, "0102030405060708"))
	copy(data[8:13], mustHex(t, "8056c2e21c"))
	data[13] = 0xff
	data[14] = 0x32
	data[15] = 4
	copy(data[16:], []byte{9, 8})
	if !IsFragment(data) {
		t.Fatal("fragment was not detected")
	}
	fragment, err := ParseFragment(data)
	if err != nil {
		t.Fatal(err)
	}
	if fragment.TotalFragments != 3 || fragment.Number != 2 ||
		fragment.Hops != 4 || fragment.Destination != "8056c2e21c" {
		t.Fatalf("unexpected fragment: %+v", fragment)
	}
}

func TestRejectsMalformedFraming(t *testing.T) {
	if _, err := ParseRouting(make([]byte, HeaderLength-1)); err == nil {
		t.Fatal("expected short packet to fail")
	}
	fragment := make([]byte, FragmentLength)
	fragment[13] = 0xff
	fragment[15] = 0x80
	if _, err := ParseFragment(fragment); err == nil {
		t.Fatal("expected reserved fragment hop bits to fail")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
