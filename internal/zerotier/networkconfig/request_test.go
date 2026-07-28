package networkconfig

import (
	"encoding/binary"
	"testing"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

func TestParseCurrentNetworkConfigRequest(t *testing.T) {
	metadata := []byte("v=7\npv=d\nmajv=1\nminv=10\nrevv=5\no=linux-x86_64\na=token\\evalue")
	payload := make([]byte, 10+len(metadata)+16+2)
	binary.BigEndian.PutUint64(payload[:8], 0x8056c2e21c000001)
	binary.BigEndian.PutUint16(payload[8:10], uint16(len(metadata)))
	copy(payload[10:], metadata)
	offset := 10 + len(metadata)
	binary.BigEndian.PutUint64(payload[offset:offset+8], 42)
	binary.BigEndian.PutUint64(payload[offset+8:offset+16], 123456)
	copy(payload[offset+16:], []byte{0xaa, 0xbb})

	request, err := ParseRequest(packet.Decoded{
		Verb:    packet.VerbNetworkConfigRequest,
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.NetworkID != "8056c2e21c000001" ||
		!request.HasCurrentState ||
		request.CurrentRevision != 42 ||
		request.CurrentTimestamp != 123456 ||
		string(request.Metadata["a"]) != "token=value" ||
		len(request.Extensions) != 2 {
		t.Fatalf("unexpected request: %+v", request)
	}
	if protocol, ok := request.Metadata.HexUint("pv"); !ok || protocol != 13 {
		t.Fatalf("unexpected protocol metadata: %d, %v", protocol, ok)
	}
	payload[offset+16] = 0
	if request.Extensions[0] != 0xaa {
		t.Fatal("request extensions alias packet payload")
	}
}

func TestParseLegacyRequestWithoutState(t *testing.T) {
	payload := make([]byte, 10)
	binary.BigEndian.PutUint64(payload[:8], 0x8056c2e21c000001)
	request, err := ParseRequest(packet.Decoded{
		Verb:    packet.VerbNetworkConfigRequest,
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	if request.HasCurrentState || len(request.Metadata) != 0 {
		t.Fatalf("unexpected legacy request: %+v", request)
	}
}

func TestMetadataEscapesAndDuplicateSemantics(t *testing.T) {
	metadata, err := ParseMetadata([]byte("a=first\na=second\nbinary=x\\0y\\nz\\r\\\\\\e"))
	if err != nil {
		t.Fatal(err)
	}
	if string(metadata["a"]) != "first" {
		t.Fatal("first duplicate metadata value must win")
	}
	expected := "x\x00y\nz\r\\="
	if string(metadata["binary"]) != expected {
		t.Fatalf("got %q, want %q", metadata["binary"], expected)
	}
}

func TestRejectsMalformedRequests(t *testing.T) {
	tests := []packet.Decoded{
		{Verb: packet.VerbEcho},
		{Verb: packet.VerbNetworkConfigRequest, Compressed: true},
		{Verb: packet.VerbNetworkConfigRequest, Payload: make([]byte, 9)},
		{Verb: packet.VerbNetworkConfigRequest, Payload: requestWithLength(3, []byte("a"))},
		{Verb: packet.VerbNetworkConfigRequest, Payload: append(requestWithLength(0, nil), 1)},
		{Verb: packet.VerbNetworkConfigRequest, Payload: requestWithLength(4, []byte("bad!"))},
	}
	for index, test := range tests {
		if _, err := ParseRequest(test); err == nil {
			t.Fatalf("test %d: expected malformed request to fail", index)
		}
	}
}

func requestWithLength(length uint16, metadata []byte) []byte {
	payload := make([]byte, 10+len(metadata))
	binary.BigEndian.PutUint64(payload[:8], 0x8056c2e21c000001)
	binary.BigEndian.PutUint16(payload[8:10], length)
	copy(payload[10:], metadata)
	return payload
}
