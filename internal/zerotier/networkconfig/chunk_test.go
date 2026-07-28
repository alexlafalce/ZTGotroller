package networkconfig

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

func TestSignedConfigChunkRoundTrip(t *testing.T) {
	signer := deterministicSigner(t)
	dictionary := bytes.Repeat([]byte("config"), 20)
	chunks, err := BuildSignedChunks(
		"8056c2e21c000001", dictionary, 99, 50, signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	var assembled []byte
	for index, payload := range chunks {
		chunk, err := ParseSignedChunk(payload, signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		if chunk.Index != uint32(index*50) || chunk.UpdateID != 99 ||
			chunk.TotalLength != uint32(len(dictionary)) {
			t.Fatalf("unexpected chunk: %+v", chunk)
		}
		assembled = append(assembled, chunk.Data...)
	}
	if !bytes.Equal(assembled, dictionary) {
		t.Fatal("chunks did not reassemble the dictionary")
	}
}

func TestSignatureCoversChunkMetadata(t *testing.T) {
	signer := deterministicSigner(t)
	chunks, err := BuildSignedChunks("8056c2e21c000001", []byte("nwid=value"), 1, 0, signer)
	if err != nil {
		t.Fatal(err)
	}
	chunks[0][10] ^= 1
	if _, err := ParseSignedChunk(chunks[0], signer.Public()); err == nil {
		t.Fatal("tampered chunk passed signature verification")
	}
}

func TestWrapOK(t *testing.T) {
	wrapped := WrapOK(0x0102030405060708, []byte{9, 10})
	if wrapped[0] != byte(packet.VerbNetworkConfigRequest) ||
		binary.BigEndian.Uint64(wrapped[1:9]) != 0x0102030405060708 ||
		!bytes.Equal(wrapped[9:], []byte{9, 10}) {
		t.Fatalf("unexpected OK payload: %x", wrapped)
	}
}

func TestWrapError(t *testing.T) {
	payload, err := WrapError(0x0102030405060708, "8056c2e21c000001", ErrorAccessDenied)
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] != byte(packet.VerbNetworkConfigRequest) ||
		binary.BigEndian.Uint64(payload[1:9]) != 0x0102030405060708 ||
		payload[9] != byte(ErrorAccessDenied) ||
		!bytes.Equal(payload[10:], []byte{0x80, 0x56, 0xc2, 0xe2, 0x1c, 0, 0, 1}) {
		t.Fatalf("unexpected ERROR payload: %x", payload)
	}
}

func TestRejectsInvalidChunkBuild(t *testing.T) {
	signer := deterministicSigner(t)
	for _, test := range []struct {
		dictionary []byte
		updateID   uint64
		maxChunk   int
	}{
		{dictionary: nil, updateID: 1},
		{dictionary: []byte("x"), updateID: 0},
		{dictionary: []byte("x"), updateID: 1, maxChunk: 65536},
	} {
		if _, err := BuildSignedChunks(
			"8056c2e21c000001", test.dictionary, test.updateID, test.maxChunk, signer,
		); err == nil {
			t.Fatal("expected invalid chunk build to fail")
		}
	}
}

func deterministicSigner(t *testing.T) identity.Identity {
	t.Helper()
	signer, err := identity.Generate(
		context.Background(),
		bytes.NewReader(make([]byte, identity.PrivateKeyLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
