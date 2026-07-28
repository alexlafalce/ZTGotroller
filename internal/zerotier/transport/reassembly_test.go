package transport

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

func TestReassemblerAcceptsOutOfOrderFragments(t *testing.T) {
	payload := bytes.Repeat([]byte("reassemble"), 300)
	draft, err := packet.Build(123, "8056c2e21c", "abcdef1234", packet.VerbOK, payload)
	if err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	fragments, err := packet.ArmorAndFragment(draft, key, true, 600)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := netip.MustParseAddrPort("192.0.2.1:9993")
	now := time.Now()
	reassembler := newReassembler()
	for index := len(fragments) - 1; index >= 0; index-- {
		assembled, ready, err := reassembler.push(fragments[index], endpoint, now)
		if err != nil {
			t.Fatal(err)
		}
		if index != 0 && ready {
			t.Fatal("packet completed before first fragment arrived")
		}
		if index == 0 {
			if !ready {
				t.Fatal("complete fragment set did not reassemble")
			}
			decoded, err := packet.Dearmor(assembled, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded.Payload, payload) {
				t.Fatal("reassembled packet payload differs")
			}
		}
	}
}
