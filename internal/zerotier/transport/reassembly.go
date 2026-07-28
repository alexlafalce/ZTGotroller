package transport

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

const (
	reassemblyTTL      = 5 * time.Second
	maxReassemblySlots = 32
)

type reassemblyKey struct {
	endpoint netip.AddrPort
	packetID uint64
}

type partialPacket struct {
	created   time.Time
	first     []byte
	total     uint8
	bytes     int
	fragments map[uint8][]byte
}

type reassembler struct {
	partial map[reassemblyKey]*partialPacket
}

func newReassembler() *reassembler {
	return &reassembler{partial: make(map[reassemblyKey]*partialPacket)}
}

func (reassembler *reassembler) push(
	datagram []byte,
	endpoint netip.AddrPort,
	now time.Time,
) ([]byte, bool, error) {
	reassembler.expire(now)
	if packet.IsFragment(datagram) {
		fragment, err := packet.ParseFragment(datagram)
		if err != nil {
			return nil, false, err
		}
		if fragment.Number == 0 || fragment.TotalFragments < 2 ||
			fragment.TotalFragments > packet.MaxPacketFragments ||
			fragment.Number >= fragment.TotalFragments {
			return nil, false, errors.New("fragment numbering is invalid")
		}
		key := reassemblyKey{endpoint: endpoint, packetID: fragment.PacketID}
		partial, err := reassembler.slot(key, now)
		if err != nil {
			return nil, false, err
		}
		if partial.total != 0 && partial.total != fragment.TotalFragments {
			delete(reassembler.partial, key)
			return nil, false, errors.New("fragment total changed within packet")
		}
		partial.total = fragment.TotalFragments
		if _, duplicate := partial.fragments[fragment.Number]; duplicate {
			return reassembler.complete(key, partial)
		}
		if partial.bytes+len(fragment.Payload) > packet.MaxPacketLength {
			delete(reassembler.partial, key)
			return nil, false, errors.New("fragment set exceeds reassembly byte budget")
		}
		partial.fragments[fragment.Number] = append([]byte(nil), fragment.Payload...)
		partial.bytes += len(fragment.Payload)
		return reassembler.complete(key, partial)
	}

	routing, err := packet.ParseRouting(datagram)
	if err != nil {
		return nil, false, err
	}
	if !routing.Fragmented {
		return append([]byte(nil), datagram...), true, nil
	}
	key := reassemblyKey{endpoint: endpoint, packetID: routing.PacketID}
	partial, err := reassembler.slot(key, now)
	if err != nil {
		return nil, false, err
	}
	if len(partial.first) == 0 {
		if partial.bytes+len(datagram) > packet.MaxPacketLength {
			delete(reassembler.partial, key)
			return nil, false, errors.New("fragment set exceeds reassembly byte budget")
		}
		partial.first = append([]byte(nil), datagram...)
		partial.bytes += len(datagram)
	}
	return reassembler.complete(key, partial)
}

func (reassembler *reassembler) slot(key reassemblyKey, now time.Time) (*partialPacket, error) {
	if partial, ok := reassembler.partial[key]; ok {
		return partial, nil
	}
	if len(reassembler.partial) >= maxReassemblySlots {
		return nil, errors.New("fragment reassembly capacity exhausted")
	}
	partial := &partialPacket{
		created:   now,
		fragments: make(map[uint8][]byte),
	}
	reassembler.partial[key] = partial
	return partial, nil
}

func (reassembler *reassembler) complete(
	key reassemblyKey,
	partial *partialPacket,
) ([]byte, bool, error) {
	if len(partial.first) == 0 || partial.total == 0 ||
		len(partial.fragments) != int(partial.total)-1 {
		return nil, false, nil
	}
	assembled := append([]byte(nil), partial.first...)
	for number := uint8(1); number < partial.total; number++ {
		payload, ok := partial.fragments[number]
		if !ok {
			return nil, false, nil
		}
		if len(assembled)+len(payload) > packet.MaxPacketLength {
			delete(reassembler.partial, key)
			return nil, false, fmt.Errorf("reassembled packet exceeds %d bytes", packet.MaxPacketLength)
		}
		assembled = append(assembled, payload...)
	}
	delete(reassembler.partial, key)
	return assembled, true, nil
}

func (reassembler *reassembler) expire(now time.Time) {
	for key, partial := range reassembler.partial {
		if now.Sub(partial.created) >= reassemblyTTL {
			delete(reassembler.partial, key)
		}
	}
}
