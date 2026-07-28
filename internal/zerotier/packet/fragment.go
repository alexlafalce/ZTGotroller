package packet

import (
	"errors"
	"fmt"
)

const (
	DefaultPhysicalMTU = 1432
	MaxPacketFragments = 7
)

// ArmorAndFragment sets the authenticated fragmented flag before armoring and
// splits the resulting packet using ZeroTier's fragment framing.
func ArmorAndFragment(
	unarmored []byte,
	sharedKey [32]byte,
	encrypt bool,
	mtu int,
) ([][]byte, error) {
	if mtu == 0 {
		mtu = DefaultPhysicalMTU
	}
	if mtu < HeaderLength || mtu <= FragmentLength {
		return nil, errors.New("physical MTU is too small for ZeroTier framing")
	}
	maxAssembled := mtu + (MaxPacketFragments-1)*(mtu-FragmentLength)
	if len(unarmored) > maxAssembled {
		return nil, fmt.Errorf("packet length %d exceeds %d-byte fragmented capacity", len(unarmored), maxAssembled)
	}
	draft := append([]byte(nil), unarmored...)
	if len(draft) > mtu {
		draft[18] |= FlagFragmented
	}
	armored, err := Armor(draft, sharedKey, encrypt)
	if err != nil {
		return nil, err
	}
	return fragmentArmored(armored, mtu)
}

func fragmentArmored(armored []byte, mtu int) ([][]byte, error) {
	if len(armored) <= mtu {
		return [][]byte{armored}, nil
	}
	remaining := len(armored) - mtu
	fragmentPayload := mtu - FragmentLength
	total := 1 + (remaining+fragmentPayload-1)/fragmentPayload
	if total > MaxPacketFragments {
		return nil, errors.New("packet requires too many fragments")
	}
	fragments := make([][]byte, 0, total)
	fragments = append(fragments, append([]byte(nil), armored[:mtu]...))
	offset := mtu
	for number := 1; number < total; number++ {
		length := fragmentPayload
		if length > len(armored)-offset {
			length = len(armored) - offset
		}
		fragment := make([]byte, FragmentLength+length)
		copy(fragment[:13], armored[:13])
		fragment[13] = 0xff
		fragment[14] = byte(total<<4 | number)
		copy(fragment[FragmentLength:], armored[offset:offset+length])
		fragments = append(fragments, fragment)
		offset += length
	}
	return fragments, nil
}
