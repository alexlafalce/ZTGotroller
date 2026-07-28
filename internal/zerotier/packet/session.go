package packet

import "fmt"

const SessionKeyLength = 48

type SessionKey [SessionKeyLength]byte

func (key SessionKey) salsaKey() [32]byte {
	var salsa [32]byte
	copy(salsa[:], key[:32])
	return salsa
}

func DearmorSession(armored []byte, key SessionKey) (Decoded, error) {
	routing, err := ParseRouting(armored)
	if err != nil {
		return Decoded{}, err
	}
	if routing.Cipher == CipherAESGMACSIV {
		return DearmorAES(armored, key)
	}
	return Dearmor(armored, key.salsaKey())
}

func ArmorSession(unarmored []byte, key SessionKey, encrypt, useAES bool) ([]byte, error) {
	if useAES {
		return ArmorAES(unarmored, key)
	}
	return Armor(unarmored, key.salsaKey(), encrypt)
}

func ArmorSessionAndFragment(
	unarmored []byte,
	key SessionKey,
	encrypt bool,
	useAES bool,
	mtu int,
) ([][]byte, error) {
	if !useAES {
		return ArmorAndFragment(unarmored, key.salsaKey(), encrypt, mtu)
	}
	if mtu == 0 {
		mtu = DefaultPhysicalMTU
	}
	maxAssembled := mtu + (MaxPacketFragments-1)*(mtu-FragmentLength)
	if len(unarmored) > maxAssembled {
		return nil, fmt.Errorf("packet length %d exceeds %d-byte fragmented capacity", len(unarmored), maxAssembled)
	}
	draft := append([]byte(nil), unarmored...)
	if len(draft) > mtu {
		draft[18] |= FlagFragmented
	}
	armored, err := ArmorAES(draft, key)
	if err != nil {
		return nil, err
	}
	return fragmentArmored(armored, mtu)
}
