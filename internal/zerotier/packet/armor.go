package packet

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"golang.org/x/crypto/poly1305"
)

const MaxPacketLength = 7 * 1432

func Build(packetID uint64, destination, source domain.NodeID, verb Verb, payload []byte) ([]byte, error) {
	if err := destination.Validate(); err != nil {
		return nil, fmt.Errorf("destination: %w", err)
	}
	if err := source.Validate(); err != nil {
		return nil, fmt.Errorf("source: %w", err)
	}
	if verb > 0x1f {
		return nil, fmt.Errorf("verb %d exceeds five-bit framing", verb)
	}
	if HeaderLength+len(payload) > MaxPacketLength {
		return nil, fmt.Errorf("packet length exceeds %d bytes", MaxPacketLength)
	}
	packet := make([]byte, HeaderLength+len(payload))
	binary.BigEndian.PutUint64(packet[:8], packetID)
	destinationBytes, _ := hex.DecodeString(string(destination))
	sourceBytes, _ := hex.DecodeString(string(source))
	copy(packet[8:13], destinationBytes)
	copy(packet[13:18], sourceBytes)
	packet[27] = byte(verb)
	copy(packet[HeaderLength:], payload)
	return packet, nil
}

// Armor authenticates a packet and optionally encrypts its verb and payload
// using ZeroTier's C25519/Poly1305/Salsa20/12 suite.
func Armor(unarmored []byte, sharedKey [32]byte, encrypt bool) ([]byte, error) {
	return armor(unarmored, sharedKey, encrypt, false)
}

func armor(unarmored []byte, sharedKey [32]byte, encrypt, extended bool) ([]byte, error) {
	if len(unarmored) < HeaderLength || len(unarmored) > MaxPacketLength {
		return nil, errors.New("unarmored packet has invalid length")
	}
	packet := append([]byte(nil), unarmored...)
	cipher := CipherC25519Poly1305Clear
	if encrypt {
		cipher = CipherC25519Poly1305Salsa
	}
	packet[18] = (packet[18] & 0xc7) | byte(cipher<<3)
	if extended {
		packet[18] |= FlagExtendedArmor
	} else {
		packet[18] &^= FlagExtendedArmor
	}
	if encrypt {
		packet[18] |= FlagExtendedArmor // historical encrypted flag shares bit 0x80
	}
	key := mangleKey(packet, sharedKey)
	stream := salsa12Stream(key, packet[:8], 64+len(packet[27:]))
	if encrypt {
		xorBytes(packet[27:], stream[64:])
	}
	var polyKey [32]byte
	copy(polyKey[:], stream[:32])
	var tag [16]byte
	poly1305.Sum(&tag, packet[27:], &polyKey)
	copy(packet[19:27], tag[:8])
	return packet, nil
}

// Dearmor authenticates before decrypting and only then exposes Decoded.
func Dearmor(armored []byte, sharedKey [32]byte) (Decoded, error) {
	if len(armored) < HeaderLength || len(armored) > MaxPacketLength {
		return Decoded{}, errors.New("armored packet has invalid length")
	}
	routing, err := ParseRouting(armored)
	if err != nil {
		return Decoded{}, err
	}
	if routing.Cipher != CipherC25519Poly1305Clear && routing.Cipher != CipherC25519Poly1305Salsa {
		return Decoded{}, fmt.Errorf("unsupported packet cipher %d", routing.Cipher)
	}
	packet := append([]byte(nil), armored...)
	key := mangleKey(packet, sharedKey)
	stream := salsa12Stream(key, packet[:8], 64+len(packet[27:]))
	var polyKey [32]byte
	copy(polyKey[:], stream[:32])
	var tag [16]byte
	poly1305.Sum(&tag, packet[27:], &polyKey)
	if subtle.ConstantTimeCompare(packet[19:27], tag[:8]) != 1 {
		return Decoded{}, errors.New("packet authentication failed")
	}
	if routing.Cipher == CipherC25519Poly1305Salsa {
		xorBytes(packet[27:], stream[64:])
	}
	return ParseDecoded(packet)
}

func mangleKey(packet []byte, sharedKey [32]byte) [32]byte {
	key := sharedKey
	for index := 0; index < 18; index++ {
		key[index] ^= packet[index]
	}
	key[18] ^= packet[18] & 0xf8
	key[19] ^= byte(len(packet))
	key[20] ^= byte(len(packet) >> 8)
	return key
}

func salsa12Stream(key [32]byte, nonce []byte, length int) []byte {
	stream := make([]byte, length)
	for offset, counter := 0, uint64(0); offset < length; counter++ {
		block := salsa12Block(key, nonce, counter)
		offset += copy(stream[offset:], block[:])
	}
	return stream
}

func salsa12Block(key [32]byte, nonce []byte, counter uint64) [64]byte {
	constants := [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}
	var state [16]uint32
	state[0], state[5], state[10], state[15] = constants[0], constants[1], constants[2], constants[3]
	for index := 0; index < 4; index++ {
		state[1+index] = binary.LittleEndian.Uint32(key[index*4:])
		state[11+index] = binary.LittleEndian.Uint32(key[16+index*4:])
	}
	state[6] = binary.LittleEndian.Uint32(nonce[:4])
	state[7] = binary.LittleEndian.Uint32(nonce[4:8])
	state[8] = uint32(counter)
	state[9] = uint32(counter >> 32)
	working := state
	for round := 0; round < 12; round += 2 {
		salsaQuarter(&working, 0, 4, 8, 12)
		salsaQuarter(&working, 5, 9, 13, 1)
		salsaQuarter(&working, 10, 14, 2, 6)
		salsaQuarter(&working, 15, 3, 7, 11)
		salsaQuarter(&working, 0, 1, 2, 3)
		salsaQuarter(&working, 5, 6, 7, 4)
		salsaQuarter(&working, 10, 11, 8, 9)
		salsaQuarter(&working, 15, 12, 13, 14)
	}
	var block [64]byte
	for index := range working {
		binary.LittleEndian.PutUint32(block[index*4:], working[index]+state[index])
	}
	return block
}

func salsaQuarter(state *[16]uint32, a, b, c, d int) {
	state[b] ^= bits.RotateLeft32(state[a]+state[d], 7)
	state[c] ^= bits.RotateLeft32(state[b]+state[a], 9)
	state[d] ^= bits.RotateLeft32(state[c]+state[b], 13)
	state[a] ^= bits.RotateLeft32(state[d]+state[c], 18)
}

func xorBytes(destination, keyStream []byte) {
	for index := range destination {
		destination[index] ^= keyStream[index]
	}
}
