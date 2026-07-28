package identity

import (
	"crypto/sha512"
	"encoding/binary"

	"golang.org/x/crypto/salsa20/salsa"
)

const (
	proofMemorySize = 2 * 1024 * 1024
	proofThreshold  = byte(17)
	salsaBlockSize  = 64
)

// LocallyValidate verifies that the public key satisfies ZeroTier's identity
// proof of work and derives the identity's declared 40-bit address.
func (identity Identity) LocallyValidate() bool {
	if isReserved(identity.address) {
		return false
	}
	digest := memoryHardHash(identity.publicKey[:])
	if digest[0] >= proofThreshold {
		return false
	}
	addressBytes := []byte{
		byteValue(string(identity.address), 0),
		byteValue(string(identity.address), 1),
		byteValue(string(identity.address), 2),
		byteValue(string(identity.address), 3),
		byteValue(string(identity.address), 4),
	}
	for index := range addressBytes {
		if digest[59+index] != addressBytes[index] {
			return false
		}
	}
	return true
}

func memoryHardHash(publicKey []byte) [64]byte {
	digest := sha512.Sum512(publicKey)
	var key [32]byte
	var counter [16]byte
	copy(key[:], digest[:32])
	copy(counter[:8], digest[32:40])

	memory := make([]byte, proofMemorySize)
	// Generate every keystream block at once, then apply the CBC-like input
	// dependency used by ZeroTier: plaintext block N is ciphertext block N-1.
	salsa.XORKeyStream(memory, memory, &counter, &key)
	for offset := salsaBlockSize; offset < len(memory); offset += salsaBlockSize {
		for index := 0; index < salsaBlockSize; index++ {
			memory[offset+index] ^= memory[offset-salsaBlockSize+index]
		}
	}

	binary.LittleEndian.PutUint64(counter[8:], uint64(proofMemorySize/salsaBlockSize))
	for offset := 0; offset < len(memory); {
		first := binary.BigEndian.Uint64(memory[offset : offset+8])
		offset += 8
		second := binary.BigEndian.Uint64(memory[offset : offset+8])
		offset += 8
		digestOffset := int(first%8) * 8
		memoryOffset := int(second%(proofMemorySize/8)) * 8
		var temporary [8]byte
		copy(temporary[:], memory[memoryOffset:memoryOffset+8])
		copy(memory[memoryOffset:memoryOffset+8], digest[digestOffset:digestOffset+8])
		copy(digest[digestOffset:digestOffset+8], temporary[:])
		salsa.XORKeyStream(digest[:], digest[:], &counter, &key)
		incrementSalsaCounter(&counter)
	}
	return digest
}

func incrementSalsaCounter(counter *[16]byte) {
	value := binary.LittleEndian.Uint64(counter[8:])
	binary.LittleEndian.PutUint64(counter[8:], value+1)
}

func byteValue(address string, index int) byte {
	high := hexNibble(address[index*2])
	low := hexNibble(address[index*2+1])
	return high<<4 | low
}

func hexNibble(value byte) byte {
	if value <= '9' {
		return value - '0'
	}
	return value - 'a' + 10
}
