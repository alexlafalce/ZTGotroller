package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
)

func ArmorAES(unarmored []byte, sessionKey SessionKey) ([]byte, error) {
	if len(unarmored) < HeaderLength || len(unarmored) > MaxPacketLength {
		return nil, errors.New("unarmored packet has invalid length")
	}
	key0, key1, err := aesSessionKeys(sessionKey)
	if err != nil {
		return nil, err
	}
	packet := append([]byte(nil), unarmored...)
	packet[18] = (packet[18] & 0xc7) | byte(CipherAESGMACSIV<<3)
	packet[18] &^= FlagExtendedArmor
	plaintext := packet[27:]
	authenticated := make([]byte, 0, 16+len(plaintext))
	authenticated = append(authenticated, packet[8:19]...)
	authenticated = append(authenticated, make([]byte, 5)...)
	authenticated = append(authenticated, plaintext...)
	var iv [12]byte
	copy(iv[:8], packet[:8])
	gmac := computeGMAC(key0, iv, authenticated)
	var synthetic [16]byte
	copy(synthetic[:8], packet[:8])
	for index := 0; index < 8; index++ {
		synthetic[8+index] = gmac[index] ^ gmac[8+index]
	}
	key1.Encrypt(synthetic[:], synthetic[:])
	counter := synthetic
	counter[12] &= 0x7f
	cipher.NewCTR(key1, counter[:]).XORKeyStream(plaintext, plaintext)
	copy(packet[:8], synthetic[:8])
	copy(packet[19:27], synthetic[8:])
	return packet, nil
}

func DearmorAES(armored []byte, sessionKey SessionKey) (Decoded, error) {
	if len(armored) < HeaderLength || len(armored) > MaxPacketLength {
		return Decoded{}, errors.New("armored packet has invalid length")
	}
	routing, err := ParseRouting(armored)
	if err != nil {
		return Decoded{}, err
	}
	if routing.Cipher != CipherAESGMACSIV {
		return Decoded{}, fmt.Errorf("packet cipher %d is not AES-GMAC-SIV", routing.Cipher)
	}
	key0, key1, err := aesSessionKeys(sessionKey)
	if err != nil {
		return Decoded{}, err
	}
	packet := append([]byte(nil), armored...)
	var synthetic [16]byte
	copy(synthetic[:8], packet[:8])
	copy(synthetic[8:], packet[19:27])
	counter := synthetic
	counter[12] &= 0x7f
	cipher.NewCTR(key1, counter[:]).XORKeyStream(packet[27:], packet[27:])
	var ivMac [16]byte
	key1.Decrypt(ivMac[:], synthetic[:])
	authenticated := make([]byte, 0, 16+len(packet[27:]))
	authenticated = append(authenticated, packet[8:19]...)
	authenticated[10] &= 0xf8 // forwarding nodes may alter hop count
	authenticated = append(authenticated, make([]byte, 5)...)
	authenticated = append(authenticated, packet[27:]...)
	var iv [12]byte
	copy(iv[:8], ivMac[:8])
	gmac := computeGMAC(key0, iv, authenticated)
	var expected [8]byte
	for index := range expected {
		expected[index] = gmac[index] ^ gmac[8+index]
	}
	if subtle.ConstantTimeCompare(expected[:], ivMac[8:]) != 1 {
		return Decoded{}, errors.New("AES-GMAC-SIV packet authentication failed")
	}
	return ParseDecoded(packet)
}

func aesSessionKeys(sessionKey SessionKey) (cipher.Block, cipher.Block, error) {
	first := deriveAESKey(sessionKey, '0')
	second := deriveAESKey(sessionKey, '1')
	key0, err := aes.NewCipher(first[:32])
	if err != nil {
		return nil, nil, err
	}
	key1, err := aes.NewCipher(second[:32])
	if err != nil {
		return nil, nil, err
	}
	return key0, key1, nil
}

func deriveAESKey(sessionKey SessionKey, label byte) [48]byte {
	message := [13]byte{0, 0, 0, 0, 'Z', 'T', label, 0, 0, 0, 0, 1, 0x80}
	mac := hmac.New(sha512.New384, sessionKey[:])
	_, _ = mac.Write(message[:])
	var result [48]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func computeGMAC(block cipher.Block, iv [12]byte, data []byte) [16]byte {
	var zero, hash [16]byte
	block.Encrypt(hash[:], zero[:])
	var accumulator [16]byte
	for offset := 0; offset < len(data); offset += 16 {
		var chunk [16]byte
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		copy(chunk[:], data[offset:end])
		xorBlock(&accumulator, &chunk)
		accumulator = galoisMultiply(accumulator, hash)
	}
	var length [16]byte
	bitLength := uint64(len(data)) * 8
	for index := 0; index < 8; index++ {
		length[7-index] = byte(bitLength >> (index * 8))
	}
	xorBlock(&accumulator, &length)
	accumulator = galoisMultiply(accumulator, hash)
	var counter [16]byte
	copy(counter[:12], iv[:])
	counter[15] = 1
	block.Encrypt(counter[:], counter[:])
	xorBlock(&accumulator, &counter)
	return accumulator
}

func galoisMultiply(left, right [16]byte) [16]byte {
	var product [16]byte
	value := right
	for bit := 0; bit < 128; bit++ {
		if left[bit/8]&(1<<uint(7-bit%8)) != 0 {
			xorBlock(&product, &value)
		}
		least := value[15] & 1
		for index := 15; index > 0; index-- {
			value[index] = value[index]>>1 | value[index-1]<<7
		}
		value[0] >>= 1
		if least != 0 {
			value[0] ^= 0xe1
		}
	}
	return product
}

func xorBlock(destination, source *[16]byte) {
	for index := range destination {
		destination[index] ^= source[index]
	}
}
