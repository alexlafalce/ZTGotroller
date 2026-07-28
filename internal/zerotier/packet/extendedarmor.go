package packet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const ephemeralPublicKeyLength = 32

// ArmorExtended authenticates a clear HELLO with the ordinary session key,
// then encrypts everything from the MAC onward with an ephemeral X25519/AES-CTR
// layer understood by protocol-13 agents.
func ArmorExtended(
	unarmored []byte,
	sessionKey SessionKey,
	destination identity.Identity,
) ([]byte, error) {
	if !destination.LocallyValidate() {
		return nil, errors.New("extended armor destination identity is invalid")
	}
	packet, err := armor(unarmored, sessionKey.salsaKey(), false, true)
	if err != nil {
		return nil, err
	}
	if len(packet)+ephemeralPublicKeyLength > MaxPacketLength {
		return nil, fmt.Errorf("extended armor packet exceeds %d bytes", MaxPacketLength)
	}
	curve := ecdh.X25519()
	ephemeral, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate extended armor key: %w", err)
	}
	public := destination.PublicKey()
	destinationKey, err := curve.NewPublicKey(public[:32])
	if err != nil {
		return nil, fmt.Errorf("load extended armor destination key: %w", err)
	}
	raw, err := ephemeral.ECDH(destinationKey)
	if err != nil {
		return nil, fmt.Errorf("derive extended armor key: %w", err)
	}
	digest := sha512.Sum512(raw)
	if err := cryptExtendedArmor(packet, digest[:32]); err != nil {
		return nil, err
	}
	packet = append(packet, ephemeral.PublicKey().Bytes()...)
	return packet, nil
}

// DearmorExtended removes the ephemeral encryption layer. The returned packet
// still carries ordinary ZeroTier session armor and must subsequently be
// authenticated with DearmorSession.
func DearmorExtended(armored []byte, local identity.Identity) ([]byte, error) {
	if !local.HasPrivate() {
		return nil, errors.New("extended armor requires a private local identity")
	}
	if len(armored) < HeaderLength+ephemeralPublicKeyLength {
		return nil, errors.New("extended armor packet is truncated")
	}
	if len(armored) > MaxPacketLength {
		return nil, fmt.Errorf("extended armor packet exceeds %d bytes", MaxPacketLength)
	}
	routing, err := ParseRouting(armored)
	if err != nil {
		return nil, err
	}
	if !routing.ExtendedArmor || routing.Cipher != CipherC25519Poly1305Clear {
		return nil, errors.New("packet does not use extended clear armor")
	}
	ciphertextEnd := len(armored) - ephemeralPublicKeyLength
	if ciphertextEnd < HeaderLength {
		return nil, errors.New("extended armor ciphertext is truncated")
	}
	var ephemeral [32]byte
	copy(ephemeral[:], armored[ciphertextEnd:])
	key, err := local.AgreeRawPublic(ephemeral, 32)
	if err != nil {
		return nil, fmt.Errorf("derive extended armor key: %w", err)
	}
	packet := append([]byte(nil), armored[:ciphertextEnd]...)
	if err := cryptExtendedArmor(packet, key); err != nil {
		return nil, err
	}
	return packet, nil
}

func cryptExtendedArmor(packet, key []byte) error {
	if len(packet) < HeaderLength {
		return errors.New("extended armor packet is shorter than its header")
	}
	if len(key) != 32 {
		return errors.New("extended armor key must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("initialize extended armor AES: %w", err)
	}
	var counter [aes.BlockSize]byte
	copy(counter[:12], packet[:12])
	cipher.NewCTR(block, counter[:]).XORKeyStream(packet[19:], packet[19:])
	return nil
}
