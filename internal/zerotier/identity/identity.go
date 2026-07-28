package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

const (
	TypeC25519            = byte(0)
	PublicKeyLength       = 64
	PrivateKeyLength      = 64
	SignatureLength       = 96
	PublicBinaryLength    = 5 + 1 + PublicKeyLength + 1
	SecretBinaryLength    = PublicBinaryLength + PrivateKeyLength
	MaxAgreementKeyLength = 4096
)

type Identity struct {
	address    domain.NodeID
	publicKey  [PublicKeyLength]byte
	privateKey [PrivateKeyLength]byte
	hasPrivate bool
}

type Signature [SignatureLength]byte

func Parse(value string) (Identity, error) {
	fields := strings.Split(value, ":")
	if len(fields) != 3 && len(fields) != 4 {
		return Identity{}, errors.New("identity must contain three or four fields")
	}
	address, err := domain.ParseNodeID(fields[0])
	if err != nil {
		return Identity{}, err
	}
	if isReserved(address) {
		return Identity{}, errors.New("identity uses a reserved address")
	}
	if fields[1] != "0" {
		return Identity{}, fmt.Errorf("unsupported identity type %q", fields[1])
	}
	var identity Identity
	identity.address = address
	if err := decodeKey(fields[2], identity.publicKey[:], "public"); err != nil {
		return Identity{}, err
	}
	if len(fields) == 4 {
		if err := decodeKey(fields[3], identity.privateKey[:], "private"); err != nil {
			return Identity{}, err
		}
		identity.hasPrivate = true
	}
	return identity, nil
}

func ParseBinary(value []byte) (Identity, error) {
	if len(value) != PublicBinaryLength && len(value) != SecretBinaryLength {
		return Identity{}, fmt.Errorf("invalid binary identity length %d", len(value))
	}
	address, err := domain.ParseNodeID(hex.EncodeToString(value[:5]))
	if err != nil {
		return Identity{}, err
	}
	if isReserved(address) {
		return Identity{}, errors.New("identity uses a reserved address")
	}
	if value[5] != TypeC25519 {
		return Identity{}, fmt.Errorf("unsupported identity type %d", value[5])
	}
	var identity Identity
	identity.address = address
	copy(identity.publicKey[:], value[6:6+PublicKeyLength])
	privateLength := int(value[6+PublicKeyLength])
	switch {
	case privateLength == 0 && len(value) == PublicBinaryLength:
	case privateLength == PrivateKeyLength && len(value) == SecretBinaryLength:
		copy(identity.privateKey[:], value[PublicBinaryLength:])
		identity.hasPrivate = true
	default:
		return Identity{}, errors.New("private key length does not match identity payload")
	}
	return identity, nil
}

func (identity Identity) Address() domain.NodeID {
	return identity.address
}

func (identity Identity) HasPrivate() bool {
	return identity.hasPrivate
}

func (identity Identity) PublicKey() [PublicKeyLength]byte {
	return identity.publicKey
}

func (identity Identity) Public() Identity {
	identity.privateKey = [PrivateKeyLength]byte{}
	identity.hasPrivate = false
	return identity
}

func (identity Identity) Sign(message []byte) (Signature, error) {
	if !identity.hasPrivate {
		return Signature{}, errors.New("identity has no private key")
	}
	seed := identity.privateKey[32:]
	privateKey := ed25519.NewKeyFromSeed(seed)
	if subtle.ConstantTimeCompare(privateKey[32:], identity.publicKey[32:]) != 1 {
		return Signature{}, errors.New("private signing key does not match public identity")
	}
	digest := sha512.Sum512(message)
	edSignature := ed25519.Sign(privateKey, digest[:32])
	var signature Signature
	copy(signature[:64], edSignature)
	copy(signature[64:], digest[:32])
	return signature, nil
}

func (identity Identity) Verify(message []byte, signature Signature) bool {
	digest := sha512.Sum512(message)
	if subtle.ConstantTimeCompare(signature[64:], digest[:32]) != 1 {
		return false
	}
	return ed25519.Verify(
		ed25519.PublicKey(identity.publicKey[32:]),
		digest[:32],
		signature[:64],
	)
}

// Agree derives ZeroTier symmetric key material with the Curve25519 halves of
// two identities. The raw X25519 secret is expanded through repeated SHA-512.
func (identity Identity) Agree(peer Identity, length int) ([]byte, error) {
	if !identity.hasPrivate {
		return nil, errors.New("identity has no private key")
	}
	if length <= 0 || length > MaxAgreementKeyLength {
		return nil, fmt.Errorf("agreement key length must be between 1 and %d", MaxAgreementKeyLength)
	}
	curve := ecdh.X25519()
	privateKey, err := curve.NewPrivateKey(identity.privateKey[:32])
	if err != nil {
		return nil, fmt.Errorf("load private agreement key: %w", err)
	}
	publicKey, err := curve.NewPublicKey(peer.publicKey[:32])
	if err != nil {
		return nil, fmt.Errorf("load public agreement key: %w", err)
	}
	raw, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("agree keys: %w", err)
	}
	digest := sha512.Sum512(raw)
	key := make([]byte, length)
	for offset := 0; offset < length; {
		copied := copy(key[offset:], digest[:])
		offset += copied
		if offset < length {
			digest = sha512.Sum512(digest[:])
		}
	}
	return key, nil
}

func (identity Identity) String() string {
	value := string(identity.address) + ":0:" + hex.EncodeToString(identity.publicKey[:])
	return value
}

func (identity Identity) SecretString() (string, error) {
	if !identity.hasPrivate {
		return "", errors.New("identity has no private key")
	}
	value := identity.String()
	if identity.hasPrivate {
		value += ":" + hex.EncodeToString(identity.privateKey[:])
	}
	return value, nil
}

func (identity Identity) MarshalBinary() ([]byte, error) {
	if err := identity.address.Validate(); err != nil {
		return nil, err
	}
	if isReserved(identity.address) {
		return nil, errors.New("identity uses a reserved address")
	}
	length := PublicBinaryLength
	if identity.hasPrivate {
		length = SecretBinaryLength
	}
	value := make([]byte, length)
	address, _ := hex.DecodeString(string(identity.address))
	copy(value[:5], address)
	value[5] = TypeC25519
	copy(value[6:6+PublicKeyLength], identity.publicKey[:])
	if identity.hasPrivate {
		value[6+PublicKeyLength] = PrivateKeyLength
		copy(value[PublicBinaryLength:], identity.privateKey[:])
	}
	return value, nil
}

func decodeKey(value string, destination []byte, name string) error {
	if len(value) != len(destination)*2 {
		return fmt.Errorf("%s key must contain %d hexadecimal characters", name, len(destination)*2)
	}
	if value != strings.ToLower(value) {
		return fmt.Errorf("%s key must use lowercase hexadecimal", name)
	}
	if _, err := hex.Decode(destination, []byte(value)); err != nil {
		return fmt.Errorf("%s key must be hexadecimal", name)
	}
	return nil
}

func isReserved(address domain.NodeID) bool {
	return address == "0000000000" || strings.HasPrefix(string(address), "ff")
}
