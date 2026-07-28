package identity

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

// Generate creates a type-0 identity using ZeroTier's proof-of-work search.
// When random is nil, crypto/rand.Reader is used.
func Generate(ctx context.Context, random io.Reader) (Identity, error) {
	if ctx == nil {
		return Identity{}, errors.New("context is required")
	}
	if random == nil {
		random = rand.Reader
	}
	var identity Identity
	identity.hasPrivate = true
	if _, err := io.ReadFull(random, identity.privateKey[:]); err != nil {
		return Identity{}, err
	}

	signingKey := ed25519.NewKeyFromSeed(identity.privateKey[32:])
	copy(identity.publicKey[32:], signingKey[32:])
	curve := ecdh.X25519()

	for {
		if err := ctx.Err(); err != nil {
			return Identity{}, err
		}
		incrementCandidate(identity.privateKey[:32])
		privateKey, err := curve.NewPrivateKey(identity.privateKey[:32])
		if err != nil {
			return Identity{}, err
		}
		copy(identity.publicKey[:32], privateKey.PublicKey().Bytes())
		digest := memoryHardHash(identity.publicKey[:])
		if digest[0] >= proofThreshold {
			continue
		}
		address := domain.NodeID(hex.EncodeToString(digest[59:]))
		if isReserved(address) {
			continue
		}
		identity.address = address
		return identity, nil
	}
}

func incrementCandidate(privateKey []byte) {
	first := binary.LittleEndian.Uint64(privateKey[8:16])
	second := binary.LittleEndian.Uint64(privateKey[16:24])
	binary.LittleEndian.PutUint64(privateKey[8:16], first+1)
	binary.LittleEndian.PutUint64(privateKey[16:24], second-1)
}
