package networkconfig

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const (
	credentialTypeCOM       = byte(1)
	revocationFastPropagate = uint64(1)
)

type Revocation struct {
	ID           uint32
	NetworkID    domain.NetworkID
	CredentialID uint32
	Threshold    uint64
	Flags        uint64
	Target       domain.NodeID
	SignedBy     domain.NodeID
	Type         byte
	Signature    identity.Signature
}

func NewCOMRevocation(
	networkID domain.NetworkID,
	target domain.NodeID,
	threshold time.Time,
	signer identity.Identity,
	random io.Reader,
) (Revocation, error) {
	if signer.Address() != mustControllerID(networkID) || !signer.HasPrivate() {
		return Revocation{}, fmt.Errorf("revocation signer is not the network controller")
	}
	if err := target.Validate(); err != nil {
		return Revocation{}, err
	}
	if threshold.IsZero() || threshold.UnixMilli() < 0 {
		return Revocation{}, fmt.Errorf("revocation threshold is invalid")
	}
	if random == nil {
		random = rand.Reader
	}
	var idBytes [4]byte
	if _, err := io.ReadFull(random, idBytes[:]); err != nil {
		return Revocation{}, fmt.Errorf("generate revocation ID: %w", err)
	}
	revocation := Revocation{
		ID: binary.BigEndian.Uint32(idBytes[:]), NetworkID: networkID,
		Threshold: uint64(threshold.UnixMilli()), Flags: revocationFastPropagate,
		Target: target, SignedBy: signer.Address(), Type: credentialTypeCOM,
	}
	signature, err := signer.Sign(withPolicySentinels(append(revocation.base(), 0, 0)))
	if err != nil {
		return Revocation{}, fmt.Errorf("sign revocation: %w", err)
	}
	revocation.Signature = signature
	return revocation, nil
}

func (revocation Revocation) MarshalBinary() ([]byte, error) {
	if revocation.Type == 0 || revocation.SignedBy == "" {
		return nil, fmt.Errorf("revocation is incomplete")
	}
	result := revocation.base()
	result = append(result, 1)
	result = append(result, uint16Bytes(identity.SignatureLength)...)
	result = append(result, revocation.Signature[:]...)
	result = append(result, 0, 0)
	return result, nil
}

func (revocation Revocation) Verify(signer identity.Identity) bool {
	return signer.Address() == revocation.SignedBy &&
		signer.Verify(withPolicySentinels(append(revocation.base(), 0, 0)), revocation.Signature)
}

func (revocation Revocation) base() []byte {
	networkValue, _ := parseHexUint(string(revocation.NetworkID))
	target, _ := nodeIDBytes(revocation.Target)
	signer, _ := nodeIDBytes(revocation.SignedBy)
	var result bytes.Buffer
	_ = binary.Write(&result, binary.BigEndian, uint32(0))
	_ = binary.Write(&result, binary.BigEndian, revocation.ID)
	_ = binary.Write(&result, binary.BigEndian, networkValue)
	_ = binary.Write(&result, binary.BigEndian, uint32(0))
	_ = binary.Write(&result, binary.BigEndian, revocation.CredentialID)
	_ = binary.Write(&result, binary.BigEndian, revocation.Threshold)
	_ = binary.Write(&result, binary.BigEndian, revocation.Flags)
	result.Write(target)
	result.Write(signer)
	result.WriteByte(revocation.Type)
	return result.Bytes()
}

func BuildRevocationCredentialsPayload(serialized []byte) []byte {
	result := []byte{0, 0, 0, 0, 0, 0, 1}
	result = append(result, serialized...)
	result = append(result, 0, 0)
	return result
}
