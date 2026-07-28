package networkconfig

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const (
	membershipFormatVersion = 1
	maxCOMQualifiers        = 8
)

type COMQualifier struct {
	ID       uint64
	Value    uint64
	MaxDelta uint64
}

type CertificateOfMembership struct {
	Qualifiers []COMQualifier
	SignedBy   domain.NodeID
	Signature  identity.Signature
}

func NewCertificateOfMembership(
	timestamp uint64,
	timestampMaxDelta uint64,
	networkID domain.NetworkID,
	issuedTo identity.Identity,
	signer identity.Identity,
) (CertificateOfMembership, error) {
	if signer.Address() != mustControllerID(networkID) {
		return CertificateOfMembership{}, errors.New("COM signer is not the network controller")
	}
	networkValue, err := parseHexUint(string(networkID))
	if err != nil {
		return CertificateOfMembership{}, err
	}
	issuedValue, err := parseHexUint(string(issuedTo.Address()))
	if err != nil {
		return CertificateOfMembership{}, err
	}
	publicHash, err := identityPublicHash(issuedTo)
	if err != nil {
		return CertificateOfMembership{}, err
	}
	certificate := CertificateOfMembership{
		Qualifiers: []COMQualifier{
			{ID: 0, Value: timestamp, MaxDelta: timestampMaxDelta},
			{ID: 1, Value: networkValue},
			{ID: 2, Value: issuedValue, MaxDelta: ^uint64(0)},
			{ID: 3, Value: binary.BigEndian.Uint64(publicHash[0:8]), MaxDelta: ^uint64(0)},
			{ID: 4, Value: binary.BigEndian.Uint64(publicHash[8:16]), MaxDelta: ^uint64(0)},
			{ID: 5, Value: binary.BigEndian.Uint64(publicHash[16:24]), MaxDelta: ^uint64(0)},
			{ID: 6, Value: binary.BigEndian.Uint64(publicHash[24:32]), MaxDelta: ^uint64(0)},
		},
		SignedBy: signer.Address(),
	}
	signature, err := signer.Sign(certificate.signedPayload())
	if err != nil {
		return CertificateOfMembership{}, fmt.Errorf("sign COM: %w", err)
	}
	certificate.Signature = signature
	return certificate, nil
}

func (certificate CertificateOfMembership) Verify(
	networkID domain.NetworkID,
	signer identity.Identity,
) error {
	if err := certificate.validate(); err != nil {
		return err
	}
	if certificate.SignedBy != mustControllerID(networkID) {
		return errors.New("COM was not signed by the network controller")
	}
	if signer.Address() != certificate.SignedBy {
		return errors.New("provided signer identity does not match COM signer")
	}
	if !signer.Verify(certificate.signedPayload(), certificate.Signature) {
		return errors.New("invalid COM signature")
	}
	return nil
}

func (certificate CertificateOfMembership) MarshalBinary() ([]byte, error) {
	if err := certificate.validate(); err != nil {
		return nil, err
	}
	var result bytes.Buffer
	result.WriteByte(membershipFormatVersion)
	_ = binary.Write(&result, binary.BigEndian, uint16(len(certificate.Qualifiers)))
	result.Write(certificate.signedPayload())
	signer, _ := hex.DecodeString(string(certificate.SignedBy))
	result.Write(signer)
	result.Write(certificate.Signature[:])
	return result.Bytes(), nil
}

func ParseCertificateOfMembership(serialized []byte) (CertificateOfMembership, error) {
	if len(serialized) < 1+2+5 {
		return CertificateOfMembership{}, errors.New("COM is truncated")
	}
	if serialized[0] != membershipFormatVersion {
		return CertificateOfMembership{}, fmt.Errorf("unsupported COM version %d", serialized[0])
	}
	count := int(binary.BigEndian.Uint16(serialized[1:3]))
	if count == 0 || count > maxCOMQualifiers {
		return CertificateOfMembership{}, fmt.Errorf("invalid COM qualifier count %d", count)
	}
	expected := 3 + count*24 + 5 + identity.SignatureLength
	if len(serialized) != expected {
		return CertificateOfMembership{}, fmt.Errorf("COM length %d, want %d", len(serialized), expected)
	}
	certificate := CertificateOfMembership{Qualifiers: make([]COMQualifier, count)}
	offset := 3
	for index := range certificate.Qualifiers {
		certificate.Qualifiers[index] = COMQualifier{
			ID:       binary.BigEndian.Uint64(serialized[offset : offset+8]),
			Value:    binary.BigEndian.Uint64(serialized[offset+8 : offset+16]),
			MaxDelta: binary.BigEndian.Uint64(serialized[offset+16 : offset+24]),
		}
		offset += 24
	}
	signer, err := domain.ParseNodeID(hex.EncodeToString(serialized[offset : offset+5]))
	if err != nil {
		return CertificateOfMembership{}, err
	}
	certificate.SignedBy = signer
	copy(certificate.Signature[:], serialized[offset+5:])
	if err := certificate.validate(); err != nil {
		return CertificateOfMembership{}, err
	}
	return certificate, nil
}

func (certificate CertificateOfMembership) validate() error {
	if len(certificate.Qualifiers) == 0 || len(certificate.Qualifiers) > maxCOMQualifiers {
		return fmt.Errorf("COM must contain between 1 and %d qualifiers", maxCOMQualifiers)
	}
	for index, qualifier := range certificate.Qualifiers {
		if index > 0 && qualifier.ID < certificate.Qualifiers[index-1].ID {
			return errors.New("COM qualifiers are not sorted")
		}
	}
	if err := certificate.SignedBy.Validate(); err != nil {
		return fmt.Errorf("COM signer: %w", err)
	}
	return nil
}

func (certificate CertificateOfMembership) signedPayload() []byte {
	payload := make([]byte, len(certificate.Qualifiers)*24)
	for index, qualifier := range certificate.Qualifiers {
		offset := index * 24
		binary.BigEndian.PutUint64(payload[offset:offset+8], qualifier.ID)
		binary.BigEndian.PutUint64(payload[offset+8:offset+16], qualifier.Value)
		binary.BigEndian.PutUint64(payload[offset+16:offset+24], qualifier.MaxDelta)
	}
	return payload
}

func identityPublicHash(value identity.Identity) ([48]byte, error) {
	address, err := hex.DecodeString(string(value.Address()))
	if err != nil {
		return [48]byte{}, err
	}
	publicKey := value.PublicKey()
	input := make([]byte, 0, len(address)+len(publicKey))
	input = append(input, address...)
	input = append(input, publicKey[:]...)
	return sha512.Sum384(input), nil
}

func parseHexUint(value string) (uint64, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0, err
	}
	var padded [8]byte
	copy(padded[8-len(decoded):], decoded)
	return binary.BigEndian.Uint64(padded[:]), nil
}

func mustControllerID(networkID domain.NetworkID) domain.NodeID {
	controller, _ := networkID.ControllerID()
	return controller
}
