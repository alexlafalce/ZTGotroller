package networkconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const (
	maxOwnershipThings = 16
	ownershipSentinel  = uint64(0x7f7f7f7f7f7f7f7f)
	ownershipCrypto    = byte(1) // Ed25519

	ownershipThingIPv4 = byte(2)
	ownershipThingIPv6 = byte(3)
)

type OwnershipThing struct {
	Type  byte
	Value [16]byte
}

type CertificateOfOwnership struct {
	NetworkID domain.NetworkID
	Timestamp uint64
	Flags     uint64
	ID        uint32
	Things    []OwnershipThing
	IssuedTo  domain.NodeID
	SignedBy  domain.NodeID
	Signature identity.Signature
}

func NewCertificateOfOwnership(
	networkID domain.NetworkID,
	timestamp uint64,
	id uint32,
	issuedTo domain.NodeID,
	addresses []netip.Addr,
	signer identity.Identity,
) (CertificateOfOwnership, error) {
	if len(addresses) == 0 || len(addresses) > maxOwnershipThings {
		return CertificateOfOwnership{}, fmt.Errorf("ownership certificate requires between 1 and %d addresses", maxOwnershipThings)
	}
	if signer.Address() != mustControllerID(networkID) {
		return CertificateOfOwnership{}, errors.New("ownership signer is not the network controller")
	}
	certificate := CertificateOfOwnership{
		NetworkID: networkID,
		Timestamp: timestamp,
		ID:        id,
		IssuedTo:  issuedTo,
		SignedBy:  signer.Address(),
		Things:    make([]OwnershipThing, 0, len(addresses)),
	}
	for index, address := range addresses {
		var thing OwnershipThing
		switch {
		case address.Is4():
			thing.Type = ownershipThingIPv4
			value := address.As4()
			copy(thing.Value[:], value[:])
		case address.Is6():
			thing.Type = ownershipThingIPv6
			thing.Value = address.As16()
		default:
			return CertificateOfOwnership{}, fmt.Errorf("ownership address %d is invalid", index)
		}
		certificate.Things = append(certificate.Things, thing)
	}
	signature, err := signer.Sign(certificate.signingPayload())
	if err != nil {
		return CertificateOfOwnership{}, fmt.Errorf("sign ownership certificate: %w", err)
	}
	certificate.Signature = signature
	return certificate, nil
}

func (certificate CertificateOfOwnership) Verify(signer identity.Identity) error {
	if err := certificate.validate(); err != nil {
		return err
	}
	if certificate.SignedBy != mustControllerID(certificate.NetworkID) {
		return errors.New("ownership certificate was not signed by the network controller")
	}
	if signer.Address() != certificate.SignedBy {
		return errors.New("provided signer identity does not match ownership signer")
	}
	if !signer.Verify(certificate.signingPayload(), certificate.Signature) {
		return errors.New("invalid ownership certificate signature")
	}
	return nil
}

func (certificate CertificateOfOwnership) Owns(address netip.Addr) bool {
	for _, thing := range certificate.Things {
		if address.Is4() && thing.Type == ownershipThingIPv4 {
			value := address.As4()
			if bytes.Equal(thing.Value[:4], value[:]) {
				return true
			}
		}
		if address.Is6() && thing.Type == ownershipThingIPv6 {
			value := address.As16()
			if bytes.Equal(thing.Value[:], value[:]) {
				return true
			}
		}
	}
	return false
}

func (certificate CertificateOfOwnership) MarshalBinary() ([]byte, error) {
	if err := certificate.validate(); err != nil {
		return nil, err
	}
	var result bytes.Buffer
	certificate.appendCore(&result)
	result.WriteByte(ownershipCrypto)
	_ = binary.Write(&result, binary.BigEndian, uint16(identity.SignatureLength))
	result.Write(certificate.Signature[:])
	_ = binary.Write(&result, binary.BigEndian, uint16(0))
	return result.Bytes(), nil
}

func ParseCertificateOfOwnership(serialized []byte) (CertificateOfOwnership, error) {
	const fixedPrefix = 8 + 8 + 8 + 4 + 2
	if len(serialized) < fixedPrefix+5+5+1+2+identity.SignatureLength+2 {
		return CertificateOfOwnership{}, errors.New("ownership certificate is truncated")
	}
	offset := 0
	networkID, err := domain.ParseNetworkID(hex.EncodeToString(serialized[:8]))
	if err != nil {
		return CertificateOfOwnership{}, err
	}
	certificate := CertificateOfOwnership{
		NetworkID: networkID,
		Timestamp: binary.BigEndian.Uint64(serialized[8:16]),
		Flags:     binary.BigEndian.Uint64(serialized[16:24]),
		ID:        binary.BigEndian.Uint32(serialized[24:28]),
	}
	count := int(binary.BigEndian.Uint16(serialized[28:30]))
	if count == 0 || count > maxOwnershipThings {
		return CertificateOfOwnership{}, fmt.Errorf("invalid ownership thing count %d", count)
	}
	offset = fixedPrefix
	required := fixedPrefix + count*17 + 5 + 5 + 1 + 2 + identity.SignatureLength + 2
	if len(serialized) < required {
		return CertificateOfOwnership{}, errors.New("ownership certificate things are truncated")
	}
	certificate.Things = make([]OwnershipThing, count)
	for index := range certificate.Things {
		certificate.Things[index].Type = serialized[offset]
		copy(certificate.Things[index].Value[:], serialized[offset+1:offset+17])
		offset += 17
	}
	certificate.IssuedTo, err = domain.ParseNodeID(hex.EncodeToString(serialized[offset : offset+5]))
	if err != nil {
		return CertificateOfOwnership{}, err
	}
	offset += 5
	certificate.SignedBy, err = domain.ParseNodeID(hex.EncodeToString(serialized[offset : offset+5]))
	if err != nil {
		return CertificateOfOwnership{}, err
	}
	offset += 5
	if serialized[offset] != ownershipCrypto || binary.BigEndian.Uint16(serialized[offset+1:offset+3]) != identity.SignatureLength {
		return CertificateOfOwnership{}, errors.New("unsupported ownership signature")
	}
	offset += 3
	copy(certificate.Signature[:], serialized[offset:offset+identity.SignatureLength])
	offset += identity.SignatureLength
	extraLength := int(binary.BigEndian.Uint16(serialized[offset : offset+2]))
	offset += 2
	if offset+extraLength != len(serialized) {
		return CertificateOfOwnership{}, errors.New("invalid ownership additional-fields length")
	}
	if extraLength != 0 {
		return CertificateOfOwnership{}, errors.New("ownership additional fields are not supported")
	}
	if err := certificate.validate(); err != nil {
		return CertificateOfOwnership{}, err
	}
	return certificate, nil
}

func (certificate CertificateOfOwnership) signingPayload() []byte {
	var result bytes.Buffer
	_ = binary.Write(&result, binary.BigEndian, ownershipSentinel)
	certificate.appendCore(&result)
	_ = binary.Write(&result, binary.BigEndian, uint16(0))
	_ = binary.Write(&result, binary.BigEndian, ownershipSentinel)
	return result.Bytes()
}

func (certificate CertificateOfOwnership) appendCore(result *bytes.Buffer) {
	networkID, _ := hex.DecodeString(string(certificate.NetworkID))
	result.Write(networkID)
	_ = binary.Write(result, binary.BigEndian, certificate.Timestamp)
	_ = binary.Write(result, binary.BigEndian, certificate.Flags)
	_ = binary.Write(result, binary.BigEndian, certificate.ID)
	_ = binary.Write(result, binary.BigEndian, uint16(len(certificate.Things)))
	for _, thing := range certificate.Things {
		result.WriteByte(thing.Type)
		result.Write(thing.Value[:])
	}
	issuedTo, _ := hex.DecodeString(string(certificate.IssuedTo))
	result.Write(issuedTo)
	signedBy, _ := hex.DecodeString(string(certificate.SignedBy))
	result.Write(signedBy)
}

func (certificate CertificateOfOwnership) validate() error {
	if err := certificate.NetworkID.Validate(); err != nil {
		return err
	}
	if err := certificate.IssuedTo.Validate(); err != nil {
		return err
	}
	if err := certificate.SignedBy.Validate(); err != nil {
		return err
	}
	if len(certificate.Things) == 0 || len(certificate.Things) > maxOwnershipThings {
		return fmt.Errorf("ownership certificate must contain between 1 and %d things", maxOwnershipThings)
	}
	for index, thing := range certificate.Things {
		if thing.Type != ownershipThingIPv4 && thing.Type != ownershipThingIPv6 {
			return fmt.Errorf("ownership thing %d has unsupported type %d", index, thing.Type)
		}
	}
	return nil
}
