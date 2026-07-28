package networkconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const (
	policySigningSentinel = uint64(0x7f7f7f7f7f7f7f7f)
	maxIssuedCapabilities = 128
	maxIssuedTags         = 128
	maxCapabilityRules    = 64
)

func issuePolicyCredentials(
	network domain.Network,
	member domain.Member,
	timestamp uint64,
	signer identity.Identity,
) ([]byte, []byte, error) {
	capabilityIDs := make(map[uint32]struct{}, len(member.Capabilities))
	for _, id := range member.Capabilities {
		capabilityIDs[id] = struct{}{}
	}
	for _, capability := range network.Capabilities {
		if capability.Default {
			capabilityIDs[capability.ID] = struct{}{}
		}
	}
	capabilityDefinitions := make(map[uint32]domain.Capability, len(network.Capabilities))
	for _, capability := range network.Capabilities {
		capabilityDefinitions[capability.ID] = capability
	}
	orderedCapabilities := make([]uint32, 0, len(capabilityIDs))
	for id := range capabilityIDs {
		orderedCapabilities = append(orderedCapabilities, id)
	}
	sort.Slice(orderedCapabilities, func(i, j int) bool {
		return orderedCapabilities[i] < orderedCapabilities[j]
	})
	if len(orderedCapabilities) > maxIssuedCapabilities {
		orderedCapabilities = orderedCapabilities[:maxIssuedCapabilities]
	}
	var capabilities bytes.Buffer
	for _, id := range orderedCapabilities {
		definition, exists := capabilityDefinitions[id]
		if !exists {
			continue
		}
		serialized, err := issueCapability(
			network.ID, timestamp, member.NodeID, definition, signer,
		)
		if err != nil {
			return nil, nil, err
		}
		capabilities.Write(serialized)
	}

	tagValues := make(map[uint32]uint32, len(network.Tags)+len(member.Tags))
	for _, definition := range network.Tags {
		if definition.Default != nil {
			tagValues[definition.ID] = *definition.Default
		}
	}
	for _, tag := range member.Tags {
		tagValues[tag.ID] = tag.Value
	}
	orderedTags := make([]uint32, 0, len(tagValues))
	for id := range tagValues {
		orderedTags = append(orderedTags, id)
	}
	sort.Slice(orderedTags, func(i, j int) bool { return orderedTags[i] < orderedTags[j] })
	if len(orderedTags) > maxIssuedTags {
		orderedTags = orderedTags[:maxIssuedTags]
	}
	var tags bytes.Buffer
	for _, id := range orderedTags {
		serialized, err := issueTag(
			network.ID, timestamp, member.NodeID, id, tagValues[id], signer,
		)
		if err != nil {
			return nil, nil, err
		}
		tags.Write(serialized)
	}
	return capabilities.Bytes(), tags.Bytes(), nil
}

func issueTag(
	networkID domain.NetworkID,
	timestamp uint64,
	issuedTo domain.NodeID,
	id uint32,
	value uint32,
	signer identity.Identity,
) ([]byte, error) {
	base, err := policyCredentialBase(networkID, timestamp, id)
	if err != nil {
		return nil, err
	}
	issuedBytes, err := nodeIDBytes(issuedTo)
	if err != nil {
		return nil, err
	}
	signerBytes, err := nodeIDBytes(signer.Address())
	if err != nil {
		return nil, err
	}
	base = append(base, uint32Bytes(value)...)
	base = append(base, issuedBytes...)
	base = append(base, signerBytes...)
	signingPayload := withPolicySentinels(append(append([]byte(nil), base...), 0, 0))
	signature, err := signer.Sign(signingPayload)
	if err != nil {
		return nil, fmt.Errorf("sign tag %d: %w", id, err)
	}
	result := append([]byte(nil), base...)
	result = append(result, 1)
	result = append(result, uint16Bytes(identity.SignatureLength)...)
	result = append(result, signature[:]...)
	result = append(result, 0, 0)
	return result, nil
}

func issueCapability(
	networkID domain.NetworkID,
	timestamp uint64,
	issuedTo domain.NodeID,
	definition domain.Capability,
	signer identity.Identity,
) ([]byte, error) {
	if len(definition.Rules) > maxCapabilityRules {
		return nil, fmt.Errorf("capability %d exceeds %d rules", definition.ID, maxCapabilityRules)
	}
	rules, err := SerializeRules(definition.Rules)
	if err != nil {
		return nil, fmt.Errorf("capability %d: %w", definition.ID, err)
	}
	base, err := policyCredentialBase(networkID, timestamp, definition.ID)
	if err != nil {
		return nil, err
	}
	base = append(base, uint16Bytes(len(definition.Rules))...)
	base = append(base, rules...)
	base = append(base, 1) // non-transferable custody chain
	signingPayload := withPolicySentinels(append(append([]byte(nil), base...), 0, 0))
	signature, err := signer.Sign(signingPayload)
	if err != nil {
		return nil, fmt.Errorf("sign capability %d: %w", definition.ID, err)
	}
	to, err := nodeIDBytes(issuedTo)
	if err != nil {
		return nil, err
	}
	from, err := nodeIDBytes(signer.Address())
	if err != nil {
		return nil, err
	}
	result := append([]byte(nil), base...)
	result = append(result, to...)
	result = append(result, from...)
	result = append(result, 1)
	result = append(result, uint16Bytes(identity.SignatureLength)...)
	result = append(result, signature[:]...)
	result = append(result, make([]byte, 5)...) // zero address terminates custody
	result = append(result, 0, 0)
	return result, nil
}

func policyCredentialBase(
	networkID domain.NetworkID,
	timestamp uint64,
	id uint32,
) ([]byte, error) {
	networkValue, err := parseHexUint(string(networkID))
	if err != nil {
		return nil, err
	}
	result := make([]byte, 20)
	binary.BigEndian.PutUint64(result, networkValue)
	binary.BigEndian.PutUint64(result[8:], timestamp)
	binary.BigEndian.PutUint32(result[16:], id)
	return result, nil
}

func nodeIDBytes(value domain.NodeID) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(string(value))
	if err != nil || len(decoded) != 5 {
		return nil, errors.New("node ID is not five bytes")
	}
	return decoded, nil
}

func withPolicySentinels(payload []byte) []byte {
	result := make([]byte, 8, len(payload)+16)
	binary.BigEndian.PutUint64(result, policySigningSentinel)
	result = append(result, payload...)
	result = append(result, make([]byte, 8)...)
	binary.BigEndian.PutUint64(result[len(result)-8:], policySigningSentinel)
	return result
}

func uint16Bytes(value int) []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, uint16(value))
	return result
}

func uint32Bytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}
