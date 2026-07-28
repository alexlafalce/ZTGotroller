package networkconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

const MaxMetadataLength = 1023

type Metadata map[string][]byte

type Request struct {
	NetworkID        domain.NetworkID
	Metadata         Metadata
	HasCurrentState  bool
	CurrentRevision  uint64
	CurrentTimestamp uint64
	Extensions       []byte
}

func ParseRequest(decoded packet.Decoded) (Request, error) {
	if decoded.Verb != packet.VerbNetworkConfigRequest {
		return Request{}, fmt.Errorf("unexpected verb %d", decoded.Verb)
	}
	if decoded.Compressed {
		return Request{}, errors.New("network config request must be decompressed before parsing")
	}
	payload := decoded.Payload
	if len(payload) < 10 {
		return Request{}, errors.New("network config request is shorter than network ID and dictionary length")
	}
	networkID, err := domain.ParseNetworkID(hex.EncodeToString(payload[:8]))
	if err != nil {
		return Request{}, err
	}
	metadataLength := int(binary.BigEndian.Uint16(payload[8:10]))
	if metadataLength > MaxMetadataLength {
		return Request{}, fmt.Errorf("metadata length %d exceeds %d", metadataLength, MaxMetadataLength)
	}
	if len(payload) < 10+metadataLength {
		return Request{}, errors.New("declared metadata length exceeds payload")
	}
	metadata, err := ParseMetadata(payload[10 : 10+metadataLength])
	if err != nil {
		return Request{}, err
	}
	request := Request{NetworkID: networkID, Metadata: metadata}
	remainder := payload[10+metadataLength:]
	if len(remainder) == 0 {
		return request, nil
	}
	if len(remainder) < 16 {
		return Request{}, errors.New("current config state trailer is truncated")
	}
	request.HasCurrentState = true
	request.CurrentRevision = binary.BigEndian.Uint64(remainder[:8])
	request.CurrentTimestamp = binary.BigEndian.Uint64(remainder[8:16])
	request.Extensions = append([]byte(nil), remainder[16:]...)
	return request, nil
}

func ParseMetadata(serialized []byte) (Metadata, error) {
	if len(serialized) > MaxMetadataLength {
		return nil, fmt.Errorf("metadata length %d exceeds %d", len(serialized), MaxMetadataLength)
	}
	if bytes.IndexByte(serialized, 0) >= 0 {
		return nil, errors.New("metadata contains an unescaped null byte")
	}
	metadata := make(Metadata)
	for lineNumber, line := range splitLines(serialized) {
		if len(line) == 0 {
			continue
		}
		separator := bytes.IndexByte(line, '=')
		if separator <= 0 {
			return nil, fmt.Errorf("metadata line %d has no valid key separator", lineNumber+1)
		}
		keyBytes := line[:separator]
		for _, character := range keyBytes {
			if character < 0x21 || character > 0x7e || character == '\\' {
				return nil, fmt.Errorf("metadata line %d contains an invalid key", lineNumber+1)
			}
		}
		key := string(keyBytes)
		value, err := unescapeValue(line[separator+1:])
		if err != nil {
			return nil, fmt.Errorf("metadata key %q: %w", key, err)
		}
		// ZeroTier Dictionary::get returns the first duplicate.
		if _, exists := metadata[key]; !exists {
			metadata[key] = value
		}
	}
	return metadata, nil
}

func (metadata Metadata) HexUint(key string) (uint64, bool) {
	value, exists := metadata[key]
	if !exists || len(value) == 0 {
		return 0, false
	}
	var result uint64
	for _, character := range value {
		var nibble byte
		switch {
		case character >= '0' && character <= '9':
			nibble = character - '0'
		case character >= 'a' && character <= 'f':
			nibble = character - 'a' + 10
		case character >= 'A' && character <= 'F':
			nibble = character - 'A' + 10
		default:
			return 0, false
		}
		if result > (^uint64(0) >> 4) {
			return 0, false
		}
		result = result<<4 | uint64(nibble)
	}
	return result, true
}

func splitLines(value []byte) [][]byte {
	return bytes.FieldsFunc(value, func(character rune) bool {
		return character == '\r' || character == '\n'
	})
}

func unescapeValue(value []byte) ([]byte, error) {
	result := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result = append(result, value[index])
			continue
		}
		index++
		if index == len(value) {
			return nil, errors.New("value ends with an incomplete escape")
		}
		switch value[index] {
		case '0':
			result = append(result, 0)
		case 'r':
			result = append(result, '\r')
		case 'n':
			result = append(result, '\n')
		case 'e':
			result = append(result, '=')
		case '\\':
			result = append(result, '\\')
		default:
			result = append(result, value[index])
		}
	}
	return result, nil
}
