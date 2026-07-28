package networkconfig

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

const (
	ruleFlagOr  = byte(0x40)
	ruleFlagNot = byte(0x80)
)

var ruleTypes = map[string]byte{
	"ACTION_DROP": 0, "ACTION_ACCEPT": 1, "ACTION_TEE": 2, "ACTION_WATCH": 3,
	"ACTION_REDIRECT": 4, "ACTION_BREAK": 5, "ACTION_PRIORITY": 6,
	"MATCH_SOURCE_ZEROTIER_ADDRESS": 24, "MATCH_DEST_ZEROTIER_ADDRESS": 25,
	"MATCH_VLAN_ID": 26, "MATCH_VLAN_PCP": 27, "MATCH_VLAN_DEI": 28,
	"MATCH_MAC_SOURCE": 29, "MATCH_MAC_DEST": 30,
	"MATCH_IPV4_SOURCE": 31, "MATCH_IPV4_DEST": 32,
	"MATCH_IPV6_SOURCE": 33, "MATCH_IPV6_DEST": 34,
	"MATCH_IP_TOS": 35, "MATCH_IP_PROTOCOL": 36, "MATCH_ETHERTYPE": 37,
	"MATCH_ICMP": 38, "MATCH_IP_SOURCE_PORT_RANGE": 39,
	"MATCH_IP_DEST_PORT_RANGE": 40, "MATCH_CHARACTERISTICS": 41,
	"MATCH_FRAME_SIZE_RANGE": 42, "MATCH_RANDOM": 43,
	"MATCH_TAGS_DIFFERENCE": 44, "MATCH_TAGS_BITWISE_AND": 45,
	"MATCH_TAGS_BITWISE_OR": 46, "MATCH_TAGS_BITWISE_XOR": 47,
	"MATCH_TAGS_EQUAL": 48, "MATCH_TAG_SENDER": 49, "MATCH_TAG_RECEIVER": 50,
	"MATCH_INTEGER_RANGE": 51, "INTEGER_RANGE": 51,
}

// SerializeRules emits the extensible type/length/value sequence consumed by
// NetworkConfig. Numeric values use network byte order, matching Buffer::append.
func SerializeRules(rules []domain.Rule) ([]byte, error) {
	var result bytes.Buffer
	for index, rule := range rules {
		ruleType, ok := ruleTypes[rule.Type]
		if !ok {
			return nil, fmt.Errorf("rule %d has unsupported type %q", index, rule.Type)
		}
		field, err := serializeRuleField(ruleType, rule.Parameters)
		if err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", index, rule.Type, err)
		}
		if len(field) > 255 {
			return nil, fmt.Errorf("rule %d field exceeds 255 bytes", index)
		}
		encodedType := ruleType
		if rule.Negate {
			encodedType |= ruleFlagNot
		}
		if rule.Or {
			encodedType |= ruleFlagOr
		}
		result.WriteByte(encodedType)
		result.WriteByte(byte(len(field)))
		result.Write(field)
	}
	return result.Bytes(), nil
}

func serializeRuleField(ruleType byte, parameters map[string]json.RawMessage) ([]byte, error) {
	switch ruleType {
	case 0, 1, 5, 6:
		return noParameters(parameters)
	case 2, 3, 4:
		address, err := hexValue(parameters, "address", 40)
		if err != nil {
			return nil, err
		}
		flags, err := uintValue(parameters, "flags", 32)
		if err != nil {
			return nil, err
		}
		length := uint64(0)
		if ruleType != 4 {
			length, err = uintValue(parameters, "length", 16)
			if err != nil {
				return nil, err
			}
		}
		field := make([]byte, 14)
		binary.BigEndian.PutUint64(field, address)
		binary.BigEndian.PutUint32(field[8:], uint32(flags))
		binary.BigEndian.PutUint16(field[12:], uint16(length))
		return field, nil
	case 24, 25:
		value, err := hexValue(parameters, "zt", 40)
		if err != nil {
			return nil, err
		}
		field := make([]byte, 5)
		for index := 4; index >= 0; index-- {
			field[index] = byte(value)
			value >>= 8
		}
		return field, nil
	case 26:
		return uintField(parameters, "vlanId", 16)
	case 27:
		return uintField(parameters, "vlanPcp", 8)
	case 28:
		return uintField(parameters, "vlanDei", 8)
	case 29, 30:
		value, err := stringValue(parameters, "mac")
		if err != nil {
			return nil, err
		}
		mac, err := net.ParseMAC(value)
		if err != nil || len(mac) != 6 {
			return nil, errors.New("mac must be a 48-bit address")
		}
		return []byte(mac), nil
	case 31, 32:
		return prefixField(parameters, 4)
	case 33, 34:
		return prefixField(parameters, 16)
	case 35:
		mask, err := uintValue(parameters, "mask", 8)
		if err != nil {
			return nil, err
		}
		start, err := uintValue(parameters, "start", 8)
		if err != nil {
			return nil, err
		}
		end, err := uintValue(parameters, "end", 8)
		if err != nil {
			return nil, err
		}
		return []byte{byte(mask), byte(start), byte(end)}, nil
	case 36:
		return uintField(parameters, "ipProtocol", 8)
	case 37:
		return uintField(parameters, "etherType", 16)
	case 38:
		icmpType, err := uintValue(parameters, "icmpType", 8)
		if err != nil {
			return nil, err
		}
		code := uint64(0)
		flags := byte(0)
		if raw, exists := parameters["icmpCode"]; exists && string(raw) != "null" {
			code, err = uintValue(parameters, "icmpCode", 8)
			if err != nil {
				return nil, err
			}
			flags = 1
		}
		return []byte{byte(icmpType), byte(code), flags}, nil
	case 39, 40, 42:
		return range16Field(parameters)
	case 41:
		value, err := flexibleHexValue(parameters, "mask", 64)
		if err != nil {
			return nil, err
		}
		field := make([]byte, 8)
		binary.BigEndian.PutUint64(field, value)
		return field, nil
	case 43:
		return uintField(parameters, "probability", 32)
	case 44, 45, 46, 47, 48, 49, 50:
		id, err := uintValue(parameters, "id", 32)
		if err != nil {
			return nil, err
		}
		value, err := uintValue(parameters, "value", 32)
		if err != nil {
			return nil, err
		}
		field := make([]byte, 8)
		binary.BigEndian.PutUint32(field, uint32(id))
		binary.BigEndian.PutUint32(field[4:], uint32(value))
		return field, nil
	case 51:
		start, err := flexibleHexValue(parameters, "start", 64)
		if err != nil {
			return nil, err
		}
		end, err := flexibleHexValue(parameters, "end", 64)
		if err != nil {
			return nil, err
		}
		if end < start || end-start > uint64(^uint32(0)) {
			return nil, errors.New("integer range end is invalid")
		}
		index, err := uintValue(parameters, "idx", 16)
		if err != nil {
			return nil, err
		}
		bits, err := uintValue(parameters, "bits", 8)
		if err != nil || bits < 1 || bits > 64 {
			return nil, errors.New("bits must be between 1 and 64")
		}
		little, err := boolValue(parameters, "little")
		if err != nil {
			return nil, err
		}
		format := byte(bits - 1)
		if little {
			format |= 0x80
		}
		field := make([]byte, 19)
		binary.BigEndian.PutUint64(field, start)
		binary.BigEndian.PutUint64(field[8:], end)
		binary.BigEndian.PutUint16(field[16:], uint16(index))
		field[18] = format
		return field, nil
	default:
		return nil, fmt.Errorf("rule type %d is unsupported", ruleType)
	}
}

func noParameters(parameters map[string]json.RawMessage) ([]byte, error) {
	if len(parameters) != 0 {
		return nil, errors.New("action cannot have parameters")
	}
	return nil, nil
}

func prefixField(parameters map[string]json.RawMessage, length int) ([]byte, error) {
	value, err := stringValue(parameters, "ip")
	if err != nil {
		return nil, err
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || (length == 4) != prefix.Addr().Is4() {
		return nil, fmt.Errorf("ip must be a valid IPv%d prefix", length*8)
	}
	field := make([]byte, length+1)
	if length == 4 {
		address := prefix.Addr().As4()
		copy(field, address[:])
	} else {
		address := prefix.Addr().As16()
		copy(field, address[:])
	}
	field[length] = byte(prefix.Bits())
	return field, nil
}

func range16Field(parameters map[string]json.RawMessage) ([]byte, error) {
	start, err := uintValue(parameters, "start", 16)
	if err != nil {
		return nil, err
	}
	end, err := uintValue(parameters, "end", 16)
	if err != nil {
		return nil, err
	}
	if start > end {
		return nil, errors.New("range start exceeds end")
	}
	field := make([]byte, 4)
	binary.BigEndian.PutUint16(field, uint16(start))
	binary.BigEndian.PutUint16(field[2:], uint16(end))
	return field, nil
}

func uintField(parameters map[string]json.RawMessage, key string, bits int) ([]byte, error) {
	value, err := uintValue(parameters, key, bits)
	if err != nil {
		return nil, err
	}
	field := make([]byte, bits/8)
	switch bits {
	case 8:
		field[0] = byte(value)
	case 16:
		binary.BigEndian.PutUint16(field, uint16(value))
	case 32:
		binary.BigEndian.PutUint32(field, uint32(value))
	}
	return field, nil
}

func uintValue(parameters map[string]json.RawMessage, key string, bits int) (uint64, error) {
	raw, ok := parameters[key]
	if !ok {
		return 0, fmt.Errorf("%s is required", key)
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, fmt.Errorf("%s must be an unsigned integer", key)
	}
	if bits < 64 && value >= uint64(1)<<bits {
		return 0, fmt.Errorf("%s exceeds %d bits", key, bits)
	}
	return value, nil
}

func stringValue(parameters map[string]json.RawMessage, key string) (string, error) {
	raw, ok := parameters[key]
	if !ok {
		return "", fmt.Errorf("%s is required", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return value, nil
}

func boolValue(parameters map[string]json.RawMessage, key string) (bool, error) {
	raw, ok := parameters[key]
	if !ok {
		return false, fmt.Errorf("%s is required", key)
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return value, nil
}

func hexValue(parameters map[string]json.RawMessage, key string, bits int) (uint64, error) {
	value, err := stringValue(parameters, key)
	if err != nil {
		return 0, err
	}
	value = strings.TrimPrefix(value, "0x")
	if _, err := hex.DecodeString(leftPadEven(value)); err != nil {
		return 0, fmt.Errorf("%s must be hexadecimal", key)
	}
	parsed, err := strconv.ParseUint(value, 16, bits)
	if err != nil {
		return 0, fmt.Errorf("%s exceeds %d bits", key, bits)
	}
	return parsed, nil
}

func flexibleHexValue(parameters map[string]json.RawMessage, key string, bits int) (uint64, error) {
	raw, ok := parameters[key]
	if !ok {
		return 0, fmt.Errorf("%s is required", key)
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return hexValue(map[string]json.RawMessage{key: raw}, key, bits)
	}
	return uintValue(parameters, key, bits)
}

func leftPadEven(value string) string {
	if len(value)%2 != 0 {
		return "0" + value
	}
	return value
}
