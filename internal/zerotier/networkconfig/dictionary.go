package networkconfig

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

const MaxDictionaryLength = 65535

// DictionaryBuilder serializes the escaped key/value format consumed by
// ZeroTier's Dictionary class. Entries retain insertion order.
type DictionaryBuilder struct {
	data []byte
}

func (builder *DictionaryBuilder) Add(key string, value []byte) error {
	if err := validateDictionaryKey(key); err != nil {
		return err
	}
	added := len(key) + 2
	for _, character := range value {
		switch character {
		case 0, '\r', '\n', '\\', '=':
			added += 2
		default:
			added++
		}
	}
	if len(builder.data)+added > MaxDictionaryLength {
		return fmt.Errorf("dictionary exceeds %d bytes", MaxDictionaryLength)
	}
	builder.data = append(builder.data, key...)
	builder.data = append(builder.data, '=')
	for _, character := range value {
		switch character {
		case 0:
			builder.data = append(builder.data, '\\', '0')
		case '\r':
			builder.data = append(builder.data, '\\', 'r')
		case '\n':
			builder.data = append(builder.data, '\\', 'n')
		case '\\':
			builder.data = append(builder.data, '\\', '\\')
		case '=':
			builder.data = append(builder.data, '\\', 'e')
		default:
			builder.data = append(builder.data, character)
		}
	}
	builder.data = append(builder.data, '\n')
	return nil
}

func (builder *DictionaryBuilder) AddString(key, value string) error {
	return builder.Add(key, []byte(value))
}

func (builder *DictionaryBuilder) AddHexUint(key string, value uint64) error {
	return builder.AddString(key, strconv.FormatUint(value, 16))
}

func (builder *DictionaryBuilder) Bytes() []byte {
	return bytes.Clone(builder.data)
}

func validateDictionaryKey(key string) error {
	if key == "" {
		return errors.New("dictionary key cannot be empty")
	}
	for _, character := range []byte(key) {
		if character < 0x21 || character > 0x7e || character == '\\' || character == '=' {
			return fmt.Errorf("dictionary key %q contains an invalid character", key)
		}
	}
	return nil
}
