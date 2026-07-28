package packet

import (
	"errors"
	"fmt"
)

// Decompress expands ZeroTier's raw LZ4 block payload after packet
// authentication. The verb byte itself is not part of the compressed block.
func Decompress(decoded Decoded, maximum int) (Decoded, error) {
	if !decoded.Compressed {
		return decoded, nil
	}
	if maximum <= 0 || maximum > MaxPacketLength-HeaderLength {
		return Decoded{}, errors.New("invalid decompression limit")
	}
	output := make([]byte, 0, min(maximum, len(decoded.Payload)*2))
	input := decoded.Payload
	for cursor := 0; cursor < len(input); {
		token := input[cursor]
		cursor++
		literalLength, next, err := lz4Length(input, cursor, int(token>>4))
		if err != nil {
			return Decoded{}, err
		}
		cursor = next
		if literalLength > len(input)-cursor || literalLength > maximum-len(output) {
			return Decoded{}, errors.New("LZ4 literal exceeds input or output limit")
		}
		output = append(output, input[cursor:cursor+literalLength]...)
		cursor += literalLength
		if cursor == len(input) {
			break
		}
		if len(input)-cursor < 2 {
			return Decoded{}, errors.New("LZ4 match offset is truncated")
		}
		offset := int(input[cursor]) | int(input[cursor+1])<<8
		cursor += 2
		if offset == 0 || offset > len(output) {
			return Decoded{}, errors.New("LZ4 match offset is invalid")
		}
		matchLength, next, err := lz4Length(input, cursor, int(token&0x0f))
		if err != nil {
			return Decoded{}, err
		}
		cursor = next
		matchLength += 4
		if matchLength > maximum-len(output) {
			return Decoded{}, errors.New("LZ4 match exceeds output limit")
		}
		for index := 0; index < matchLength; index++ {
			output = append(output, output[len(output)-offset])
		}
	}
	if len(output) == 0 {
		return Decoded{}, errors.New("LZ4 block expands to an empty payload")
	}
	decoded.Payload = output
	decoded.Compressed = false
	return decoded, nil
}

func lz4Length(input []byte, cursor, base int) (int, int, error) {
	if base != 15 {
		return base, cursor, nil
	}
	length := base
	for {
		if cursor >= len(input) {
			return 0, 0, errors.New("LZ4 extended length is truncated")
		}
		value := int(input[cursor])
		cursor++
		if length > MaxPacketLength-value {
			return 0, 0, fmt.Errorf("LZ4 length exceeds %d bytes", MaxPacketLength)
		}
		length += value
		if value != 255 {
			return length, cursor, nil
		}
	}
}
