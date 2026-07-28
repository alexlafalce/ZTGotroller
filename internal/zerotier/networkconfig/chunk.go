package networkconfig

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

const (
	ChunkSignatureTypeEd25519 = 1
	DefaultMaxChunkData       = 44_000
	MaxConfigDictionary       = 1 << 20
	chunkFixedOverhead        = 8 + 2 + 1 + 8 + 4 + 4 + 1 + 2 + identity.SignatureLength
)

type ErrorCode byte

const (
	ErrorObjectNotFound ErrorCode = 0x03
	ErrorAccessDenied   ErrorCode = 0x07
)

type SignedChunk struct {
	NetworkID     domain.NetworkID
	Data          []byte
	Flags         byte
	UpdateID      uint64
	TotalLength   uint32
	Index         uint32
	Signature     identity.Signature
	SignedPayload []byte
}

func BuildSignedChunks(
	networkID domain.NetworkID,
	dictionary []byte,
	updateID uint64,
	maxChunkData int,
	signer identity.Identity,
) ([][]byte, error) {
	if err := networkID.Validate(); err != nil {
		return nil, err
	}
	if updateID == 0 {
		return nil, errors.New("config update ID cannot be zero")
	}
	if len(dictionary) == 0 || len(dictionary) >= MaxConfigDictionary {
		return nil, fmt.Errorf("config dictionary length must be between 1 and %d", MaxConfigDictionary-1)
	}
	if maxChunkData <= 0 {
		maxChunkData = DefaultMaxChunkData
	}
	if maxChunkData > 0xffff {
		return nil, errors.New("chunk data limit exceeds 16-bit framing")
	}
	networkBytes, _ := hex.DecodeString(string(networkID))
	chunks := make([][]byte, 0, (len(dictionary)+maxChunkData-1)/maxChunkData)
	for index := 0; index < len(dictionary); index += maxChunkData {
		end := index + maxChunkData
		if end > len(dictionary) {
			end = len(dictionary)
		}
		data := dictionary[index:end]
		signedLength := 8 + 2 + len(data) + 1 + 8 + 4 + 4
		payload := make([]byte, signedLength+1+2+identity.SignatureLength)
		copy(payload[:8], networkBytes)
		binary.BigEndian.PutUint16(payload[8:10], uint16(len(data)))
		copy(payload[10:], data)
		offset := 10 + len(data)
		payload[offset] = 0
		binary.BigEndian.PutUint64(payload[offset+1:offset+9], updateID)
		binary.BigEndian.PutUint32(payload[offset+9:offset+13], uint32(len(dictionary)))
		binary.BigEndian.PutUint32(payload[offset+13:offset+17], uint32(index))
		signature, err := signer.Sign(payload[:signedLength])
		if err != nil {
			return nil, err
		}
		payload[signedLength] = ChunkSignatureTypeEd25519
		binary.BigEndian.PutUint16(
			payload[signedLength+1:signedLength+3],
			identity.SignatureLength,
		)
		copy(payload[signedLength+3:], signature[:])
		chunks = append(chunks, payload)
	}
	return chunks, nil
}

func ParseSignedChunk(payload []byte, signer identity.Identity) (SignedChunk, error) {
	if len(payload) < chunkFixedOverhead {
		return SignedChunk{}, errors.New("signed config chunk is too short")
	}
	networkID, err := domain.ParseNetworkID(hex.EncodeToString(payload[:8]))
	if err != nil {
		return SignedChunk{}, err
	}
	dataLength := int(binary.BigEndian.Uint16(payload[8:10]))
	signedLength := 8 + 2 + dataLength + 1 + 8 + 4 + 4
	totalLength := signedLength + 1 + 2 + identity.SignatureLength
	if len(payload) != totalLength {
		return SignedChunk{}, errors.New("signed config chunk length does not match framing")
	}
	offset := 10 + dataLength
	flags := payload[offset]
	updateID := binary.BigEndian.Uint64(payload[offset+1 : offset+9])
	configLength := binary.BigEndian.Uint32(payload[offset+9 : offset+13])
	index := binary.BigEndian.Uint32(payload[offset+13 : offset+17])
	if updateID == 0 {
		return SignedChunk{}, errors.New("config update ID cannot be zero")
	}
	if configLength == 0 || configLength >= MaxConfigDictionary ||
		uint64(index)+uint64(dataLength) > uint64(configLength) {
		return SignedChunk{}, errors.New("config chunk range is invalid")
	}
	if payload[signedLength] != ChunkSignatureTypeEd25519 ||
		binary.BigEndian.Uint16(payload[signedLength+1:signedLength+3]) != identity.SignatureLength {
		return SignedChunk{}, errors.New("unsupported config chunk signature")
	}
	var signature identity.Signature
	copy(signature[:], payload[signedLength+3:])
	if !signer.Verify(payload[:signedLength], signature) {
		return SignedChunk{}, errors.New("invalid config chunk signature")
	}
	return SignedChunk{
		NetworkID:     networkID,
		Data:          append([]byte(nil), payload[10:10+dataLength]...),
		Flags:         flags,
		UpdateID:      updateID,
		TotalLength:   configLength,
		Index:         index,
		Signature:     signature,
		SignedPayload: append([]byte(nil), payload[:signedLength]...),
	}, nil
}

func WrapOK(requestPacketID uint64, signedChunk []byte) []byte {
	payload := make([]byte, 1+8+len(signedChunk))
	payload[0] = byte(packet.VerbNetworkConfigRequest)
	binary.BigEndian.PutUint64(payload[1:9], requestPacketID)
	copy(payload[9:], signedChunk)
	return payload
}

func WrapError(requestPacketID uint64, networkID domain.NetworkID, code ErrorCode) ([]byte, error) {
	if err := networkID.Validate(); err != nil {
		return nil, err
	}
	if code != ErrorObjectNotFound && code != ErrorAccessDenied {
		return nil, fmt.Errorf("unsupported network config error code %d", code)
	}
	networkBytes, _ := hex.DecodeString(string(networkID))
	payload := make([]byte, 1+8+1+8)
	payload[0] = byte(packet.VerbNetworkConfigRequest)
	binary.BigEndian.PutUint64(payload[1:9], requestPacketID)
	payload[9] = byte(code)
	copy(payload[10:], networkBytes)
	return payload, nil
}
