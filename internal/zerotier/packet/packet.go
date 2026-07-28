package packet

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

const (
	ProtocolVersionLegacy  = 12
	ProtocolVersionCurrent = 13
	MinimumProtocolVersion = 4

	HeaderLength   = 28
	FragmentLength = 16

	FlagExtendedArmor = 0x80
	FlagFragmented    = 0x40
	FlagCompressed    = 0x80
)

type Cipher uint8

const (
	CipherC25519Poly1305Clear Cipher = 0
	CipherC25519Poly1305Salsa Cipher = 1
	CipherTrustedPath         Cipher = 2
	CipherAESGMACSIV          Cipher = 3
)

type Verb uint8

const (
	VerbNOP                    Verb = 0x00
	VerbHello                  Verb = 0x01
	VerbError                  Verb = 0x02
	VerbOK                     Verb = 0x03
	VerbWhois                  Verb = 0x04
	VerbRendezvous             Verb = 0x05
	VerbFrame                  Verb = 0x06
	VerbExtendedFrame          Verb = 0x07
	VerbEcho                   Verb = 0x08
	VerbMulticastLike          Verb = 0x09
	VerbNetworkCredentials     Verb = 0x0a
	VerbNetworkConfigRequest   Verb = 0x0b
	VerbNetworkConfig          Verb = 0x0c
	VerbMulticastGather        Verb = 0x0d
	VerbMulticastFrame         Verb = 0x0e
	VerbPushDirectPaths        Verb = 0x10
	VerbACK                    Verb = 0x12
	VerbQoSMeasurement         Verb = 0x13
	VerbUserMessage            Verb = 0x14
	VerbRemoteTrace            Verb = 0x15
	VerbPathNegotiationRequest Verb = 0x16
)

type RoutingHeader struct {
	PacketID      uint64
	Destination   domain.NodeID
	Source        domain.NodeID
	Flags         byte
	Hops          uint8
	Cipher        Cipher
	Fragmented    bool
	ExtendedArmor bool
}

type Decoded struct {
	Routing       RoutingHeader
	Authenticator [8]byte
	Verb          Verb
	Compressed    bool
	Payload       []byte
}

// ParseRouting reads only fields that are available before authentication and
// decryption. It must not be used to trust the packet verb or payload.
func ParseRouting(data []byte) (RoutingHeader, error) {
	if len(data) < HeaderLength {
		return RoutingHeader{}, fmt.Errorf("packet length %d is below header length %d", len(data), HeaderLength)
	}
	destination, err := domain.ParseNodeID(hex.EncodeToString(data[8:13]))
	if err != nil {
		return RoutingHeader{}, err
	}
	source, err := domain.ParseNodeID(hex.EncodeToString(data[13:18]))
	if err != nil {
		return RoutingHeader{}, err
	}
	flags := data[18]
	return RoutingHeader{
		PacketID:      binary.BigEndian.Uint64(data[:8]),
		Destination:   destination,
		Source:        source,
		Flags:         flags,
		Hops:          flags & 0x07,
		Cipher:        Cipher((flags & 0x38) >> 3),
		Fragmented:    flags&FlagFragmented != 0,
		ExtendedArmor: flags&FlagExtendedArmor != 0,
	}, nil
}

// ParseDecoded parses a packet only after the caller has authenticated and
// removed its transport armor.
func ParseDecoded(data []byte) (Decoded, error) {
	routing, err := ParseRouting(data)
	if err != nil {
		return Decoded{}, err
	}
	var authenticator [8]byte
	copy(authenticator[:], data[19:27])
	payload := append([]byte(nil), data[HeaderLength:]...)
	return Decoded{
		Routing:       routing,
		Authenticator: authenticator,
		Verb:          Verb(data[27] & 0x1f),
		Compressed:    data[27]&FlagCompressed != 0,
		Payload:       payload,
	}, nil
}

type Fragment struct {
	PacketID       uint64
	Destination    domain.NodeID
	TotalFragments uint8
	Number         uint8
	Hops           uint8
	Payload        []byte
}

func IsFragment(data []byte) bool {
	return len(data) >= FragmentLength && data[13] == 0xff
}

func ParseFragment(data []byte) (Fragment, error) {
	if len(data) < FragmentLength {
		return Fragment{}, fmt.Errorf("fragment length %d is below minimum %d", len(data), FragmentLength)
	}
	if data[13] != 0xff {
		return Fragment{}, errors.New("fragment indicator is not 0xff")
	}
	if data[15]&0xf8 != 0 {
		return Fragment{}, errors.New("fragment hop reserved bits are set")
	}
	destination, err := domain.ParseNodeID(hex.EncodeToString(data[8:13]))
	if err != nil {
		return Fragment{}, err
	}
	return Fragment{
		PacketID:       binary.BigEndian.Uint64(data[:8]),
		Destination:    destination,
		TotalFragments: data[14] >> 4,
		Number:         data[14] & 0x0f,
		Hops:           data[15],
		Payload:        append([]byte(nil), data[FragmentLength:]...),
	}, nil
}
