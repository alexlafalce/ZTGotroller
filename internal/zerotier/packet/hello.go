package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

const helloFixedLength = 1 + 1 + 1 + 2 + 8 + identity.PublicBinaryLength

type InetAddress struct {
	Address netip.Addr
	Port    uint16
}

type Hello struct {
	Routing                 RoutingHeader
	ProtocolVersion         byte
	Major                   byte
	Minor                   byte
	Revision                uint16
	Timestamp               uint64
	Identity                identity.Identity
	ExternalSurface         *InetAddress
	PlanetWorldID           uint64
	PlanetWorldTimestamp    uint64
	EncryptedWorldExtension []byte
}

type LocalVersion struct {
	Protocol byte
	Major    byte
	Minor    byte
	Revision uint16
}

type HelloOK struct {
	RequestPacketID uint64
	Timestamp       uint64
	Version         LocalVersion
	ExternalSurface *InetAddress
	WorldUpdate     []byte
}

// BuildHello constructs the authenticated, clear-text bootstrap packet used to
// introduce a node identity to a known upstream peer.
func BuildHello(
	packetID uint64,
	destination identity.Identity,
	local identity.Identity,
	version LocalVersion,
	timestamp uint64,
	planetWorldID uint64,
	planetWorldTimestamp uint64,
	sharedKey SessionKey,
) ([]byte, error) {
	if !local.HasPrivate() {
		return nil, errors.New("local identity must include its private key")
	}
	if !destination.LocallyValidate() {
		return nil, errors.New("destination identity failed local validation")
	}
	if version.Protocol < MinimumProtocolVersion {
		return nil, errors.New("local protocol version is below the supported minimum")
	}
	public, err := local.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}
	payload := []byte{version.Protocol, version.Major, version.Minor}
	payload = binary.BigEndian.AppendUint16(payload, version.Revision)
	payload = binary.BigEndian.AppendUint64(payload, timestamp)
	payload = append(payload, public...)
	payload = append(payload, 0) // no claimed external surface
	payload = binary.BigEndian.AppendUint64(payload, planetWorldID)
	payload = binary.BigEndian.AppendUint64(payload, planetWorldTimestamp)
	draft, err := Build(packetID, destination.Address(), local.Address(), VerbHello, payload)
	if err != nil {
		return nil, err
	}
	return ArmorSession(draft, sharedKey, false, false)
}

func ParseHelloOK(decoded Decoded) (HelloOK, error) {
	if decoded.Verb != VerbOK || len(decoded.Payload) < 22 ||
		Verb(decoded.Payload[0]) != VerbHello {
		return HelloOK{}, errors.New("packet is not a complete HELLO OK")
	}
	result := HelloOK{
		RequestPacketID: binary.BigEndian.Uint64(decoded.Payload[1:9]),
		Timestamp:       binary.BigEndian.Uint64(decoded.Payload[9:17]),
		Version: LocalVersion{
			Protocol: decoded.Payload[17],
			Major:    decoded.Payload[18],
			Minor:    decoded.Payload[19],
			Revision: binary.BigEndian.Uint16(decoded.Payload[20:22]),
		},
	}
	if result.Version.Protocol < MinimumProtocolVersion {
		return HelloOK{}, errors.New("HELLO OK protocol version is unsupported")
	}
	offset := 22
	if offset < len(decoded.Payload) {
		address, consumed, err := parseInetAddress(decoded.Payload[offset:])
		if err != nil {
			return HelloOK{}, err
		}
		result.ExternalSurface = address
		offset += consumed
	}
	if len(decoded.Payload)-offset >= 2 {
		length := int(binary.BigEndian.Uint16(decoded.Payload[offset : offset+2]))
		offset += 2
		if length > len(decoded.Payload)-offset {
			return HelloOK{}, errors.New("HELLO OK world update is truncated")
		}
		result.WorldUpdate = append([]byte(nil), decoded.Payload[offset:offset+length]...)
	}
	return result, nil
}

// AuthenticateHello performs the special bootstrap path: the public identity
// is read only to derive a candidate key, then the entire HELLO is MAC-checked
// before any identity or metadata is trusted.
func AuthenticateHello(armored []byte, local identity.Identity) (Hello, SessionKey, error) {
	routing, err := ParseRouting(armored)
	if err != nil {
		return Hello{}, SessionKey{}, err
	}
	if routing.ExtendedArmor {
		armored, err = DearmorExtended(armored, local)
		if err != nil {
			return Hello{}, SessionKey{}, err
		}
		routing, err = ParseRouting(armored)
		if err != nil {
			return Hello{}, SessionKey{}, err
		}
	}
	if routing.Cipher != CipherC25519Poly1305Clear {
		return Hello{}, SessionKey{}, errors.New("initial HELLO must use authenticated clear armor")
	}
	if len(armored) < HeaderLength+helloFixedLength || Verb(armored[27]&0x1f) != VerbHello {
		return Hello{}, SessionKey{}, errors.New("HELLO is truncated or has the wrong verb")
	}
	identityStart := HeaderLength + 13
	peer, err := identity.ParseBinary(armored[identityStart : identityStart+identity.PublicBinaryLength])
	if err != nil {
		return Hello{}, SessionKey{}, fmt.Errorf("parse HELLO identity: %w", err)
	}
	agreed, err := local.Agree(peer, SessionKeyLength)
	if err != nil {
		return Hello{}, SessionKey{}, fmt.Errorf("derive HELLO key: %w", err)
	}
	var sharedKey SessionKey
	copy(sharedKey[:], agreed)
	decoded, err := DearmorSession(armored, sharedKey)
	if err != nil {
		return Hello{}, SessionKey{}, err
	}
	if decoded.Verb != VerbHello {
		return Hello{}, SessionKey{}, errors.New("authenticated packet is not HELLO")
	}
	if decoded.Routing.Source != peer.Address() {
		return Hello{}, SessionKey{}, errors.New("HELLO source and identity address differ")
	}
	if decoded.Routing.Destination != local.Address() {
		return Hello{}, SessionKey{}, errors.New("HELLO is addressed to another identity")
	}
	if !peer.LocallyValidate() {
		return Hello{}, SessionKey{}, errors.New("HELLO identity failed local proof validation")
	}
	hello, err := parseHelloPayload(decoded, peer)
	if err != nil {
		return Hello{}, SessionKey{}, err
	}
	return hello, sharedKey, nil
}

func parseHelloPayload(decoded Decoded, peer identity.Identity) (Hello, error) {
	payload := decoded.Payload
	if len(payload) < helloFixedLength {
		return Hello{}, errors.New("HELLO payload is truncated")
	}
	hello := Hello{
		Routing:         decoded.Routing,
		ProtocolVersion: payload[0],
		Major:           payload[1],
		Minor:           payload[2],
		Revision:        binary.BigEndian.Uint16(payload[3:5]),
		Timestamp:       binary.BigEndian.Uint64(payload[5:13]),
		Identity:        peer,
	}
	if hello.ProtocolVersion < MinimumProtocolVersion {
		return Hello{}, fmt.Errorf("HELLO protocol %d is below minimum %d", hello.ProtocolVersion, MinimumProtocolVersion)
	}
	offset := helloFixedLength
	if offset < len(payload) {
		address, consumed, err := parseInetAddress(payload[offset:])
		if err != nil {
			return Hello{}, fmt.Errorf("HELLO external surface: %w", err)
		}
		offset += consumed
		hello.ExternalSurface = address
	}
	if len(payload)-offset >= 16 {
		hello.PlanetWorldID = binary.BigEndian.Uint64(payload[offset : offset+8])
		hello.PlanetWorldTimestamp = binary.BigEndian.Uint64(payload[offset+8 : offset+16])
		offset += 16
	}
	hello.EncryptedWorldExtension = append([]byte(nil), payload[offset:]...)
	return hello, nil
}

func BuildHelloOK(
	responsePacketID uint64,
	request Hello,
	local identity.Identity,
	observed InetAddress,
	version LocalVersion,
	sharedKey SessionKey,
) ([]byte, error) {
	if version.Protocol < MinimumProtocolVersion {
		return nil, errors.New("local protocol version is below the supported minimum")
	}
	payload := make([]byte, 0, 9+13+19+2)
	payload = append(payload, byte(VerbHello))
	payload = binary.BigEndian.AppendUint64(payload, request.Routing.PacketID)
	payload = binary.BigEndian.AppendUint64(payload, request.Timestamp)
	payload = append(payload, version.Protocol, version.Major, version.Minor)
	payload = binary.BigEndian.AppendUint16(payload, version.Revision)
	serializedAddress, err := serializeInetAddress(observed)
	if err != nil {
		return nil, err
	}
	payload = append(payload, serializedAddress...)
	payload = binary.BigEndian.AppendUint16(payload, 0) // no planet/moon update
	draft, err := Build(responsePacketID, request.Identity.Address(), local.Address(), VerbOK, payload)
	if err != nil {
		return nil, err
	}
	return Armor(draft, sharedKey.salsaKey(), true)
}

func parseInetAddress(serialized []byte) (*InetAddress, int, error) {
	if len(serialized) < 1 {
		return nil, 0, errors.New("missing address family")
	}
	switch serialized[0] {
	case 0:
		return nil, 1, nil
	case 4:
		if len(serialized) < 7 {
			return nil, 0, errors.New("truncated IPv4 address")
		}
		return &InetAddress{
			Address: netip.AddrFrom4([4]byte(serialized[1:5])),
			Port:    binary.BigEndian.Uint16(serialized[5:7]),
		}, 7, nil
	case 6:
		if len(serialized) < 19 {
			return nil, 0, errors.New("truncated IPv6 address")
		}
		return &InetAddress{
			Address: netip.AddrFrom16([16]byte(serialized[1:17])),
			Port:    binary.BigEndian.Uint16(serialized[17:19]),
		}, 19, nil
	default:
		return nil, 0, fmt.Errorf("unsupported address family %d", serialized[0])
	}
}

func serializeInetAddress(address InetAddress) ([]byte, error) {
	switch {
	case address.Address.Is4():
		result := make([]byte, 7)
		result[0] = 4
		value := address.Address.As4()
		copy(result[1:5], value[:])
		binary.BigEndian.PutUint16(result[5:7], address.Port)
		return result, nil
	case address.Address.Is6():
		result := make([]byte, 19)
		result[0] = 6
		value := address.Address.As16()
		copy(result[1:17], value[:])
		binary.BigEndian.PutUint16(result[17:19], address.Port)
		return result, nil
	default:
		return nil, errors.New("observed physical address is invalid")
	}
}
