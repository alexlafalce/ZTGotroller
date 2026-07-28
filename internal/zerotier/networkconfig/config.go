package networkconfig

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

const (
	CurrentVersion                = 7
	DefaultCredentialTimeMaxDelta = 24 * time.Hour
	maxDNSServers                 = 4

	flagEnableBroadcast = uint64(0x02)
	flagEnableNDP       = uint64(0x04)
)

type ConfigInput struct {
	Network                domain.Network
	Member                 domain.Member
	IssuedAt               time.Time
	Revision               uint64
	CredentialTimeMaxDelta time.Duration

	// These protocol objects are added by their dedicated encoders. Keeping
	// them explicit prevents an incomplete credential from looking valid.
	CertificateOfMembership []byte
	CertificatesOfOwnership []byte
	Capabilities            []byte
	Tags                    []byte
}

func BuildDictionary(input ConfigInput) ([]byte, error) {
	if err := input.Network.Validate(); err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	if err := input.Member.Validate(); err != nil {
		return nil, fmt.Errorf("member: %w", err)
	}
	if input.Member.NetworkID != input.Network.ID {
		return nil, errors.New("member belongs to a different network")
	}
	if input.IssuedAt.IsZero() {
		return nil, errors.New("issue time is required")
	}
	if input.CredentialTimeMaxDelta == 0 {
		input.CredentialTimeMaxDelta = DefaultCredentialTimeMaxDelta
	}
	if input.CredentialTimeMaxDelta < 0 {
		return nil, errors.New("credential time maximum delta cannot be negative")
	}

	staticIPs, err := serializeStaticIPs(input.Network.Routes, input.Member.IPAssignments)
	if err != nil {
		return nil, err
	}
	routes, err := serializeRoutes(input.Network.Routes)
	if err != nil {
		return nil, err
	}
	dns, err := serializeDNS(input.Network.DNS)
	if err != nil {
		return nil, err
	}
	rules, err := SerializeRules(input.Network.Rules)
	if err != nil {
		return nil, err
	}

	flags := uint64(0)
	if input.Network.EnableBroadcast {
		flags |= flagEnableBroadcast
	}
	if input.Network.Assignment.IPv6RFC4193 || input.Network.Assignment.IPv6SixPlane {
		flags |= flagEnableNDP
	}
	networkType := uint64(0)
	if !input.Network.Private {
		networkType = 1
	}

	var dictionary DictionaryBuilder
	base := []struct {
		key   string
		value uint64
	}{
		{"v", CurrentVersion},
		{"nwid", mustHexUint(string(input.Network.ID))},
		{"ts", uint64(input.IssuedAt.UnixMilli())},
		{"ctmd", uint64(input.CredentialTimeMaxDelta.Milliseconds())},
		{"r", input.Revision},
	}
	for _, field := range base {
		if err := dictionary.AddHexUint(field.key, field.value); err != nil {
			return nil, err
		}
	}
	if err := dictionary.AddString("id", string(input.Member.NodeID)); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		key   string
		value uint64
	}{{"tt", 0}, {"tl", 0}, {"f", flags}, {"ml", uint64(input.Network.MulticastLimit)}, {"t", networkType}} {
		if err := dictionary.AddHexUint(field.key, field.value); err != nil {
			return nil, err
		}
	}
	if err := dictionary.AddString("n", input.Network.Name); err != nil {
		return nil, err
	}
	if err := dictionary.AddHexUint("mtu", uint64(input.Network.MTU)); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		key   string
		value []byte
	}{{"C", input.CertificateOfMembership}, {"CAP", input.Capabilities}, {"TAG", input.Tags}, {"COO", input.CertificatesOfOwnership}, {"RT", routes}, {"I", staticIPs}, {"R", rules}, {"DNS", dns}} {
		if len(field.value) > 0 {
			if err := dictionary.Add(field.key, field.value); err != nil {
				return nil, err
			}
		}
	}
	return dictionary.Bytes(), nil
}

func serializeRoutes(routes []domain.Route) ([]byte, error) {
	var result bytes.Buffer
	for index, route := range routes {
		if err := appendInetAddress(&result, route.Target.Addr(), route.Target.Bits()); err != nil {
			return nil, fmt.Errorf("route %d target: %w", index, err)
		}
		if route.Via.IsValid() {
			if err := appendInetAddress(&result, route.Via, 0); err != nil {
				return nil, fmt.Errorf("route %d gateway: %w", index, err)
			}
		} else {
			result.WriteByte(0)
		}
		_ = binary.Write(&result, binary.BigEndian, uint16(0)) // flags
		_ = binary.Write(&result, binary.BigEndian, uint16(0)) // metric
	}
	return result.Bytes(), nil
}

func serializeStaticIPs(routes []domain.Route, assignments []netip.Addr) ([]byte, error) {
	var result bytes.Buffer
	for index, address := range assignments {
		prefixBits := -1
		for _, route := range routes {
			if route.Target.Addr().Is4() == address.Is4() && route.Target.Contains(address) && route.Target.Bits() > prefixBits {
				prefixBits = route.Target.Bits()
			}
		}
		if prefixBits < 0 {
			return nil, fmt.Errorf("IP assignment %d (%s) has no containing managed route", index, address)
		}
		if err := appendInetAddress(&result, address, prefixBits); err != nil {
			return nil, fmt.Errorf("IP assignment %d: %w", index, err)
		}
	}
	return result.Bytes(), nil
}

func serializeDNS(config *domain.DNSConfig) ([]byte, error) {
	var result bytes.Buffer
	domainName := ""
	var servers []netip.Addr
	if config != nil {
		domainName = config.Domain
		servers = config.Servers
	}
	if len(domainName) > 127 {
		return nil, errors.New("DNS domain exceeds 127 bytes")
	}
	if len(servers) > maxDNSServers {
		return nil, fmt.Errorf("DNS has more than %d servers", maxDNSServers)
	}
	domainField := make([]byte, 128)
	copy(domainField, domainName)
	result.Write(domainField)
	for index := 0; index < maxDNSServers; index++ {
		if index >= len(servers) {
			result.WriteByte(0)
			continue
		}
		if err := appendInetAddress(&result, servers[index], 0); err != nil {
			return nil, fmt.Errorf("DNS server %d: %w", index, err)
		}
	}
	return result.Bytes(), nil
}

func appendInetAddress(buffer *bytes.Buffer, address netip.Addr, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("port or prefix %d is out of range", port)
	}
	switch {
	case address.Is4():
		buffer.WriteByte(4)
		value := address.As4()
		buffer.Write(value[:])
	case address.Is6():
		buffer.WriteByte(6)
		value := address.As16()
		buffer.Write(value[:])
	default:
		return errors.New("invalid IP address")
	}
	_ = binary.Write(buffer, binary.BigEndian, uint16(port))
	return nil
}

func mustHexUint(value string) uint64 {
	var result uint64
	for _, character := range value {
		result <<= 4
		if character >= '0' && character <= '9' {
			result |= uint64(character - '0')
		} else {
			result |= uint64(character-'a') + 10
		}
	}
	return result
}
