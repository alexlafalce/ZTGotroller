package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	CurrentSchemaVersion  = 1
	DefaultMTU            = 2800
	MinMTU                = 1280
	MaxMTU                = 10000
	DefaultMulticastLimit = 32
	MaxCollectionSize     = 16384
)

type AssignmentModes struct {
	IPv4ZeroTier bool `json:"ipv4ZeroTier"`
	IPv6ZeroTier bool `json:"ipv6ZeroTier"`
	IPv6RFC4193  bool `json:"ipv6RFC4193"`
	IPv6SixPlane bool `json:"ipv6SixPlane"`
}

type Route struct {
	Target netip.Prefix `json:"target"`
	Via    netip.Addr   `json:"via,omitempty"`
}

type IPPool struct {
	Start netip.Addr `json:"start"`
	End   netip.Addr `json:"end"`
}

type DNSConfig struct {
	Domain  string       `json:"domain,omitempty"`
	Servers []netip.Addr `json:"servers,omitempty"`
}

type Rule struct {
	Type       string                     `json:"type"`
	Negate     bool                       `json:"negate,omitempty"`
	Or         bool                       `json:"or,omitempty"`
	Parameters map[string]json.RawMessage `json:"parameters,omitempty"`
}

type Capability struct {
	ID      uint32 `json:"id"`
	Default bool   `json:"default"`
	Rules   []Rule `json:"rules,omitempty"`
}

type TagDefinition struct {
	ID      uint32 `json:"id"`
	Default uint32 `json:"default"`
}

type Network struct {
	SchemaVersion   int             `json:"schemaVersion"`
	ID              NetworkID       `json:"id"`
	Name            string          `json:"name"`
	Private         bool            `json:"private"`
	MTU             int             `json:"mtu"`
	MulticastLimit  int             `json:"multicastLimit"`
	EnableBroadcast bool            `json:"enableBroadcast"`
	Assignment      AssignmentModes `json:"assignment"`
	Routes          []Route         `json:"routes,omitempty"`
	IPPools         []IPPool        `json:"ipPools,omitempty"`
	DNS             *DNSConfig      `json:"dns,omitempty"`
	Rules           []Rule          `json:"rules"`
	Capabilities    []Capability    `json:"capabilities,omitempty"`
	Tags            []TagDefinition `json:"tags,omitempty"`
	CreatedAt       time.Time       `json:"createdAt"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	Revision        uint64          `json:"revision"`
}

func NewNetwork(id NetworkID, now time.Time) Network {
	now = now.UTC()
	return Network{
		SchemaVersion:   CurrentSchemaVersion,
		ID:              id,
		Private:         true,
		MTU:             DefaultMTU,
		MulticastLimit:  DefaultMulticastLimit,
		EnableBroadcast: true,
		Rules:           []Rule{{Type: "ACTION_ACCEPT"}},
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func (network Network) Validate() error {
	if err := network.ID.Validate(); err != nil {
		return err
	}
	if network.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", network.SchemaVersion)
	}
	if network.MTU < MinMTU || network.MTU > MaxMTU {
		return fmt.Errorf("MTU must be between %d and %d", MinMTU, MaxMTU)
	}
	if network.MulticastLimit < 0 {
		return errors.New("multicast limit cannot be negative")
	}
	if network.CreatedAt.IsZero() || network.UpdatedAt.IsZero() {
		return errors.New("creation and update timestamps are required")
	}
	if network.UpdatedAt.Before(network.CreatedAt) {
		return errors.New("updatedAt cannot precede createdAt")
	}
	if err := validateCollectionSizes(network); err != nil {
		return err
	}
	for index, route := range network.Routes {
		if !route.Target.IsValid() {
			return fmt.Errorf("route %d has an invalid target", index)
		}
		if route.Via.IsValid() && route.Via.Is4() != route.Target.Addr().Is4() {
			return fmt.Errorf("route %d target and gateway use different address families", index)
		}
	}
	for index, pool := range network.IPPools {
		if !pool.Start.IsValid() || !pool.End.IsValid() {
			return fmt.Errorf("IP pool %d has an invalid endpoint", index)
		}
		if pool.Start.Is4() != pool.End.Is4() || pool.Start.Compare(pool.End) > 0 {
			return fmt.Errorf("IP pool %d must contain an ordered range from one address family", index)
		}
	}
	for index, rule := range network.Rules {
		if rule.Type == "" {
			return fmt.Errorf("rule %d has no type", index)
		}
	}
	if err := validateUniqueDefinitions(network.Capabilities, network.Tags); err != nil {
		return err
	}
	if network.DNS != nil {
		for index, server := range network.DNS.Servers {
			if !server.IsValid() {
				return fmt.Errorf("DNS server %d is invalid", index)
			}
		}
	}
	return nil
}

func validateCollectionSizes(network Network) error {
	sizes := map[string]int{
		"routes": len(network.Routes), "IP pools": len(network.IPPools),
		"rules": len(network.Rules), "capabilities": len(network.Capabilities),
		"tags": len(network.Tags),
	}
	for name, size := range sizes {
		if size > MaxCollectionSize {
			return fmt.Errorf("%s exceeds the limit of %d entries", name, MaxCollectionSize)
		}
	}
	return nil
}

func validateUniqueDefinitions(capabilities []Capability, tags []TagDefinition) error {
	ids := make(map[uint32]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if _, exists := ids[capability.ID]; exists {
			return fmt.Errorf("duplicate capability ID %d", capability.ID)
		}
		ids[capability.ID] = struct{}{}
	}
	ids = make(map[uint32]struct{}, len(tags))
	for _, tag := range tags {
		if _, exists := ids[tag.ID]; exists {
			return fmt.Errorf("duplicate tag ID %d", tag.ID)
		}
		ids[tag.ID] = struct{}{}
	}
	return nil
}
