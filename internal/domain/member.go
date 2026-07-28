package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

type TagValue struct {
	ID    uint32 `json:"id"`
	Value uint32 `json:"value"`
}

// Member contains administrator-owned desired state.
type Member struct {
	SchemaVersion            int          `json:"schemaVersion"`
	NetworkID                NetworkID    `json:"networkId"`
	NodeID                   NodeID       `json:"nodeId"`
	Authorized               bool         `json:"authorized"`
	Name                     string       `json:"name,omitempty"`
	ActiveBridge             bool         `json:"activeBridge"`
	NetworkRelay             bool         `json:"networkRelay,omitempty"`
	MulticastReplicator      bool         `json:"multicastReplicator,omitempty"`
	NoAutoAssign             bool         `json:"noAutoAssignIps"`
	IPAssignments            []netip.Addr `json:"ipAssignments,omitempty"`
	Capabilities             []uint32     `json:"capabilities,omitempty"`
	Tags                     []TagValue   `json:"tags,omitempty"`
	AuthenticationExpiryTime uint64       `json:"authenticationExpiryTime,omitempty"`
	AuthenticationURL        string       `json:"authenticationURL,omitempty"`
	RemoteTraceTarget        string       `json:"remoteTraceTarget,omitempty"`
	RemoteTraceLevel         uint64       `json:"remoteTraceLevel,omitempty"`
	SSOExempt                bool         `json:"ssoExempt,omitempty"`
	LastAuthorizedAt         time.Time    `json:"lastAuthorizedAt,omitempty"`
	LastDeauthorizedAt       time.Time    `json:"lastDeauthorizedAt,omitempty"`
	CreatedAt                time.Time    `json:"createdAt"`
	UpdatedAt                time.Time    `json:"updatedAt"`
	Revision                 uint64       `json:"revision"`
}

// MemberStatus contains observed, replaceable runtime information.
type MemberStatus struct {
	NetworkID NetworkID    `json:"networkId"`
	NodeID    NodeID       `json:"nodeId"`
	Online    bool         `json:"online"`
	LastSeen  time.Time    `json:"lastSeen,omitempty"`
	Version   AgentVersion `json:"version"`
}

type AgentVersion struct {
	Major    int `json:"major"`
	Minor    int `json:"minor"`
	Revision int `json:"revision"`
	Protocol int `json:"protocol"`
}

// AgentMetadata contains replaceable capabilities reported by an agent in a
// network configuration request. It is observed state, not administrator-owned
// member configuration.
type AgentMetadata struct {
	NetworkID           NetworkID `json:"networkId"`
	NodeID              NodeID    `json:"nodeId"`
	Target              string    `json:"target,omitempty"`
	Vendor              uint64    `json:"vendor,omitempty"`
	Protocol            uint64    `json:"protocol,omitempty"`
	Major               uint64    `json:"major,omitempty"`
	Minor               uint64    `json:"minor,omitempty"`
	Revision            uint64    `json:"revision,omitempty"`
	RulesEngineRevision uint64    `json:"rulesEngineRevision,omitempty"`
	MaxRules            uint64    `json:"maxRules,omitempty"`
	MaxCapabilities     uint64    `json:"maxCapabilities,omitempty"`
	MaxCapabilityRules  uint64    `json:"maxCapabilityRules,omitempty"`
	MaxTags             uint64    `json:"maxTags,omitempty"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

func (metadata AgentMetadata) Validate() error {
	if err := metadata.NetworkID.Validate(); err != nil {
		return err
	}
	if err := metadata.NodeID.Validate(); err != nil {
		return err
	}
	if len(metadata.Target) > 128 {
		return errors.New("agent target exceeds 128 bytes")
	}
	if metadata.UpdatedAt.IsZero() {
		return errors.New("agent metadata update time is required")
	}
	return nil
}

func NewMember(networkID NetworkID, nodeID NodeID, now time.Time) Member {
	now = now.UTC()
	return Member{
		SchemaVersion: CurrentSchemaVersion,
		NetworkID:     networkID,
		NodeID:        nodeID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func (member Member) Validate() error {
	if member.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", member.SchemaVersion)
	}
	if err := member.NetworkID.Validate(); err != nil {
		return err
	}
	if err := member.NodeID.Validate(); err != nil {
		return err
	}
	if member.CreatedAt.IsZero() || member.UpdatedAt.IsZero() {
		return errors.New("creation and update timestamps are required")
	}
	if member.UpdatedAt.Before(member.CreatedAt) {
		return errors.New("updatedAt cannot precede createdAt")
	}
	if len(member.IPAssignments) > MaxCollectionSize ||
		len(member.Capabilities) > MaxCollectionSize ||
		len(member.Tags) > MaxCollectionSize {
		return fmt.Errorf("member collection exceeds the limit of %d entries", MaxCollectionSize)
	}
	if err := validateUniqueMemberValues(member); err != nil {
		return err
	}
	return nil
}

func validateUniqueMemberValues(member Member) error {
	addresses := make(map[netip.Addr]struct{}, len(member.IPAssignments))
	for index, address := range member.IPAssignments {
		if !address.IsValid() {
			return fmt.Errorf("IP assignment %d is invalid", index)
		}
		if _, exists := addresses[address]; exists {
			return fmt.Errorf("duplicate IP assignment %s", address)
		}
		addresses[address] = struct{}{}
	}
	capabilities := make(map[uint32]struct{}, len(member.Capabilities))
	for _, id := range member.Capabilities {
		if _, exists := capabilities[id]; exists {
			return fmt.Errorf("duplicate capability ID %d", id)
		}
		capabilities[id] = struct{}{}
	}
	tags := make(map[uint32]struct{}, len(member.Tags))
	for _, tag := range member.Tags {
		if _, exists := tags[tag.ID]; exists {
			return fmt.Errorf("duplicate tag ID %d", tag.ID)
		}
		tags[tag.ID] = struct{}{}
	}
	return nil
}
