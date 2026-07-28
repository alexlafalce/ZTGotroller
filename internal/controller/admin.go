package controller

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
)

type NetworkUpdate struct {
	Name            string                 `json:"name"`
	Private         bool                   `json:"private"`
	MTU             int                    `json:"mtu"`
	MulticastLimit  int                    `json:"multicastLimit"`
	EnableBroadcast bool                   `json:"enableBroadcast"`
	Assignment      domain.AssignmentModes `json:"assignment"`
	Routes          []domain.Route         `json:"routes"`
	IPPools         []domain.IPPool        `json:"ipPools"`
	DNS             *domain.DNSConfig      `json:"dns"`
	Rules           []domain.Rule          `json:"rules"`
}

type MemberUpdate struct {
	ActiveBridge  bool              `json:"activeBridge"`
	NoAutoAssign  bool              `json:"noAutoAssignIps"`
	IPAssignments []netip.Addr      `json:"ipAssignments"`
	Capabilities  []uint32          `json:"capabilities"`
	Tags          []domain.TagValue `json:"tags"`
}

func (service *Service) GetNetwork(ctx context.Context, networkID domain.NetworkID) (domain.Network, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return domain.Network{}, err
	}
	return service.store.GetNetwork(ctx, networkID)
}

func (service *Service) ListNetworks(ctx context.Context) ([]domain.Network, error) {
	return service.store.ListNetworks(ctx)
}

func (service *Service) UpdateNetwork(
	ctx context.Context,
	networkID domain.NetworkID,
	update NetworkUpdate,
	expectedRevision uint64,
) (domain.Network, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return domain.Network{}, err
	}
	network, err := service.store.GetNetwork(ctx, networkID)
	if err != nil {
		return domain.Network{}, err
	}
	if network.Revision != expectedRevision {
		return domain.Network{}, store.ErrConflict
	}
	network.Name = update.Name
	network.Private = update.Private
	network.MTU = update.MTU
	network.MulticastLimit = update.MulticastLimit
	network.EnableBroadcast = update.EnableBroadcast
	network.Assignment = update.Assignment
	network.Routes = append([]domain.Route(nil), update.Routes...)
	network.IPPools = append([]domain.IPPool(nil), update.IPPools...)
	network.DNS = cloneDNS(update.DNS)
	network.Rules = append([]domain.Rule(nil), update.Rules...)
	network.UpdatedAt = service.now().UTC()
	if err := network.Validate(); err != nil {
		return domain.Network{}, fmt.Errorf("updated network: %w", err)
	}
	if err := service.store.SaveNetwork(ctx, network); err != nil {
		return domain.Network{}, err
	}
	return service.store.GetNetwork(ctx, networkID)
}

func (service *Service) GetMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
) (domain.Member, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return domain.Member{}, err
	}
	return service.store.GetMember(ctx, networkID, nodeID)
}

func (service *Service) ListMembers(
	ctx context.Context,
	networkID domain.NetworkID,
) ([]domain.Member, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return nil, err
	}
	if _, err := service.store.GetNetwork(ctx, networkID); err != nil {
		return nil, err
	}
	return service.store.ListMembers(ctx, networkID)
}

func (service *Service) UpdateMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
	update MemberUpdate,
	expectedRevision uint64,
) (domain.Member, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return domain.Member{}, err
	}
	member, err := service.store.GetMember(ctx, networkID, nodeID)
	if err != nil {
		return domain.Member{}, err
	}
	if member.Revision != expectedRevision {
		return domain.Member{}, store.ErrConflict
	}
	member.ActiveBridge = update.ActiveBridge
	member.NoAutoAssign = update.NoAutoAssign
	member.IPAssignments = append([]netip.Addr(nil), update.IPAssignments...)
	member.Capabilities = append([]uint32(nil), update.Capabilities...)
	member.Tags = append([]domain.TagValue(nil), update.Tags...)
	member.UpdatedAt = service.now().UTC()
	if err := member.Validate(); err != nil {
		return domain.Member{}, fmt.Errorf("updated member: %w", err)
	}
	if err := service.store.SaveMember(ctx, member); err != nil {
		return domain.Member{}, err
	}
	return service.store.GetMember(ctx, networkID, nodeID)
}

func cloneDNS(value *domain.DNSConfig) *domain.DNSConfig {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Servers = append([]netip.Addr(nil), value.Servers...)
	return &cloned
}
