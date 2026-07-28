package memory

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"sync"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
)

type Store struct {
	mu       sync.RWMutex
	networks map[domain.NetworkID]domain.Network
	members  map[domain.NetworkID]map[domain.NodeID]domain.Member
}

func New() *Store {
	return &Store{
		networks: make(map[domain.NetworkID]domain.Network),
		members:  make(map[domain.NetworkID]map[domain.NodeID]domain.Member),
	}
}

func (memory *Store) CreateNetwork(ctx context.Context, network domain.Network) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := network.Validate(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.networks[network.ID]; exists {
		return store.ErrAlreadyExists
	}
	network.Revision = 1
	memory.networks[network.ID] = cloneNetwork(network)
	return nil
}

func (memory *Store) GetNetwork(ctx context.Context, id domain.NetworkID) (domain.Network, error) {
	if err := ctx.Err(); err != nil {
		return domain.Network{}, err
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	network, exists := memory.networks[id]
	if !exists {
		return domain.Network{}, store.ErrNotFound
	}
	return cloneNetwork(network), nil
}

func (memory *Store) ListNetworks(ctx context.Context) ([]domain.Network, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	networks := make([]domain.Network, 0, len(memory.networks))
	for _, network := range memory.networks {
		networks = append(networks, cloneNetwork(network))
	}
	sort.Slice(networks, func(i, j int) bool { return networks[i].ID < networks[j].ID })
	return networks, nil
}

func (memory *Store) SaveNetwork(ctx context.Context, network domain.Network) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := network.Validate(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.networks[network.ID]
	if !exists {
		return store.ErrNotFound
	}
	if network.Revision != current.Revision {
		return store.ErrConflict
	}
	network.Revision++
	memory.networks[network.ID] = cloneNetwork(network)
	return nil
}

func (memory *Store) DeleteNetwork(ctx context.Context, id domain.NetworkID, revision uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.networks[id]
	if !exists {
		return store.ErrNotFound
	}
	if revision != current.Revision {
		return store.ErrConflict
	}
	delete(memory.networks, id)
	delete(memory.members, id)
	return nil
}

func (memory *Store) CreateMember(ctx context.Context, member domain.Member) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := member.Validate(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	if _, exists := memory.networks[member.NetworkID]; !exists {
		return store.ErrNotFound
	}
	networkMembers := memory.members[member.NetworkID]
	if networkMembers == nil {
		networkMembers = make(map[domain.NodeID]domain.Member)
		memory.members[member.NetworkID] = networkMembers
	}
	if _, exists := networkMembers[member.NodeID]; exists {
		return store.ErrAlreadyExists
	}
	member.Revision = 1
	networkMembers[member.NodeID] = cloneMember(member)
	return nil
}

func (memory *Store) GetMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
) (domain.Member, error) {
	if err := ctx.Err(); err != nil {
		return domain.Member{}, err
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	member, exists := memory.members[networkID][nodeID]
	if !exists {
		return domain.Member{}, store.ErrNotFound
	}
	return cloneMember(member), nil
}

func (memory *Store) ListMembers(
	ctx context.Context,
	networkID domain.NetworkID,
) ([]domain.Member, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	memory.mu.RLock()
	defer memory.mu.RUnlock()
	if _, exists := memory.networks[networkID]; !exists {
		return nil, store.ErrNotFound
	}
	networkMembers := memory.members[networkID]
	members := make([]domain.Member, 0, len(networkMembers))
	for _, member := range networkMembers {
		members = append(members, cloneMember(member))
	}
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	return members, nil
}

func (memory *Store) SaveMember(ctx context.Context, member domain.Member) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := member.Validate(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.members[member.NetworkID][member.NodeID]
	if !exists {
		return store.ErrNotFound
	}
	if member.Revision != current.Revision {
		return store.ErrConflict
	}
	member.Revision++
	memory.members[member.NetworkID][member.NodeID] = cloneMember(member)
	return nil
}

func (memory *Store) DeleteMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
	revision uint64,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	current, exists := memory.members[networkID][nodeID]
	if !exists {
		return store.ErrNotFound
	}
	if revision != current.Revision {
		return store.ErrConflict
	}
	delete(memory.members[networkID], nodeID)
	return nil
}

func cloneNetwork(network domain.Network) domain.Network {
	network.Routes = append([]domain.Route(nil), network.Routes...)
	network.IPPools = append([]domain.IPPool(nil), network.IPPools...)
	network.Rules = cloneRules(network.Rules)
	network.Tags = append([]domain.TagDefinition(nil), network.Tags...)
	if network.DNS != nil {
		dns := *network.DNS
		dns.Servers = append([]netip.Addr(nil), network.DNS.Servers...)
		network.DNS = &dns
	}
	network.Capabilities = append([]domain.Capability(nil), network.Capabilities...)
	for index := range network.Capabilities {
		network.Capabilities[index].Rules = cloneRules(network.Capabilities[index].Rules)
	}
	return network
}

func cloneRules(rules []domain.Rule) []domain.Rule {
	cloned := append([]domain.Rule(nil), rules...)
	for index := range cloned {
		if rules[index].Parameters == nil {
			continue
		}
		cloned[index].Parameters = make(map[string]json.RawMessage, len(rules[index].Parameters))
		for key, value := range rules[index].Parameters {
			cloned[index].Parameters[key] = append(json.RawMessage(nil), value...)
		}
	}
	return cloned
}

func cloneMember(member domain.Member) domain.Member {
	member.IPAssignments = append([]netip.Addr(nil), member.IPAssignments...)
	member.Capabilities = append([]uint32(nil), member.Capabilities...)
	member.Tags = append([]domain.TagValue(nil), member.Tags...)
	return member
}

var _ store.Store = (*Store)(nil)
