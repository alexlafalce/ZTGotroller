package controller

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

const maxIPAMPoolScan = 1 << 20

// ensureAutomaticAssignments gives an authorized member at most one automatic
// address per enabled address family. The mutex makes allocation and persistence
// one controller-local critical section, while optimistic store revisions still
// protect against unrelated concurrent updates.
func (service *Service) ensureAutomaticAssignments(
	ctx context.Context,
	network domain.Network,
	member domain.Member,
) (domain.Member, error) {
	if member.NoAutoAssign || len(network.IPPools) == 0 {
		return member, nil
	}
	need4 := network.Assignment.IPv4ZeroTier && !hasAddressFamily(member.IPAssignments, true)
	need6 := network.Assignment.IPv6ZeroTier && !hasAddressFamily(member.IPAssignments, false)
	if !need4 && !need6 {
		return member, nil
	}

	service.ipamMu.Lock()
	defer service.ipamMu.Unlock()

	current, err := service.store.GetMember(ctx, network.ID, member.NodeID)
	if err != nil {
		return domain.Member{}, err
	}
	need4 = network.Assignment.IPv4ZeroTier && !hasAddressFamily(current.IPAssignments, true)
	need6 = network.Assignment.IPv6ZeroTier && !hasAddressFamily(current.IPAssignments, false)
	if current.NoAutoAssign || (!need4 && !need6) {
		return current, nil
	}
	members, err := service.store.ListMembers(ctx, network.ID)
	if err != nil {
		return domain.Member{}, err
	}
	used := make(map[netip.Addr]struct{})
	for _, existing := range members {
		for _, address := range existing.IPAssignments {
			used[address] = struct{}{}
		}
	}

	changed := false
	if need4 {
		if address, ok := firstAvailableAddress(network, used, true); ok {
			current.IPAssignments = append(current.IPAssignments, address)
			used[address] = struct{}{}
			changed = true
		}
	}
	if need6 {
		if address, ok := firstAvailableAddress(network, used, false); ok {
			current.IPAssignments = append(current.IPAssignments, address)
			changed = true
		}
	}
	if !changed {
		return current, nil
	}
	current.UpdatedAt = service.now().UTC()
	if err := current.Validate(); err != nil {
		return domain.Member{}, fmt.Errorf("automatic IP assignment: %w", err)
	}
	if err := service.store.SaveMember(ctx, current); err != nil {
		return domain.Member{}, fmt.Errorf("save automatic IP assignment: %w", err)
	}
	return service.store.GetMember(ctx, network.ID, current.NodeID)
}

func firstAvailableAddress(
	network domain.Network,
	used map[netip.Addr]struct{},
	ipv4 bool,
) (netip.Addr, bool) {
	scanned := 0
	for _, pool := range network.IPPools {
		if pool.Start.Is4() != ipv4 {
			continue
		}
		for candidate := pool.Start; candidate.IsValid() && candidate.Compare(pool.End) <= 0; candidate = candidate.Next() {
			scanned++
			if scanned > maxIPAMPoolScan {
				return netip.Addr{}, false
			}
			if _, exists := used[candidate]; exists || !addressHasManagedRoute(network.Routes, candidate) {
				continue
			}
			return candidate, true
		}
	}
	return netip.Addr{}, false
}

func addressHasManagedRoute(routes []domain.Route, address netip.Addr) bool {
	for _, route := range routes {
		if route.Target.Contains(address) {
			return true
		}
	}
	return false
}

func hasAddressFamily(addresses []netip.Addr, ipv4 bool) bool {
	for _, address := range addresses {
		if address.Is4() == ipv4 {
			return true
		}
	}
	return false
}
