package transport

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/networkconfig"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

type OutboundDatagram struct {
	Endpoint netip.AddrPort
	Payload  []byte
}

func (handler *Handler) BuildCOMRevocationBroadcast(
	ctx context.Context,
	networkID domain.NetworkID,
	target domain.NodeID,
	threshold time.Time,
) ([]OutboundDatagram, error) {
	revocation, err := networkconfig.NewCOMRevocation(
		networkID, target, threshold, handler.identity, handler.random,
	)
	if err != nil {
		return nil, err
	}
	serialized, err := revocation.MarshalBinary()
	if err != nil {
		return nil, err
	}
	payload := networkconfig.BuildRevocationCredentialsPayload(serialized)
	members, err := handler.service.ListMembers(ctx, networkID)
	if err != nil {
		return nil, err
	}
	result := make([]OutboundDatagram, 0, len(members))
	for _, member := range members {
		session, err := handler.peers.Get(member.NodeID)
		if err != nil {
			continue
		}
		packetID, err := handler.packetID()
		if err != nil {
			return nil, err
		}
		draft, err := packet.Build(
			packetID, member.NodeID, handler.identity.Address(),
			packet.VerbNetworkCredentials, payload,
		)
		if err != nil {
			return nil, err
		}
		armored, err := packet.ArmorSessionAndFragment(
			draft, session.SharedKey, true, session.ProtocolVersion >= 12,
			packet.DefaultPhysicalMTU,
		)
		if err != nil {
			return nil, fmt.Errorf("armor revocation for %s: %w", member.NodeID, err)
		}
		for _, datagram := range armored {
			result = append(result, OutboundDatagram{
				Endpoint: session.Endpoint, Payload: datagram,
			})
		}
	}
	return result, nil
}
