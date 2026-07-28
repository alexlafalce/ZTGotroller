package controller

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/networkconfig"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/packet"
)

type ConfigReply struct {
	Verb    packet.Verb
	Payload []byte
}

// HandleConfigRequest handles an already authenticated and decrypted request.
// Packet armor and transmission remain at the transport boundary.
func (service *Service) HandleConfigRequest(
	ctx context.Context,
	decoded packet.Decoded,
	recipient identity.Identity,
	controllerIdentity identity.Identity,
) ([]ConfigReply, error) {
	request, err := networkconfig.ParseRequest(decoded)
	if err != nil {
		return nil, err
	}
	if decoded.Routing.Source != recipient.Address() {
		return nil, errors.New("packet source does not match recipient identity")
	}
	if decoded.Routing.Destination != service.controllerID {
		return nil, errors.New("config request is addressed to a different controller")
	}
	if controllerIdentity.Address() != service.controllerID || !controllerIdentity.HasPrivate() {
		return nil, errors.New("controller signing identity does not match service")
	}

	network, err := service.store.GetNetwork(ctx, request.NetworkID)
	if errors.Is(err, store.ErrNotFound) {
		return service.configErrorReply(
			decoded.Routing.PacketID, request.NetworkID, networkconfig.ErrorObjectNotFound,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("get requested network: %w", err)
	}

	member, err := service.RegisterMember(ctx, request.NetworkID, recipient.Address())
	if err != nil {
		return nil, err
	}
	if !member.Authorized {
		return service.configErrorReply(
			decoded.Routing.PacketID, request.NetworkID, networkconfig.ErrorAccessDenied,
		)
	}
	revision, err := configRevision(network.Revision, member.Revision)
	if err != nil {
		return nil, err
	}
	issued, err := networkconfig.IssueAuthorizedConfig(networkconfig.IssueInput{
		Network:    network,
		Member:     member,
		Recipient:  recipient,
		Controller: controllerIdentity,
		IssuedAt:   service.now().UTC(),
		Revision:   revision,
	})
	if err != nil {
		return nil, err
	}
	replies := make([]ConfigReply, len(issued.Chunks))
	for index, chunk := range issued.Chunks {
		replies[index] = ConfigReply{
			Verb:    packet.VerbOK,
			Payload: networkconfig.WrapOK(decoded.Routing.PacketID, chunk),
		}
	}
	return replies, nil
}

func (service *Service) configErrorReply(
	packetID uint64,
	networkID domain.NetworkID,
	code networkconfig.ErrorCode,
) ([]ConfigReply, error) {
	payload, err := networkconfig.WrapError(packetID, networkID, code)
	if err != nil {
		return nil, err
	}
	return []ConfigReply{{Verb: packet.VerbError, Payload: payload}}, nil
}

func configRevision(networkRevision, memberRevision uint64) (uint64, error) {
	if networkRevision == 0 || memberRevision == 0 {
		return 0, errors.New("persisted revisions must be nonzero")
	}
	if networkRevision > math.MaxUint64-memberRevision+1 {
		return 0, errors.New("configuration revision overflow")
	}
	return networkRevision + memberRevision - 1, nil
}
