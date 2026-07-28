package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
)

type Clock func() time.Time

type Service struct {
	controllerID domain.NodeID
	store        store.Store
	now          Clock
}

func New(controllerID domain.NodeID, persistence store.Store, clock Clock) (*Service, error) {
	if err := controllerID.Validate(); err != nil {
		return nil, err
	}
	if persistence == nil {
		return nil, errors.New("store is required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{controllerID: controllerID, store: persistence, now: clock}, nil
}

func (service *Service) CreateNetwork(
	ctx context.Context,
	sequence uint32,
	name string,
) (domain.Network, error) {
	if sequence > 0x00ffffff {
		return domain.Network{}, errors.New("network sequence exceeds 24 bits")
	}
	network := domain.NewNetwork(domain.NewNetworkID(service.controllerID, sequence), service.now())
	network.Name = name
	if err := service.store.CreateNetwork(ctx, network); err != nil {
		return domain.Network{}, fmt.Errorf("create network: %w", err)
	}
	return service.store.GetNetwork(ctx, network.ID)
}

// RegisterMember records a node's first contact without authorizing it. Calling
// it again is idempotent and returns the existing desired state.
func (service *Service) RegisterMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
) (domain.Member, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return domain.Member{}, err
	}
	if err := nodeID.Validate(); err != nil {
		return domain.Member{}, err
	}
	existing, err := service.store.GetMember(ctx, networkID, nodeID)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return domain.Member{}, fmt.Errorf("get member: %w", err)
	}

	member := domain.NewMember(networkID, nodeID, service.now())
	if err := service.store.CreateMember(ctx, member); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return service.store.GetMember(ctx, networkID, nodeID)
		}
		return domain.Member{}, fmt.Errorf("register member: %w", err)
	}
	return service.store.GetMember(ctx, networkID, nodeID)
}

func (service *Service) SetMemberAuthorization(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
	authorized bool,
	expectedRevision uint64,
) (domain.Member, error) {
	if err := service.validateOwnedNetwork(networkID); err != nil {
		return domain.Member{}, err
	}
	member, err := service.store.GetMember(ctx, networkID, nodeID)
	if err != nil {
		return domain.Member{}, fmt.Errorf("get member: %w", err)
	}
	if member.Revision != expectedRevision {
		return domain.Member{}, store.ErrConflict
	}
	if member.Authorized == authorized {
		return member, nil
	}
	member.Authorized = authorized
	member.UpdatedAt = service.now().UTC()
	if err := service.store.SaveMember(ctx, member); err != nil {
		return domain.Member{}, fmt.Errorf("save member: %w", err)
	}
	return service.store.GetMember(ctx, networkID, nodeID)
}

func (service *Service) validateOwnedNetwork(networkID domain.NetworkID) error {
	controllerID, err := networkID.ControllerID()
	if err != nil {
		return err
	}
	if controllerID != service.controllerID {
		return fmt.Errorf("network %s belongs to controller %s", networkID, controllerID)
	}
	return nil
}
