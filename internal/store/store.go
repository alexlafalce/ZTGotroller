package store

import (
	"context"
	"errors"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("revision conflict")
)

// Store is the persistence boundary for controller configuration. Implementations
// must enforce optimistic concurrency with the Revision fields.
type Store interface {
	CreateNetwork(context.Context, domain.Network) error
	GetNetwork(context.Context, domain.NetworkID) (domain.Network, error)
	ListNetworks(context.Context) ([]domain.Network, error)
	SaveNetwork(context.Context, domain.Network) error
	DeleteNetwork(context.Context, domain.NetworkID, uint64) error

	CreateMember(context.Context, domain.Member) error
	GetMember(context.Context, domain.NetworkID, domain.NodeID) (domain.Member, error)
	ListMembers(context.Context, domain.NetworkID) ([]domain.Member, error)
	SaveMember(context.Context, domain.Member) error
	DeleteMember(context.Context, domain.NetworkID, domain.NodeID, uint64) error
}
