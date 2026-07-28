package store

import (
	"context"
	"errors"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
	ErrConflict      = errors.New("revision conflict")
)

// Store is the persistence boundary for controller configuration. Implementations
// must enforce optimistic concurrency with the Revision fields. Create operations
// persist revision 1. Save operations require the current revision and persist the
// next one. Delete operations require the current revision. Callers obtain the
// resulting revision with a subsequent Get.
type Store interface {
	Ping(context.Context) error
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
