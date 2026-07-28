package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
)

func TestDurableLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "controller.db")
	persistence := openTestStore(t, path)

	network := domain.NewNetwork("8056c2e21c000001", time.Now())
	network.Name = "home"
	if err := persistence.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	member := domain.NewMember(network.ID, "abcdef1234", time.Now())
	if err := persistence.CreateMember(ctx, member); err != nil {
		t.Fatal(err)
	}
	stored, err := persistence.GetMember(ctx, network.ID, member.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	stored.Authorized = true
	if err := persistence.SaveMember(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if err := persistence.SaveMember(ctx, stored); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v, want conflict", err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, path)
	authorized, err := reopened.GetMember(ctx, network.ID, member.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if !authorized.Authorized || authorized.Revision != 2 {
		t.Fatalf("unexpected durable member: %+v", authorized)
	}
	persistedNetwork, err := reopened.GetNetwork(ctx, network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.DeleteNetwork(ctx, network.ID, persistedNetwork.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.GetMember(ctx, network.ID, member.NodeID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want cascade deletion", err)
	}
}

func TestDuplicateAndMissingRelationships(t *testing.T) {
	ctx := context.Background()
	persistence := openTestStore(t, filepath.Join(t.TempDir(), "controller.db"))
	network := domain.NewNetwork("8056c2e21c000001", time.Now())
	if err := persistence.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	if err := persistence.CreateNetwork(ctx, network); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("got %v, want already exists", err)
	}
	missing := domain.NewMember("8056c2e21c000002", "abcdef1234", time.Now())
	if err := persistence.CreateMember(ctx, missing); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want not found", err)
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	persistence, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })
	return persistence
}
