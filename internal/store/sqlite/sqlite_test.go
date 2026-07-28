package sqlite

import (
	"context"
	"database/sql"
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

func TestBackupAndSchemaVersionGuard(t *testing.T) {
	ctx := context.Background()
	sourcePath := filepath.Join(t.TempDir(), "source.db")
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	persistence := openTestStore(t, sourcePath)
	network := domain.NewNetwork("8056c2e21c000001", time.Now().UTC())
	if err := persistence.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	if err := persistence.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backup := openTestStore(t, backupPath)
	if _, err := backup.GetNetwork(ctx, network.ID); err != nil {
		t.Fatalf("backup does not contain network: %v", err)
	}

	futurePath := filepath.Join(t.TempDir(), "future.db")
	db, err := sql.Open("sqlite", futurePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 999"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if future, err := Open(futurePath); err == nil {
		_ = future.Close()
		t.Fatal("expected future schema version to be rejected")
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
