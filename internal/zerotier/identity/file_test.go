package identity

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.secret")
	generated, created, err := loadOrCreate(
		context.Background(),
		path,
		bytes.NewReader(make([]byte, PrivateKeyLength)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !created || generated.Address() != "a7fa8660c2" {
		t.Fatalf("unexpected generated identity: %s", generated)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode is %04o, want 0600", info.Mode().Perm())
	}

	loaded, created, err := LoadOrCreate(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if created || loaded.String() != generated.String() {
		t.Fatal("existing identity was not reused")
	}
}

func TestLoadRejectsUnsafePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.secret")
	if err := os.WriteFile(path, []byte(knownSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsafe permissions to be rejected")
	}
}

func TestLoadRejectsPublicIdentity(t *testing.T) {
	secret, err := Parse(knownSecret)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.secret")
	if err := os.WriteFile(path, []byte(secret.Public().String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected public-only identity to be rejected")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(knownSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "identity.secret")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("expected symlink to be rejected")
	}
}
