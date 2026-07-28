package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func Load(path string) (Identity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Identity{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return Identity{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return Identity{}, err
	}
	if !os.SameFile(info, openedInfo) {
		return Identity{}, errors.New("identity path changed while opening")
	}
	if !openedInfo.Mode().IsRegular() {
		return Identity{}, errors.New("identity path must be a regular file")
	}
	if openedInfo.Mode().Perm()&0o077 != 0 {
		return Identity{}, fmt.Errorf(
			"identity file permissions %04o expose secret material; require 0600 or stricter",
			openedInfo.Mode().Perm(),
		)
	}
	value, err := io.ReadAll(file)
	if err != nil {
		return Identity{}, err
	}
	loaded, err := Parse(strings.TrimSpace(string(value)))
	if err != nil {
		return Identity{}, fmt.Errorf("parse identity: %w", err)
	}
	if !loaded.HasPrivate() {
		return Identity{}, errors.New("identity file contains no private key")
	}
	if !loaded.LocallyValidate() {
		return Identity{}, errors.New("identity proof of work or address is invalid")
	}
	return loaded, nil
}

// LoadOrCreate loads an existing identity or atomically installs a newly
// generated one without replacing a concurrently created identity.
func LoadOrCreate(ctx context.Context, path string) (Identity, bool, error) {
	return loadOrCreate(ctx, path, nil)
}

func loadOrCreate(
	ctx context.Context,
	path string,
	random io.Reader,
) (Identity, bool, error) {
	loaded, err := Load(path)
	if err == nil {
		return loaded, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Identity{}, false, err
	}

	generated, err := Generate(ctx, random)
	if err != nil {
		return Identity{}, false, fmt.Errorf("generate identity: %w", err)
	}
	secret, err := generated.SecretString()
	if err != nil {
		return Identity{}, false, err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return Identity{}, false, fmt.Errorf("create identity directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".ztgotroller-identity-*")
	if err != nil {
		return Identity{}, false, fmt.Errorf("create temporary identity: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return Identity{}, false, err
	}
	if _, err := temporary.WriteString(secret); err != nil {
		_ = temporary.Close()
		return Identity{}, false, err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return Identity{}, false, err
	}
	if err := temporary.Close(); err != nil {
		return Identity{}, false, err
	}

	if err := os.Link(temporaryPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			winner, loadErr := Load(path)
			return winner, false, loadErr
		}
		return Identity{}, false, fmt.Errorf("install identity: %w", err)
	}
	return generated, true, nil
}
