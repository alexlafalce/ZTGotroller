package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	sqlitestore "github.com/alexlafalce/ZTGotroller/internal/store/sqlite"
	"github.com/alexlafalce/ZTGotroller/internal/zerotier/identity"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	databasePath := flag.String("database", "ztgotroller.db", "SQLite database path")
	identityPath := flag.String("identity", "identity.secret", "controller identity secret path")
	outputPath := flag.String("output", "", "new backup directory")
	flag.Parse()
	if *outputPath == "" {
		return errors.New("-output is required")
	}
	secret, err := os.ReadFile(*identityPath)
	if err != nil {
		return fmt.Errorf("read controller identity: %w", err)
	}
	if _, err := identity.Parse(string(secret)); err != nil {
		return fmt.Errorf("validate controller identity: %w", err)
	}
	if err := os.Mkdir(*outputPath, 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(*outputPath)
		}
	}()
	persistence, err := sqlitestore.Open(*databasePath)
	if err != nil {
		return err
	}
	defer persistence.Close()
	if err := persistence.Backup(
		context.Background(), filepath.Join(*outputPath, "ztgotroller.db"),
	); err != nil {
		return err
	}
	if err := copySecret(
		*identityPath, filepath.Join(*outputPath, "identity.secret"),
	); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func copySecret(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return fmt.Errorf("open identity: %w", err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create identity backup: %w", err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return fmt.Errorf("copy identity: %w", err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return fmt.Errorf("sync identity backup: %w", err)
	}
	return output.Close()
}
