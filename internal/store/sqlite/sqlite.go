package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
	_ "modernc.org/sqlite"
)

const (
	currentSchemaVersion = 1
	schema               = `
CREATE TABLE IF NOT EXISTS networks (
	id TEXT PRIMARY KEY,
	revision INTEGER NOT NULL,
	document BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
	network_id TEXT NOT NULL,
	node_id TEXT NOT NULL,
	revision INTEGER NOT NULL,
	document BLOB NOT NULL,
	PRIMARY KEY (network_id, node_id),
	FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
);
`
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// A single connection makes connection-local pragmas deterministic. SQLite
	// still serializes writers, so this is appropriate for the controller's
	// embedded persistence model.
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("initialize sqlite: %w", err)
		}
	}
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read sqlite schema version: %w", err)
	}
	if version > currentSchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf(
			"database schema version %d is newer than supported version %d",
			version, currentSchemaVersion,
		)
	}
	if version == 0 {
		transaction, err := db.Begin()
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("begin sqlite migration: %w", err)
		}
		if _, err := transaction.Exec(schema); err == nil {
			_, err = transaction.Exec("PRAGMA user_version = 1")
		}
		if err != nil {
			_ = transaction.Rollback()
			_ = db.Close()
			return nil, fmt.Errorf("migrate sqlite schema: %w", err)
		}
		if err := transaction.Commit(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("commit sqlite migration: %w", err)
		}
	}
	return &Store{db: db}, nil
}

func (sqlite *Store) Close() error {
	return sqlite.db.Close()
}

// Backup writes a transactionally consistent standalone database. SQLite
// refuses to overwrite an existing destination.
func (sqlite *Store) Backup(ctx context.Context, destination string) error {
	if destination == "" {
		return errors.New("backup destination is required")
	}
	if _, err := sqlite.db.ExecContext(ctx, "VACUUM INTO ?", destination); err != nil {
		return fmt.Errorf("backup sqlite database: %w", err)
	}
	return nil
}

func (sqlite *Store) CreateNetwork(ctx context.Context, network domain.Network) error {
	if err := network.Validate(); err != nil {
		return err
	}
	network.Revision = 1
	document, err := json.Marshal(network)
	if err != nil {
		return fmt.Errorf("encode network: %w", err)
	}
	result, err := sqlite.db.ExecContext(
		ctx,
		"INSERT OR IGNORE INTO networks(id, revision, document) VALUES (?, ?, ?)",
		network.ID, network.Revision, document,
	)
	return creationResult(result, err)
}

func (sqlite *Store) GetNetwork(ctx context.Context, id domain.NetworkID) (domain.Network, error) {
	var document []byte
	err := sqlite.db.QueryRowContext(
		ctx, "SELECT document FROM networks WHERE id = ?", id,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Network{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Network{}, fmt.Errorf("get network: %w", err)
	}
	var network domain.Network
	if err := json.Unmarshal(document, &network); err != nil {
		return domain.Network{}, fmt.Errorf("decode network: %w", err)
	}
	return network, nil
}

func (sqlite *Store) ListNetworks(ctx context.Context) ([]domain.Network, error) {
	rows, err := sqlite.db.QueryContext(ctx, "SELECT document FROM networks ORDER BY id")
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	defer rows.Close()
	var networks []domain.Network
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan network: %w", err)
		}
		var network domain.Network
		if err := json.Unmarshal(document, &network); err != nil {
			return nil, fmt.Errorf("decode network: %w", err)
		}
		networks = append(networks, network)
	}
	return networks, rows.Err()
}

func (sqlite *Store) SaveNetwork(ctx context.Context, network domain.Network) error {
	if err := network.Validate(); err != nil {
		return err
	}
	expectedRevision := network.Revision
	network.Revision++
	document, err := json.Marshal(network)
	if err != nil {
		return fmt.Errorf("encode network: %w", err)
	}
	result, err := sqlite.db.ExecContext(
		ctx,
		`UPDATE networks SET revision = ?, document = ?
		 WHERE id = ? AND revision = ?`,
		network.Revision, document, network.ID, expectedRevision,
	)
	return mutationResult(ctx, sqlite.db, result, err, "networks", "id = ?", network.ID)
}

func (sqlite *Store) DeleteNetwork(
	ctx context.Context,
	id domain.NetworkID,
	revision uint64,
) error {
	result, err := sqlite.db.ExecContext(
		ctx, "DELETE FROM networks WHERE id = ? AND revision = ?", id, revision,
	)
	return mutationResult(ctx, sqlite.db, result, err, "networks", "id = ?", id)
}

func (sqlite *Store) CreateMember(ctx context.Context, member domain.Member) error {
	if err := member.Validate(); err != nil {
		return err
	}
	if exists, err := rowExists(ctx, sqlite.db, "networks", "id = ?", member.NetworkID); err != nil {
		return err
	} else if !exists {
		return store.ErrNotFound
	}
	member.Revision = 1
	document, err := json.Marshal(member)
	if err != nil {
		return fmt.Errorf("encode member: %w", err)
	}
	result, err := sqlite.db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO members(network_id, node_id, revision, document)
		 VALUES (?, ?, ?, ?)`,
		member.NetworkID, member.NodeID, member.Revision, document,
	)
	return creationResult(result, err)
}

func (sqlite *Store) GetMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
) (domain.Member, error) {
	var document []byte
	err := sqlite.db.QueryRowContext(
		ctx,
		"SELECT document FROM members WHERE network_id = ? AND node_id = ?",
		networkID, nodeID,
	).Scan(&document)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Member{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Member{}, fmt.Errorf("get member: %w", err)
	}
	var member domain.Member
	if err := json.Unmarshal(document, &member); err != nil {
		return domain.Member{}, fmt.Errorf("decode member: %w", err)
	}
	return member, nil
}

func (sqlite *Store) ListMembers(
	ctx context.Context,
	networkID domain.NetworkID,
) ([]domain.Member, error) {
	exists, err := rowExists(ctx, sqlite.db, "networks", "id = ?", networkID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, store.ErrNotFound
	}
	rows, err := sqlite.db.QueryContext(
		ctx,
		"SELECT document FROM members WHERE network_id = ? ORDER BY node_id",
		networkID,
	)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	var members []domain.Member
	for rows.Next() {
		var document []byte
		if err := rows.Scan(&document); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		var member domain.Member
		if err := json.Unmarshal(document, &member); err != nil {
			return nil, fmt.Errorf("decode member: %w", err)
		}
		members = append(members, member)
	}
	return members, rows.Err()
}

func (sqlite *Store) SaveMember(ctx context.Context, member domain.Member) error {
	if err := member.Validate(); err != nil {
		return err
	}
	expectedRevision := member.Revision
	member.Revision++
	document, err := json.Marshal(member)
	if err != nil {
		return fmt.Errorf("encode member: %w", err)
	}
	result, err := sqlite.db.ExecContext(
		ctx,
		`UPDATE members SET revision = ?, document = ?
		 WHERE network_id = ? AND node_id = ? AND revision = ?`,
		member.Revision, document, member.NetworkID, member.NodeID, expectedRevision,
	)
	return mutationResult(
		ctx, sqlite.db, result, err, "members", "network_id = ? AND node_id = ?",
		member.NetworkID, member.NodeID,
	)
}

func (sqlite *Store) DeleteMember(
	ctx context.Context,
	networkID domain.NetworkID,
	nodeID domain.NodeID,
	revision uint64,
) error {
	result, err := sqlite.db.ExecContext(
		ctx,
		`DELETE FROM members
		 WHERE network_id = ? AND node_id = ? AND revision = ?`,
		networkID, nodeID, revision,
	)
	return mutationResult(
		ctx, sqlite.db, result, err, "members", "network_id = ? AND node_id = ?",
		networkID, nodeID,
	)
}

func creationResult(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return store.ErrAlreadyExists
	}
	return nil
}

func mutationResult(
	ctx context.Context,
	db *sql.DB,
	result sql.Result,
	err error,
	table string,
	predicate string,
	arguments ...any,
) error {
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 0 {
		return nil
	}
	exists, err := rowExists(ctx, db, table, predicate, arguments...)
	if err != nil {
		return err
	}
	if exists {
		return store.ErrConflict
	}
	return store.ErrNotFound
}

func rowExists(
	ctx context.Context,
	db *sql.DB,
	table string,
	predicate string,
	arguments ...any,
) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE " + predicate + ")"
	if err := db.QueryRowContext(ctx, query, arguments...).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

var _ store.Store = (*Store)(nil)
