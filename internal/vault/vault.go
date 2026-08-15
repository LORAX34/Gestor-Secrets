package vault

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	sqlite "modernc.org/sqlite"

	"github.com/ivanperez/cli-secret/internal/crypto"
)

const schemaVersion = 1

var (
	ErrLocked       = errors.New("vault: locked")
	ErrAlreadyInit  = errors.New("vault: already initialized")
	ErrNotInit      = errors.New("vault: not initialized")
	ErrWrongMaster  = errors.New("vault: wrong master password")
	ErrNotFound     = errors.New("vault: not found")
	ErrDuplicate    = errors.New("vault: already exists")
	ErrVersion      = errors.New("vault: version not found")
	ErrExpiredToken = errors.New("vault: token expired or revoked")
)

// Vault is an encrypted SQLite-backed secret store.
type Vault struct {
	mu   sync.Mutex
	db   *sql.DB
	path string

	kek []byte // key encryption key, only in memory while unlocked
	vk  []byte // vault key, only in memory while unlocked
}

// Secret is a single stored entry. Value is plaintext only in memory.
type Secret struct {
	ID        int64      `json:"id"`
	Project   string     `json:"project"`
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Value     string     `json:"value,omitempty"`
	Notes     string     `json:"notes,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Version   int        `json:"version"`
}

// Status summarizes the vault for `sec status`.
type Status struct {
	Path          string    `json:"path"`
	Initialized   bool      `json:"initialized"`
	SchemaVersion int       `json:"schema_version"`
	SecretCount   int       `json:"secret_count"`
	ExpiredCount  int       `json:"expired_count"`
	TokenCount    int       `json:"token_count"`
	AuditCount    int       `json:"audit_count"`
	BackupDir     string    `json:"backup_dir"`
	LastBackup    *string   `json:"last_backup,omitempty"`
}

// Open opens an existing database file (creating schema if needed) without unlocking.
func Open(path string) (*Vault, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	v := &Vault{db: db, path: path}
	if err := v.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return v, nil
}

func (v *Vault) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS meta (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			schema_version INTEGER NOT NULL,
			kdf TEXT NOT NULL,
			salt BLOB NOT NULL,
			params TEXT NOT NULL,
			wrapped_key BLOB NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project TEXT NOT NULL,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'text',
			value_enc BLOB NOT NULL,
			notes TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			expires_at TEXT,
			version INTEGER NOT NULL DEFAULT 1,
			UNIQUE(project, name)
		)`,
		`CREATE TABLE IF NOT EXISTS versions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
			version INTEGER NOT NULL,
			value_enc BLOB NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(secret_id, version)
		)`,
		`CREATE TABLE IF NOT EXISTS api_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project TEXT NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			expires_at TEXT,
			last_used TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT NOT NULL,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			project TEXT,
			secret TEXT,
			result TEXT NOT NULL
		)`,
	}
	for _, s := range stmts {
		if _, err := v.db.Exec(s); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// Initialized reports whether a master key has been set up.
func (v *Vault) Initialized() (bool, error) {
	var n int
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM meta`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Init creates the vault key and wraps it with a key derived from the master password.
func (v *Vault) Init(masterPassword string, p crypto.Argon2Params) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	ok, err := v.Initialized()
	if err != nil {
		return err
	}
	if ok {
		return ErrAlreadyInit
	}
	vk, err := crypto.NewVaultKey()
	if err != nil {
		return err
	}
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	kek := crypto.DeriveKey(masterPassword, salt, p)
	wrapped, err := crypto.WrapKey(vk, kek)
	if err != nil {
		return err
	}
	params, err := crypto.EncodeParams(p)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = v.db.Exec(`INSERT INTO meta (id, schema_version, kdf, salt, params, wrapped_key, created_at, updated_at)
		VALUES (1, ?, 'argon2id', ?, ?, ?, ?, ?)`,
		schemaVersion, salt, params, wrapped, now, now)
	if err != nil {
		return err
	}
	v.kek, v.vk = kek, vk
	return nil
}

// Unlock derives the KEK and unwraps the vault key.
func (v *Vault) Unlock(masterPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	var salt []byte
	var paramsStr string
	var wrapped []byte
	err := v.db.QueryRow(`SELECT salt, params, wrapped_key FROM meta WHERE id = 1`).Scan(&salt, &paramsStr, &wrapped)
	if err == sql.ErrNoRows {
		return ErrNotInit
	}
	if err != nil {
		return err
	}
	p, err := crypto.DecodeParams(paramsStr)
	if err != nil {
		return err
	}
	kek := crypto.DeriveKey(masterPassword, salt, p)
	vk, err := crypto.UnwrapKey(wrapped, kek)
	if err != nil {
		return ErrWrongMaster
	}
	v.kek, v.vk = kek, vk
	return nil
}

// Lock wipes in-memory keys.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.kek, v.vk = nil, nil
}

// Unlocked reports whether the vault key is in memory.
func (v *Vault) Unlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.vk != nil
}

func (v *Vault) encrypt(plain string) ([]byte, error) {
	if v.vk == nil {
		return nil, ErrLocked
	}
	return crypto.Seal([]byte(plain), v.vk)
}

func (v *Vault) decrypt(enc []byte) (string, error) {
	if v.vk == nil {
		return "", ErrLocked
	}
	b, err := crypto.Open(enc, v.vk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func encodeTags(tags []string) string { return strings.Join(tags, ",") }

func decodeTags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// rotateMaster re-wraps the vault key with a new master password.
func (v *Vault) RotateMaster(newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return ErrLocked
	}
	p := crypto.DefaultParams()
	salt, err := crypto.RandomBytes(16)
	if err != nil {
		return err
	}
	kek := crypto.DeriveKey(newPassword, salt, p)
	wrapped, err := crypto.WrapKey(v.vk, kek)
	if err != nil {
		return err
	}
	params, err := crypto.EncodeParams(p)
	if err != nil {
		return err
	}
	_, err = v.db.Exec(`UPDATE meta SET salt = ?, params = ?, wrapped_key = ?, updated_at = ? WHERE id = 1`,
		salt, params, wrapped, now())
	if err != nil {
		return err
	}
	v.kek = kek
	return nil
}

// Status gathers vault metadata.
func (v *Vault) Status() (Status, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s := Status{Path: v.path}
	var n int
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM meta`).Scan(&n); err != nil {
		return s, err
	}
	s.Initialized = n > 0
	if s.Initialized {
		if err := v.db.QueryRow(`SELECT schema_version FROM meta`).Scan(&s.SchemaVersion); err != nil {
			return s, err
		}
	}
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM secrets`).Scan(&s.SecretCount); err != nil {
		return s, err
	}
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM secrets WHERE expires_at IS NOT NULL AND expires_at < ?`, now()).Scan(&s.ExpiredCount); err != nil {
		return s, err
	}
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM api_tokens`).Scan(&s.TokenCount); err != nil {
		return s, err
	}
	if err := v.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&s.AuditCount); err != nil {
		return s, err
	}
	return s, nil
}

// Close closes the underlying database.
func (v *Vault) Close() error {
	return v.db.Close()
}

// BackupTo copies the database to dst using the online SQLite backup API.
func (v *Vault) BackupTo(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := v.db.Ping(); err != nil {
		return err
	}
	ctx := context.Background()
	conn, err := v.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	type backuper interface {
		NewBackup(string) (*sqlite.Backup, error)
	}
	return conn.Raw(func(driverConn any) error {
		bck, err := driverConn.(backuper).NewBackup(dst)
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		for more := true; more; {
			more, err = bck.Step(-1)
			if err != nil {
				return fmt.Errorf("backup: %w", err)
			}
		}
		return bck.Finish()
	})
}
