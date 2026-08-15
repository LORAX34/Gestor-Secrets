package vault

import (
	"database/sql"
	"time"

	"github.com/ivanperez/cli-secret/internal/crypto"
)

// APIToken describes a stored token (the raw value is only shown once).
type APIToken struct {
	ID        int64      `json:"id"`
	Project   string     `json:"project"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// CreateToken mints a new API token scoped to a project and stores only its hash.
// The returned raw token must be shown to the user exactly once.
func (v *Vault) CreateToken(project, name string, expiresAt *time.Time) (string, APIToken, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	raw, err := crypto.NewToken()
	if err != nil {
		return "", APIToken{}, err
	}
	hash := crypto.HashToken(raw)
	var exp any
	if expiresAt != nil {
		exp = expiresAt.UTC().Format(time.RFC3339)
	}
	res, err := v.db.Exec(`INSERT INTO api_tokens (project, name, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		project, name, hash, now(), exp)
	if err != nil {
		return "", APIToken{}, err
	}
	id, _ := res.LastInsertId()
	tok := APIToken{ID: id, Project: project, Name: name, CreatedAt: time.Now().UTC()}
	if expiresAt != nil {
		tok.ExpiresAt = expiresAt
	}
	return raw, tok, nil
}

// ListTokens returns all tokens (or those scoped to a project).
func (v *Vault) ListTokens(project string) ([]APIToken, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	q := `SELECT id, project, name, created_at, expires_at, last_used FROM api_tokens`
	var args []any
	if project != "" {
		q += ` WHERE project = ?`
		args = append(args, project)
	}
	q += ` ORDER BY created_at DESC`
	rows, err := v.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var created, expires, last sql.NullString
		if err := rows.Scan(&t.ID, &t.Project, &t.Name, &created, &expires, &last); err != nil {
			return nil, err
		}
		if c, err := time.Parse(time.RFC3339, created.String); err == nil {
			t.CreatedAt = c
		}
		if expires.Valid {
			if e, err := time.Parse(time.RFC3339, expires.String); err == nil {
				t.ExpiresAt = &e
			}
		}
		if last.Valid {
			if l, err := time.Parse(time.RFC3339, last.String); err == nil {
				t.LastUsed = &l
			}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken deletes a token by ID.
func (v *Vault) RevokeToken(id int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	res, err := v.db.Exec(`DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Authenticate validates a raw token and returns its project.
func (v *Vault) Authenticate(raw string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	hash := crypto.HashToken(raw)
	var project string
	var expires sql.NullString
	err := v.db.QueryRow(`SELECT project, expires_at FROM api_tokens WHERE token_hash = ?`, hash).Scan(&project, &expires)
	if err == sql.ErrNoRows {
		return "", ErrExpiredToken
	}
	if err != nil {
		return "", err
	}
	if expires.Valid {
		if e, perr := time.Parse(time.RFC3339, expires.String); perr == nil && time.Now().After(e) {
			return "", ErrExpiredToken
		}
	}
	_, err = v.db.Exec(`UPDATE api_tokens SET last_used = ? WHERE token_hash = ?`, now(), hash)
	if err != nil {
		return "", err
	}
	return project, nil
}
