package vault

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// SecretInput carries the fields needed to create or update a secret.
type SecretInput struct {
	Project   string
	Name      string
	Type      string
	Value     string
	Notes     string
	Tags      []string
	ExpiresAt *time.Time
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", s, err)
	}
	return t, nil
}

func scanSecret(row interface{ Scan(...any) error }) (Secret, []byte, error) {
	var s Secret
	var id int64
	var project, name, typ, notes, tags, createdAt, updatedAt string
	var expiresAt sql.NullString
	var version int
	var val []byte
	if err := row.Scan(&id, &project, &name, &typ, &val, &notes, &tags, &createdAt, &updatedAt, &expiresAt, &version); err != nil {
		return s, nil, err
	}
	s.ID = id
	s.Project = project
	s.Name = name
	s.Type = typ
	s.Notes = notes
	s.Tags = decodeTags(tags)
	s.Version = version
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	s.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if expiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil {
			s.ExpiresAt = &t
		}
	}
	return s, val, nil
}

// Create adds a new encrypted secret.
func (v *Vault) Create(in SecretInput) (Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return Secret{}, ErrLocked
	}
	enc, err := v.encrypt(in.Value)
	if err != nil {
		return Secret{}, err
	}
	var exp any
	if in.ExpiresAt != nil {
		exp = in.ExpiresAt.UTC().Format(time.RFC3339)
	}
	res, err := v.db.Exec(`INSERT INTO secrets (project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
		in.Project, in.Name, orDefault(in.Type, "text"), enc, in.Notes, encodeTags(in.Tags), now(), now(), exp)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Secret{}, ErrDuplicate
		}
		return Secret{}, err
	}
	id, _ := res.LastInsertId()
	return v.getByID(id, true)
}

// Get retrieves and decrypts a single secret.
func (v *Vault) Get(project, name string) (Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return Secret{}, ErrLocked
	}
	row := v.db.QueryRow(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets WHERE project = ? AND name = ?`, project, name)
	return v.scanOne(row, true)
}

// List returns all secrets of a project. If decrypt is false, values are omitted.
func (v *Vault) List(project string, decrypt bool) ([]Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return nil, ErrLocked
	}
	rows, err := v.db.Query(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets WHERE project = ? ORDER BY name`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		s, enc, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		if decrypt {
			val, err := v.decrypt(enc)
			if err != nil {
				return nil, err
			}
			s.Value = val
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListAll returns all projects with their secret names (no values).
func (v *Vault) ListAll() ([]Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return nil, ErrLocked
	}
	rows, err := v.db.Query(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets ORDER BY project, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Secret
	for rows.Next() {
		s, _, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Projects returns the distinct project names.
func (v *Vault) Projects() ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	rows, err := v.db.Query(`SELECT DISTINCT project FROM secrets ORDER BY project`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Update replaces the value (and metadata) of a secret, preserving history.
func (v *Vault) Update(project, name string, in SecretInput) (Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return Secret{}, ErrLocked
	}
	return v.updateLocked(project, name, in)
}

func (v *Vault) updateLocked(project, name string, in SecretInput) (Secret, error) {
	existing, err := v.getByIDQuery(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets WHERE project = ? AND name = ?`, project, name)
	if err != nil {
		return Secret{}, err
	}
	if in.Type == "" {
		in.Type = existing.Type
	}
	if in.Notes == "" {
		in.Notes = existing.Notes
	}
	enc, err := v.encrypt(in.Value)
	if err != nil {
		return Secret{}, err
	}
	if err := v.saveVersion(existing.ID, existing.Version); err != nil {
		return Secret{}, err
	}
	newVersion := existing.Version + 1
	var exp any
	if in.ExpiresAt != nil {
		exp = in.ExpiresAt.UTC().Format(time.RFC3339)
	} else if existing.ExpiresAt != nil {
		exp = existing.ExpiresAt.UTC().Format(time.RFC3339)
	}
	tags := in.Tags
	if len(tags) == 0 {
		tags = existing.Tags
	}
	_, err = v.db.Exec(`UPDATE secrets SET value_enc = ?, type = ?, notes = ?, tags = ?, updated_at = ?, expires_at = ?, version = ?
		WHERE id = ?`,
		enc, in.Type, in.Notes, encodeTags(tags), now(), exp, newVersion, existing.ID)
	if err != nil {
		return Secret{}, err
	}
	return v.getByID(existing.ID, true)
}

// Rotate generates a new value for a secret, keeping the old one in history.
func (v *Vault) Rotate(project, name, newValue string) (Secret, error) {
	return v.Update(project, name, SecretInput{Project: project, Name: name, Value: newValue})
}

// Delete removes a secret and its history.
func (v *Vault) Delete(project, name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	res, err := v.db.Exec(`DELETE FROM secrets WHERE project = ? AND name = ?`, project, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Versions lists the history of a secret.
func (v *Vault) Versions(project, name string) ([]Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return nil, ErrLocked
	}
	row := v.db.QueryRow(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets WHERE project = ? AND name = ?`, project, name)
	s, err := v.scanOne(row, true)
	if err != nil {
		return nil, err
	}
	out := []Secret{s}
	rows, err := v.db.Query(`SELECT version, value_enc, created_at FROM versions WHERE secret_id = ? ORDER BY version DESC`, s.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var version int
		var enc []byte
		var ts string
		if err := rows.Scan(&version, &enc, &ts); err != nil {
			return nil, err
		}
		val, err := v.decrypt(enc)
		if err != nil {
			return nil, err
		}
		created, _ := time.Parse(time.RFC3339, ts)
		out = append(out, Secret{Project: s.Project, Name: s.Name, Version: version, Value: val, CreatedAt: created})
	}
	return out, rows.Err()
}

// Rollback restores a previous version of a secret.
func (v *Vault) Rollback(project, name string, version int) (Secret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.vk == nil {
		return Secret{}, ErrLocked
	}
	s, err := v.getByIDQuery(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets WHERE project = ? AND name = ?`, project, name)
	if err != nil {
		return Secret{}, err
	}
	var enc []byte
	err = v.db.QueryRow(`SELECT value_enc FROM versions WHERE secret_id = ? AND version = ?`, s.ID, version).Scan(&enc)
	if err == sql.ErrNoRows {
		return Secret{}, ErrVersion
	}
	if err != nil {
		return Secret{}, err
	}
	val, err := v.decrypt(enc)
	if err != nil {
		return Secret{}, err
	}
	return v.updateLocked(project, name, SecretInput{Project: project, Name: name, Value: val})
}

func (v *Vault) saveVersion(secretID int64, version int) error {
	var enc []byte
	if err := v.db.QueryRow(`SELECT value_enc FROM secrets WHERE id = ?`, secretID).Scan(&enc); err != nil {
		return err
	}
	_, err := v.db.Exec(`INSERT INTO versions (secret_id, version, value_enc, created_at) VALUES (?, ?, ?, ?)`,
		secretID, version, enc, now())
	return err
}

func (v *Vault) getByID(id int64, decrypt bool) (Secret, error) {
	row := v.db.QueryRow(`SELECT id, project, name, type, value_enc, notes, tags, created_at, updated_at, expires_at, version
		FROM secrets WHERE id = ?`, id)
	return v.scanOne(row, decrypt)
}

func (v *Vault) getByIDQuery(q string, args ...any) (Secret, error) {
	row := v.db.QueryRow(q, args...)
	return v.scanOne(row, false)
}

func (v *Vault) scanOne(row *sql.Row, decrypt bool) (Secret, error) {
	s, enc, err := scanSecret(row)
	if err == sql.ErrNoRows {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, err
	}
	if decrypt {
		val, err := v.decrypt(enc)
		if err != nil {
			return Secret{}, err
		}
		s.Value = val
	}
	return s, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
