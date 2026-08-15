package vault

import (
	"database/sql"
	"time"
)

// AuditEntry is a single row of the audit log.
type AuditEntry struct {
	ID      int64  `json:"id"`
	TS      time.Time `json:"ts"`
	Actor   string `json:"actor"`
	Action  string `json:"action"`
	Project string `json:"project,omitempty"`
	Secret  string `json:"secret,omitempty"`
	Result  string `json:"result"`
}

// Audit appends an entry to the audit log.
func (v *Vault) Audit(actor, action, project, secret, result string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, _ = v.db.Exec(`INSERT INTO audit_log (ts, actor, action, project, secret, result) VALUES (?, ?, ?, ?, ?, ?)`,
		now(), actor, action, project, secret, result)
}

// ListAudit returns audit entries most-recent-first.
func (v *Vault) ListAudit(limit int) ([]AuditEntry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	rows, err := v.db.Query(`SELECT id, ts, actor, action, project, secret, result FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		var project, secret sql.NullString
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &project, &secret, &e.Result); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			e.TS = t
		}
		if project.Valid {
			e.Project = project.String
		}
		if secret.Valid {
			e.Secret = secret.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
