package vault

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanperez/cli-secret/internal/crypto"
)

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init("testmaster", crypto.DefaultParams()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	return v, path
}

func TestInitUnlockWrongPassword(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Unlock("wrong"); err != ErrWrongMaster {
		t.Fatalf("expected ErrWrongMaster, got %v", err)
	}
	if err := v.Unlock("testmaster"); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}
}

func TestInitAlready(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Init("other", crypto.DefaultParams()); err != ErrAlreadyInit {
		t.Fatalf("expected ErrAlreadyInit, got %v", err)
	}
}

func TestSecretCRUD(t *testing.T) {
	v, _ := newTestVault(t)
	_, err := v.Create(SecretInput{Project: "app", Name: "DB", Value: "pass", Type: "password", Tags: []string{"db", "prod"}})
	if err != nil {
		t.Fatal(err)
	}
	// duplicate
	if _, err := v.Create(SecretInput{Project: "app", Name: "DB", Value: "x"}); err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	s, err := v.Get("app", "DB")
	if err != nil {
		t.Fatal(err)
	}
	if s.Value != "pass" || s.Type != "password" || len(s.Tags) != 2 {
		t.Fatalf("unexpected secret %+v", s)
	}
	if _, err := v.Get("app", "missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	// update keeps history
	_, err = v.Update("app", "DB", SecretInput{Project: "app", Name: "DB", Value: "newpass"})
	if err != nil {
		t.Fatal(err)
	}
	s, _ = v.Get("app", "DB")
	if s.Value != "newpass" || s.Version != 2 {
		t.Fatalf("unexpected after update: %+v", s)
	}
	// rollback
	_, err = v.Rollback("app", "DB", 1)
	if err != nil {
		t.Fatal(err)
	}
	s, _ = v.Get("app", "DB")
	if s.Value != "pass" {
		t.Fatalf("rollback failed: %q", s.Value)
	}
	// delete
	if err := v.Delete("app", "DB"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("app", "DB"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestExpiry(t *testing.T) {
	v, _ := newTestVault(t)
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)
	_, err := v.Create(SecretInput{Project: "p", Name: "ok", Value: "1", ExpiresAt: &future})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Create(SecretInput{Project: "p", Name: "expired", Value: "2", ExpiresAt: &past})
	if err != nil {
		t.Fatal(err)
	}
	st, err := v.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.ExpiredCount != 1 {
		t.Fatalf("expected 1 expired, got %d", st.ExpiredCount)
	}
}

func TestTokens(t *testing.T) {
	v, _ := newTestVault(t)
	raw, tok, err := v.CreateToken("app", "ci", nil)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || tok.ID == 0 {
		t.Fatal("bad token")
	}
	proj, err := v.Authenticate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if proj != "app" {
		t.Fatalf("wrong project %q", proj)
	}
	if _, err := v.Authenticate("bogus-token"); err == nil {
		t.Fatal("expected auth failure")
	}
	if err := v.RevokeToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authenticate(raw); err == nil {
		t.Fatal("expected auth failure after revoke")
	}
}

func TestLockedVault(t *testing.T) {
	v, _ := newTestVault(t)
	v.Lock()
	if _, err := v.Create(SecretInput{Project: "p", Name: "n", Value: "v"}); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	if _, err := v.List("p", true); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestBackup(t *testing.T) {
	v, _ := newTestVault(t)
	if _, err := v.Create(SecretInput{Project: "p", Name: "n", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "backup.db")
	if err := v.BackupTo(dst); err != nil {
		t.Fatal(err)
	}
	// restore backup into a fresh vault and read the secret
	v2, err := Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if err := v2.Unlock("testmaster"); err != nil {
		t.Fatal(err)
	}
	s, err := v2.Get("p", "n")
	if err != nil {
		t.Fatal(err)
	}
	if s.Value != "v" {
		t.Fatalf("backup mismatch %q", s.Value)
	}
}
