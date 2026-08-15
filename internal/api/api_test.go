package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/crypto"
	"github.com/ivanperez/cli-secret/internal/vault"
)

func setup(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := vault.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Init("master", crypto.DefaultParams()); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Create(vault.SecretInput{Project: "app", Name: "KEY", Value: "secret-value"}); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DBPath = path
	cfg.AutoLockMin = 0
	s := New(v, cfg)
	t.Cleanup(func() { v.Close() })
	return s, path
}

func tokenFor(t *testing.T, v *vault.Vault, project string) string {
	t.Helper()
	raw, _, err := v.CreateToken(project, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func doReq(t *testing.T, s *Server, method, target, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rr, req)
	return rr
}

func TestHealth(t *testing.T) {
	s, _ := setup(t)
	rr := doReq(t, s, "GET", "/v1/health", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("bad health %v", body)
	}
}

func TestAuthRequired(t *testing.T) {
	s, _ := setup(t)
	if rr := doReq(t, s, "GET", "/v1/secrets/app", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rr.Code)
	}
	if rr := doReq(t, s, "GET", "/v1/secrets/app", "bad-token", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad token, got %d", rr.Code)
	}
}

func TestProjectScoping(t *testing.T) {
	s, path := setup(t)
	v, _ := vault.Open(path)
	defer v.Close()
	token := tokenFor(t, v, "app")
	if rr := doReq(t, s, "GET", "/v1/secrets/app", token, nil); rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for own project, got %d (%s)", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, s, "GET", "/v1/secrets/other", token, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for other project, got %d", rr.Code)
	}
}

func TestGetAndCreateViaAPI(t *testing.T) {
	s, path := setup(t)
	v, _ := vault.Open(path)
	defer v.Close()
	token := tokenFor(t, v, "app")

	rr := doReq(t, s, "GET", "/v1/secrets/app", token, nil)
	var list []vault.Secret
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Value != "secret-value" {
		t.Fatalf("bad list %+v", list)
	}

	body := []byte(`{"value":"from-api","type":"token"}`)
	if rr := doReq(t, s, "POST", "/v1/secrets/app/NEW", token, body); rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rr.Code, rr.Body.String())
	}
	rr = doReq(t, s, "GET", "/v1/secrets/app/NEW", token, nil)
	var got vault.Secret
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.Value != "from-api" {
		t.Fatalf("bad created value %+v", got)
	}

	if rr := doReq(t, s, "DELETE", "/v1/secrets/app/NEW", token, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}

func TestLockedVault(t *testing.T) {
	s, _ := setup(t)
	// not configured with auto-lock; simulate lock via /v1/lock
	if rr := doReq(t, s, "POST", "/v1/lock", "", nil); rr.Code != http.StatusNoContent {
		t.Fatalf("lock failed %d", rr.Code)
	}
	rr := doReq(t, s, "GET", "/v1/secrets/app", "", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when locked, got %d", rr.Code)
	}
	// unlock with master password
	body := []byte(`{"master_password":"master"}`)
	if rr := doReq(t, s, "POST", "/v1/unlock", "", body); rr.Code != http.StatusNoContent {
		t.Fatalf("unlock failed %d", rr.Code)
	}
	if rr := doReq(t, s, "GET", "/v1/secrets/app", "", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("still requires token after unlock, got %d", rr.Code)
	}
}

func TestAutoLock(t *testing.T) {
	s, path := setup(t)
	v, _ := vault.Open(path)
	defer v.Close()
	token := tokenFor(t, v, "app")
	cfg := s.cfg
	cfg.AutoLockMin = 1
	s.cfg = cfg

	// Simulate 2 minutes of inactivity.
	s.lastActive.Store(time.Now().Add(-2 * time.Minute).Unix())
	rr := doReq(t, s, "GET", "/v1/secrets/app", token, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after idle lock, got %d (%s)", rr.Code, rr.Body.String())
	}
	// health reports locked
	rr = doReq(t, s, "GET", "/v1/health", "", nil)
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"locked":true`)) {
		t.Fatalf("expected locked in health, got %s", rr.Body.String())
	}
}

var _ = context.Background
