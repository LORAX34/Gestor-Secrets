package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/vault"
)

// Server serves the local HTTP API over an unlocked vault.
type Server struct {
	vault      *vault.Vault
	cfg        config.Config
	lastActive atomic.Int64
	locked     atomic.Bool
	srv        *http.Server
}

// New builds an API server from an already-unlocked vault.
func New(v *vault.Vault, cfg config.Config) *Server {
	s := &Server{vault: v, cfg: cfg}
	s.lastActive.Store(time.Now().Unix())
	s.locked.Store(!v.Unlocked())
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/unlock", s.handleUnlock)
	mux.HandleFunc("/v1/lock", s.handleLock)
	mux.HandleFunc("/v1/secrets/", s.handleSecrets)
	s.srv = &http.Server{
		Addr:    addr(cfg),
		Handler: s.middleware(mux),
	}
	return s
}

func addr(cfg config.Config) string {
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.Port
	if port == 0 {
		port = 9090
	}
	return host + ":" + itoa(port)
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// Start runs the server and blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()
	err := s.srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) touch() {
	now := time.Now()
	if s.cfg.AutoLockMin > 0 && !s.locked.Load() {
		last := time.Unix(s.lastActive.Load(), 0)
		if now.Sub(last) > time.Duration(s.cfg.AutoLockMin)*time.Minute {
			s.locked.Store(true)
			s.vault.Lock()
		}
	}
	s.lastActive.Store(now.Unix())
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.touch()
		w.Header().Set("Server", "cli-secret")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"locked":  s.locked.Load(),
		"version": "0.1.0",
	})
}

type unlockReq struct {
	MasterPassword string `json:"master_password"`
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req unlockReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.vault.Unlock(req.MasterPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "wrong master password")
		return
	}
	s.locked.Store(false)
	s.vault.Audit("api:admin", "unlock", "", "", "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.locked.Store(true)
	s.vault.Lock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if s.locked.Load() {
		writeError(w, http.StatusUnauthorized, "vault is locked — call POST /v1/unlock")
		return
	}
	// Auth: Bearer token scoped to a project.
	project, ok := s.authenticate(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid or expired API token")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	reqProject := parts[0]
	if reqProject != project {
		writeError(w, http.StatusForbidden, "token not authorized for project "+reqProject)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r, parts)
	case http.MethodPost:
		s.handlePost(w, r, parts)
	case http.MethodDelete:
		s.handleDelete(w, r, parts)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, parts []string) {
	project := parts[0]
	actor := "api:" + project
	if len(parts) == 2 {
		secret, err := s.vault.Get(project, parts[1])
		s.vault.Audit(actor, "get", project, parts[1], errString(err))
		if err != nil {
			writeError(w, errStatus(err), err.Error())
			return
		}
		writeJSON(w, http.StatusOK, secret)
		return
	}
	secrets, err := s.vault.List(project, true)
	s.vault.Audit(actor, "get", project, "", errString(err))
	if err != nil {
		writeError(w, errStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, secrets)
}

type secretReq struct {
	Value     string `json:"value"`
	Type      string `json:"type"`
	Notes     string `json:"notes"`
	Tags      []string `json:"tags"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request, parts []string) {
	project := parts[0]
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req secretReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var exp *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expires_at")
			return
		}
		exp = &t
	}
	in := vault.SecretInput{Project: project, Name: parts[1], Value: req.Value, Type: req.Type, Notes: req.Notes, Tags: req.Tags, ExpiresAt: exp}
	secret, err := s.vault.Get(project, parts[1])
	created := errors.Is(err, vault.ErrNotFound)
	if created {
		secret, err = s.vault.Create(in)
	} else {
		secret, err = s.vault.Update(project, parts[1], in)
	}
	s.vault.Audit("api:"+project, "post", project, parts[1], errString(err))
	if err != nil {
		writeError(w, errStatus(err), err.Error())
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, secret)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, parts []string) {
	project := parts[0]
	if len(parts) != 2 {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	err := s.vault.Delete(project, parts[1])
	s.vault.Audit("api:"+project, "delete", project, parts[1], errString(err))
	if err != nil {
		writeError(w, errStatus(err), err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authenticate(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(h, "Bearer ")
	project, err := s.vault.Authenticate(token)
	if err != nil {
		return "", false
	}
	return project, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return "error"
}

func errStatus(err error) int {
	switch {
	case errors.Is(err, vault.ErrNotFound), errors.Is(err, vault.ErrVersion):
		return http.StatusNotFound
	case errors.Is(err, vault.ErrDuplicate):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
