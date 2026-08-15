package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ivanperez/cli-secret/internal/api"
	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/vault"
)

func cmdServe(args []string) int {
	fs := newFlagSet("serve")
	cfgFlag := fs.String("config", "", "path to config file")
	host := fs.String("host", "", "bind host (overrides config)")
	port := fs.Int("port", 0, "bind port (overrides config)")
	if !fsParse(fs, args) {
		return 2
	}

	cfg, err := config.Load(configPath(*cfgFlag))
	if err != nil {
		return fail(err)
	}
	if *host != "" {
		cfg.Host = *host
	}
	if *port != 0 {
		cfg.Port = *port
	}

	v, err := vault.Open(cfg.DBPath)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	init, err := v.Initialized()
	if err != nil {
		return fail(err)
	}
	if !init {
		return fail(fmt.Errorf("vault not initialized at %s — run 'sec init' first", cfg.DBPath))
	}
	pass, err := masterPassword(false)
	if err != nil {
		return fail(err)
	}
	if err := v.Unlock(pass); err != nil {
		return fail(err)
	}
	v.Audit("api:admin", "serve-start", "", "", "ok")

	server := api.New(v, cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("cli-secret API listening on http://%s:%d\n", cfg.Host, cfg.Port)
	fmt.Printf("Health:  GET  http://%s:%d/v1/health\n", cfg.Host, cfg.Port)
	fmt.Printf("Secrets: GET  http://%s:%d/v1/secrets/<project>   (Bearer token)\n", cfg.Host, cfg.Port)
	fmt.Println("Press Ctrl-C to stop.")

	if err := server.Start(ctx); err != nil {
		return fail(err)
	}
	fmt.Println("Server stopped.")
	return 0
}
