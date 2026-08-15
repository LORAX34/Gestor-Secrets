package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config is the on-disk configuration for cli-secret.
type Config struct {
	DBPath      string `toml:"db_path"`
	Host        string `toml:"host"`
	Port        int    `toml:"port"`
	AutoLockMin int    `toml:"auto_lock_minutes"`
	Backup      Backup `toml:"backup"`
}

// Backup holds backup policy settings.
type Backup struct {
	Enabled bool   `toml:"enabled"`
	Dir     string `toml:"dir"`
	Keep    int    `toml:"keep"`
}

// Default returns a Config with sensible defaults.
func Default() Config {
	home, _ := os.UserHomeDir()
	base := filepath.Join(home, ".cli-secret")
	return Config{
		DBPath:      filepath.Join(base, "vault.db"),
		Host:        "127.0.0.1",
		Port:        9090,
		AutoLockMin: 0,
		Backup: Backup{
			Enabled: true,
			Dir:     filepath.Join(base, "backups"),
			Keep:    10,
		},
	}
}

// Load reads the TOML file at path. If the file does not exist it returns
// Default() plus os.IsNotExist semantics so callers can decide to init.
func Load(path string) (Config, error) {
	cfg := Default()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes the config to path, creating parent directories.
func (c Config) Save(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}
