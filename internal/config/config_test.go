package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	home, _ := os.UserHomeDir()
	c := Default()
	if c.DBPath != filepath.Join(home, ".cli-secret", "vault.db") {
		t.Fatalf("unexpected default db path %q", c.DBPath)
	}
	if c.Port != 9090 || c.Host != "127.0.0.1" {
		t.Fatalf("unexpected defaults %+v", c)
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	c := Default()
	c.Port = 1234
	c.Host = "0.0.0.0"
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 1234 || got.Host != "0.0.0.0" {
		t.Fatalf("round trip mismatch %+v", got)
	}
	if got.Backup.Keep != 10 {
		t.Fatalf("backup keep mismatch %d", got.Backup.Keep)
	}
}

func TestLoadMissingReturnsDefaults(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != 9090 {
		t.Fatalf("expected defaults for missing file, got %+v", got)
	}
}
