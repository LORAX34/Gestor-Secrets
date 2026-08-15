package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/vault"
)

// newFlagSet creates a flag set that prints usage to stdout on -h.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sec %s\n", name)
		fs.PrintDefaults()
	}
	return fs
}

// fsParse parses flags that may appear in any position (before or after
// positional arguments). Returns false on parse errors.
func fsParse(fs *flag.FlagSet, args []string) bool {
	reordered, err := reorderFlags(fs, args)
	if err != nil {
		fmt.Fprintln(fs.Output(), err)
		return false
	}
	if err := fs.Parse(reordered); err != nil {
		return false
	}
	return true
}

// reorderFlags moves flags (and their values) ahead of positionals so that the
// standard flag package can parse them regardless of the order they appear.
func reorderFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			if idx := strings.Index(name, "="); idx >= 0 {
				name = name[:idx]
			}
			f := fs.Lookup(name)
			if f == nil {
				return nil, fmt.Errorf("flag provided but not defined: -%s", name)
			}
			flags = append(flags, a)
			isBool := false
			if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
				isBool = bf.IsBoolFlag()
			}
			if !isBool && !strings.Contains(a, "=") {
				if i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...), nil
}

// openVault loads config, opens the DB and unlocks it with the master password.
func openVault(configFlag string) (*vault.Vault, config.Config, error) {
	cfg, err := config.Load(configPath(configFlag))
	if err != nil {
		return nil, cfg, err
	}
	v, err := vault.Open(cfg.DBPath)
	if err != nil {
		return nil, cfg, err
	}
	init, err := v.Initialized()
	if err != nil {
		v.Close()
		return nil, cfg, err
	}
	if !init {
		v.Close()
		return nil, cfg, fmt.Errorf("vault not initialized at %s — run 'sec init' first", cfg.DBPath)
	}
	pass, err := masterPassword(false)
	if err != nil {
		v.Close()
		return nil, cfg, err
	}
	if err := v.Unlock(pass); err != nil {
		v.Close()
		return nil, cfg, err
	}
	return v, cfg, nil
}

// audit wraps a vault operation with an audit entry.
func audit(v *vault.Vault, actor, action, project, secret string, err error) {
	res := "ok"
	if err != nil {
		res = "error"
	}
	v.Audit(actor, action, project, secret, res)
}
