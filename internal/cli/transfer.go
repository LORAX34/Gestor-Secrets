package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/vault"
)

// cmdExport handles two modes:
//   - "export" -> vault backup (encrypted SQLite copy) with retention
//   - "export --project P --env|--json" -> plaintext export of one project
func cmdExport(args []string) int {
	fs := newFlagSet("export")
	cfgFlag := fs.String("config", "", "path to config file")
	project := fs.String("project", "", "export a project instead of a backup")
	envOut := fs.Bool("env", false, "export as KEY=VALUE lines")
	jsonOut := fs.Bool("json", false, "export as JSON")
	out := fs.String("out", "", "output file/dir")
	if !fsParse(fs, args) {
		return 2
	}

	cfg, err := loadConfigOnly(*cfgFlag)
	if err != nil {
		return fail(err)
	}

	// Plaintext project export requires an unlocked vault.
	if *project != "" {
		v, _, err := openVault(*cfgFlag)
		if err != nil {
			return fail(err)
		}
		defer v.Close()
		secrets, err := v.List(*project, true)
		audit(v, "cli", "export", *project, "", err)
		if err != nil {
			return fail(err)
		}
		if *envOut {
			var sb strings.Builder
			for _, s := range secrets {
				sb.WriteString(fmt.Sprintf("%s=%s\n", s.Name, s.Value))
			}
			if *out != "" {
				if err := os.WriteFile(*out, []byte(sb.String()), 0o600); err != nil {
					return fail(err)
				}
				fmt.Printf("Exported %d secrets to %s\n", len(secrets), *out)
			} else {
				fmt.Print(sb.String())
			}
			return 0
		}
		if *jsonOut {
			if *out != "" {
				data, _ := json.MarshalIndent(secrets, "", "  ")
				if err := os.WriteFile(*out, data, 0o600); err != nil {
					return fail(err)
				}
				fmt.Printf("Exported %d secrets to %s\n", len(secrets), *out)
			} else {
				return printJSON(secrets)
			}
			return 0
		}
		return failUsage("sec export --project P --env|--json [--out FILE]")
	}

	// Default: backup mode. Copy the encrypted DB file.
	backupDir := cfg.Backup.Dir
	if *out != "" {
		backupDir = *out
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return fail(err)
	}
	name := fmt.Sprintf("vault-%s.db", time.Now().UTC().Format("20060102T150405Z"))
	dst := filepath.Join(backupDir, name)
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	if err := v.BackupTo(dst); err != nil {
		return fail(err)
	}
	audit(v, "cli", "backup", "", "", nil)
	fmt.Printf("Backup written to %s\n", dst)
	if cfg.Backup.Enabled && cfg.Backup.Keep > 0 {
		removed, rerr := pruneBackups(backupDir, cfg.Backup.Keep)
		if rerr != nil {
			return fail(rerr)
		}
		for _, r := range removed {
			fmt.Printf("Pruned old backup %s\n", r)
		}
	}
	return 0
}

func pruneBackups(dir string, keep int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "vault-") && strings.HasSuffix(e.Name(), ".db") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	var removed []string
	for len(files) > keep {
		f := files[0]
		files = files[1:]
		if err := os.Remove(filepath.Join(dir, f)); err != nil {
			return removed, err
		}
		removed = append(removed, f)
	}
	return removed, nil
}

// cmdImport loads secrets from a .env or .json file into the vault.
func cmdImport(args []string) int {
	fs := newFlagSet("import FILE")
	cfgFlag := fs.String("config", "", "path to config file")
	project := fs.String("project", "", "project to import into (required)")
	typ := fs.String("type", "text", "secret type for imported entries")
	if !fsParse(fs, args) {
		return 2
	}
	if fs.NArg() < 1 || *project == "" {
		return failUsage("sec import FILE --project P [--type TYPE]")
	}
	path := fs.Arg(0)
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()

	ext := strings.ToLower(filepath.Ext(path))
	entries, err := parseImportFile(path, ext)
	if err != nil {
		return fail(err)
	}
	added := 0
	for _, e := range entries {
		if _, err := v.Create(vault.SecretInput{Project: *project, Name: e.name, Type: *typ, Value: e.value}); err != nil {
			if err == vault.ErrDuplicate {
				fmt.Fprintf(os.Stderr, "skipping %s: already exists\n", e.name)
				continue
			}
			audit(v, "cli", "import", *project, e.name, err)
			return fail(err)
		}
		added++
	}
	audit(v, "cli", "import", *project, "", nil)
	fmt.Printf("Imported %d/%d secrets into %s\n", added, len(entries), *project)
	return 0
}

type importEntry struct {
	name  string
	value string
}

func parseImportFile(path, ext string) ([]importEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch ext {
	case ".env":
		var out []importEntry
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			idx := strings.Index(line, "=")
			if idx < 0 {
				continue
			}
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, `"'`)
			out = append(out, importEntry{key, val})
		}
		return out, sc.Err()
	case ".json":
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		var out []importEntry
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, importEntry{k, m[k]})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported file type %q (use .env or .json)", ext)
	}
}

func loadConfigOnly(flagPath string) (config.Config, error) {
	return config.Load(configPath(flagPath))
}
