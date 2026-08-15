package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/vault"
)

func cmdStatus(args []string) int {
	fs := newFlagSet("status")
	cfgFlag := fs.String("config", "", "path to config file")
	jsonOut := fs.Bool("json", false, "print as JSON")
	if code := fsParse(fs, args); code != 0 {
		return code
	}

	cfg, err := config.Load(configPath(*cfgFlag))
	if err != nil {
		return fail(err)
	}
	v, err := vault.Open(cfg.DBPath)
	if err != nil {
		return fail(err)
	}
	defer v.Close()

	st, err := v.Status()
	if err != nil {
		return fail(err)
	}
	st.BackupDir = cfg.Backup.Dir
	backups, _ := listBackups(cfg.Backup.Dir)
	if len(backups) > 0 {
		last := backups[len(backups)-1]
		st.LastBackup = &last
	}
	if *jsonOut {
		return printJSON(st)
	}
	state := "not initialized"
	if st.Initialized {
		state = "initialized"
	}
	fmt.Printf("Vault:       %s (%s)\n", st.Path, state)
	if !st.Initialized {
		return 0
	}
	fmt.Printf("Schema:      v%d\n", st.SchemaVersion)
	fmt.Printf("Secrets:     %d\n", st.SecretCount)
	fmt.Printf("Expired:     %d\n", st.ExpiredCount)
	fmt.Printf("API tokens:  %d\n", st.TokenCount)
	fmt.Printf("Audit rows:  %d\n", st.AuditCount)
	fmt.Printf("Backup dir:  %s\n", st.BackupDir)
	if st.LastBackup != nil {
		fmt.Printf("Last backup: %s\n", *st.LastBackup)
	}
	// Expired secrets warning
	if st.ExpiredCount > 0 {
		expired, err := v.ListAll()
		if err == nil {
			for _, s := range expired {
				if s.ExpiresAt != nil && s.ExpiresAt.Before(time.Now()) {
					fmt.Fprintf(os.Stderr, "WARNING: %s/%s expired on %s\n", s.Project, s.Name, s.ExpiresAt.Format(time.RFC3339))
				}
			}
		}
	}
	return 0
}

func cmdAudit(args []string) int {
	fs := newFlagSet("audit")
	cfgFlag := fs.String("config", "", "path to config file")
	limit := fs.Int("limit", 50, "number of entries")
	jsonOut := fs.Bool("json", false, "print as JSON")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	entries, err := v.ListAudit(*limit)
	if err != nil {
		return fail(err)
	}
	if *jsonOut {
		return printJSON(entries)
	}
	if len(entries) == 0 {
		fmt.Println("No audit entries.")
		return 0
	}
	for _, e := range entries {
		fmt.Printf("%s  %-14s %-12s %-16s %-16s %s\n",
			e.TS.Format(time.RFC3339), e.Actor, e.Action, e.Project, e.Secret, e.Result)
	}
	return 0
}

func listBackups(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
