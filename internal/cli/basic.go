package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ivanperez/cli-secret/internal/config"
	"github.com/ivanperez/cli-secret/internal/crypto"
	"github.com/ivanperez/cli-secret/internal/vault"
)

func cmdInit(args []string) int {
	fs := newFlagSet("init")
	cfgFlag := fs.String("config", "", "path to config file")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	cfgPath := configPath(*cfgFlag)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fail(err)
	}
	if _, err := os.Stat(cfg.DBPath); err == nil {
		init, ierr := vaultInitCheck(cfg.DBPath)
		if ierr != nil {
			return fail(ierr)
		}
		if init {
			return fail(fmt.Errorf("vault already initialized at %s", cfg.DBPath))
		}
	}
	pass, err := masterPassword(true)
	if err != nil {
		return fail(err)
	}
	v, err := vault.Open(cfg.DBPath)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	if err := v.Init(pass, crypto.DefaultParams()); err != nil {
		return fail(err)
	}
	if err := cfg.Save(cfgPath); err != nil {
		return fail(err)
	}
	fmt.Printf("Vault initialized at %s\n", cfg.DBPath)
	fmt.Printf("Config written to %s\n", cfgPath)
	fmt.Println("Store your first secret with: sec add <project> <name> <value>")
	return 0
}

func vaultInitCheck(path string) (bool, error) {
	v, err := vault.Open(path)
	if err != nil {
		return false, err
	}
	defer v.Close()
	return v.Initialized()
}

func cmdAdd(args []string) int {
	fs := newFlagSet("add PROJECT NAME VALUE")
	cfgFlag := fs.String("config", "", "path to config file")
	typ := fs.String("type", "text", "secret type (text, token, password, ssh_key, generic)")
	tag := fs.String("tag", "", "tag (repeatable: --tag a --tag b)")
	notes := fs.String("notes", "", "free-form notes")
	expires := fs.String("expires", "", "expiry date (RFC3339, e.g. 2026-09-01T00:00:00Z)")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	if fs.NArg() < 3 {
		return failUsage("sec add PROJECT NAME VALUE [--type text] [--tag TAG] [--notes NOTES] [--expires DATE]")
	}
	project, name, value := fs.Arg(0), fs.Arg(1), fs.Arg(2)
	if value == "-" {
		b, err := readAllStdin()
		if err != nil {
			return fail(err)
		}
		value = string(b)
	}
	var exp *time.Time
	if *expires != "" {
		t, err := time.Parse(time.RFC3339, *expires)
		if err != nil {
			return fail(fmt.Errorf("invalid --expires: %w", err))
		}
		exp = &t
	}
	v, cfg, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	_, err = v.Create(vault.SecretInput{
		Project:   project,
		Name:      name,
		Type:      *typ,
		Value:     value,
		Notes:     *notes,
		Tags:      splitTags(*tag),
		ExpiresAt: exp,
	})
	audit(v, "cli", "add", project, name, err)
	if err != nil {
		return fail(err)
	}
	_ = cfg
	fmt.Printf("Stored %s/%s\n", project, name)
	return 0
}

func cmdGet(args []string) int {
	fs := newFlagSet("get PROJECT [NAME]")
	cfgFlag := fs.String("config", "", "path to config file")
	env := fs.Bool("env", false, "print as KEY=VALUE lines")
	jsonOut := fs.Bool("json", false, "print as JSON")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	if fs.NArg() < 1 {
		return failUsage("sec get PROJECT [NAME] [--env] [--json]")
	}
	project := fs.Arg(0)
	name := ""
	if fs.NArg() > 1 {
		name = fs.Arg(1)
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	if name != "" {
		s, err := v.Get(project, name)
		audit(v, "cli", "get", project, name, err)
		if err != nil {
			return fail(err)
		}
		if *jsonOut {
			return printJSON(s)
		}
		if *env {
			fmt.Printf("%s=%s\n", s.Name, s.Value)
		} else {
			fmt.Println(s.Value)
		}
		return 0
	}
	secrets, err := v.List(project, true)
	audit(v, "cli", "get", project, "", err)
	if err != nil {
		return fail(err)
	}
	if *jsonOut {
		return printJSON(secrets)
	}
	for _, s := range secrets {
		if *env {
			fmt.Printf("%s=%s\n", s.Name, s.Value)
			continue
		}
		fmt.Printf("# %s (%s) v%d\n%s\n", s.Name, s.Type, s.Version, s.Value)
	}
	return 0
}

func cmdList(args []string) int {
	fs := newFlagSet("list")
	cfgFlag := fs.String("config", "", "path to config file")
	project := fs.String("project", "", "filter by project")
	tags := fs.String("tags", "", "filter by comma-separated tags")
	jsonOut := fs.Bool("json", false, "print as JSON")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	var secrets []vault.Secret
	if *project != "" {
		secrets, err = v.List(*project, false)
	} else {
		secrets, err = v.ListAll()
	}
	if err != nil {
		return fail(err)
	}
	tagFilter := splitTags(*tags)
	if len(tagFilter) > 0 {
		var filtered []vault.Secret
		for _, s := range secrets {
			if containsAny(s.Tags, tagFilter) {
				filtered = append(filtered, s)
			}
		}
		secrets = filtered
	}
	if *jsonOut {
		return printJSON(secrets)
	}
	if len(secrets) == 0 {
		fmt.Println("No secrets found.")
		return 0
	}
	fmt.Printf("%-24s %-24s %-10s %-4s %-16s %s\n", "PROJECT", "NAME", "TYPE", "VER", "EXPIRES", "TAGS")
	for _, s := range secrets {
		exp := ""
		if s.ExpiresAt != nil {
			exp = s.ExpiresAt.Format("2006-01-02")
		}
		fmt.Printf("%-24s %-24s %-10s %-4d %-16s %s\n", s.Project, s.Name, s.Type, s.Version, exp, strings.Join(s.Tags, ","))
	}
	return 0
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func containsAny(have, want []string) bool {
	for _, w := range want {
		for _, h := range have {
			if h == w {
				return true
			}
		}
	}
	return false
}
