package cli

import (
	"fmt"
	"strconv"
	"time"
)

func cmdTokens(args []string) int {
	if len(args) == 0 {
		return failUsage("sec tokens create|list|revoke ...")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return tokenCreate(rest)
	case "list":
		return tokenList(rest)
	case "revoke":
		return tokenRevoke(rest)
	case "-h", "--help", "help":
		fmt.Print(`sec tokens — manage project-scoped API tokens

Usage:
  sec tokens create PROJECT [--name NAME] [--expires DATE]
  sec tokens list [--project P] [--json]
  sec tokens revoke ID
`)
		return 0
	default:
		return failUsage("sec tokens create|list|revoke ...")
	}
}

func tokenCreate(args []string) int {
	fs := newFlagSet("tokens create PROJECT")
	cfgFlag := fs.String("config", "", "path to config file")
	name := fs.String("name", "default", "token name")
	expires := fs.String("expires", "", "expiry (RFC3339)")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	if fs.NArg() < 1 {
		return failUsage("sec tokens create PROJECT [--name NAME] [--expires DATE]")
	}
	project := fs.Arg(0)
	var exp *time.Time
	if *expires != "" {
		t, err := time.Parse(time.RFC3339, *expires)
		if err != nil {
			return fail(fmt.Errorf("invalid --expires: %w", err))
		}
		exp = &t
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	raw, tok, err := v.CreateToken(project, *name, exp)
	audit(v, "cli", "token-create", project, "", err)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Token created for project %q (id %d).\n", project, tok.ID)
	fmt.Println("This is the only time it is shown:")
	fmt.Println(raw)
	fmt.Println("Use it with: curl -H 'Authorization: Bearer <token>' http://127.0.0.1:9090/v1/secrets/<project>")
	return 0
}

func tokenList(args []string) int {
	fs := newFlagSet("tokens list")
	cfgFlag := fs.String("config", "", "path to config file")
	project := fs.String("project", "", "filter by project")
	jsonOut := fs.Bool("json", false, "print as JSON")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	tokens, err := v.ListTokens(*project)
	if err != nil {
		return fail(err)
	}
	if *jsonOut {
		return printJSON(tokens)
	}
	if len(tokens) == 0 {
		fmt.Println("No tokens found.")
		return 0
	}
	fmt.Printf("%-6s %-20s %-20s %-24s %-24s\n", "ID", "PROJECT", "NAME", "CREATED", "LAST USED")
	for _, t := range tokens {
		last := ""
		if t.LastUsed != nil {
			last = t.LastUsed.Format(time.RFC3339)
		}
		fmt.Printf("%-6d %-20s %-20s %-24s %-24s\n", t.ID, t.Project, t.Name, t.CreatedAt.Format(time.RFC3339), last)
	}
	return 0
}

func tokenRevoke(args []string) int {
	fs := newFlagSet("tokens revoke ID")
	cfgFlag := fs.String("config", "", "path to config file")
	if code := fsParse(fs, args); code != 0 {
		return code
	}
	if fs.NArg() < 1 {
		return failUsage("sec tokens revoke ID")
	}
	id, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		return failUsage("sec tokens revoke ID (numeric ID, see 'sec tokens list')")
	}
	v, _, err := openVault(*cfgFlag)
	if err != nil {
		return fail(err)
	}
	defer v.Close()
	err = v.RevokeToken(id)
	audit(v, "cli", "token-revoke", "", strconv.FormatInt(id, 10), err)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("Revoked token %d\n", id)
	return 0
}
