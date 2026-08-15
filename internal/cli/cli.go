package cli

import (
	"fmt"
	"os"

	"github.com/ivanperez/cli-secret/internal/config"
)

// Run executes the CLI with the given arguments and returns an exit code.
func Run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "--help", "-h":
		printUsage()
		return 0
	case "version", "--version", "-v":
		fmt.Println("cli-secret " + version)
		return 0
	case "init":
		return cmdInit(rest)
	case "add":
		return cmdAdd(rest)
	case "get":
		return cmdGet(rest)
	case "list", "ls":
		return cmdList(rest)
	case "update":
		return cmdUpdate(rest)
	case "rm", "remove":
		return cmdRm(rest)
	case "rotate":
		return cmdRotate(rest)
	case "rollback":
		return cmdRollback(rest)
	case "versions":
		return cmdVersions(rest)
	case "rotate-master":
		return cmdRotateMaster(rest)
	case "export":
		return cmdExport(rest)
	case "import":
		return cmdImport(rest)
	case "tokens":
		return cmdTokens(rest)
	case "serve":
		return cmdServe(rest)
	case "status":
		return cmdStatus(rest)
	case "audit":
		return cmdAudit(rest)
	case "completions":
		return cmdCompletions(rest)
	case "help-usage":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		printUsage()
		return 2
	}
}

func printUsage() {
	fmt.Print(`cli-secret — encrypted secrets vault for your machine

Usage:
  sec <command> [flags]

Commands:
  init              Create a new vault and set the master password
  add               Store a new secret
  get               Print one secret or an entire project
  list              List secrets (optionally filter by project/tags)
  update            Replace a secret value, keeping history
  rm                Delete a secret
  rotate            Regenerate a secret with a new value
  rollback          Restore a previous version of a secret
  versions          Show the version history of a secret
  rotate-master     Change the master password
  export            Back up the vault or export a project as env/.json
  import            Import secrets from a .env or .json file
  tokens            Create, list and revoke project-scoped API tokens
  serve             Start the local HTTP API
  status            Show vault health, expiry and token info
  audit             Show the audit log
  completions       Generate shell completions (bash|zsh|fish)
  help              Show this help

Run 'sec help' or 'sec <command> --help' for details.
`)
}

const version = "0.1.0"

// loadConfig returns the config file path resolved from args/env/default.
func configPath(flag string) string {
	if flag != "" {
		return flag
	}
	if p := os.Getenv("SEC_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.toml"
	}
	return home + "/.cli-secret/config.toml"
}

var _ = config.Default
