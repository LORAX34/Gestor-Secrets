# Commands

All commands accept `--config <path>` to use a non-default config file
(default: `~/.cli-secret/config.toml`, or `$SEC_CONFIG`). The master password
can be supplied non-interactively via the `SEC_MASTER` environment variable.

Legend: `PROJECT` = a namespace, `NAME` = a secret key, `VALUE` = the secret value.

## Global flags

| Flag | Env var | Description |
|------|---------|-------------|
| `--config PATH` | `SEC_CONFIG` | Path to the TOML config file |
| — | `SEC_MASTER` | Master password for non-interactive use |
| — | `SEC_MASTER_NEW` | New master password for `rotate-master` |

## init

```sh
sec init [--config PATH]
```

Creates a new vault, prompts for a master password (twice) and writes the
config file. Only the first invocation creates the vault; subsequent calls fail.

## add

```sh
sec add PROJECT NAME VALUE [--type TYPE] [--tag TAG] [--notes NOTES] [--expires DATE]
```

Stores a new secret. Use `VALUE=-` to read the value from stdin.

- `--type` — `text` (default), `password`, `token`, `ssh_key`, `generic`.
- `--tag` — repeatable, e.g. `--tag prod --tag ci`.
- `--expires` — RFC3339 date (e.g. `2026-09-01T00:00:00Z`).

```sh
sec add myapp DB_PASS secret123 --type password --tag prod
sec add myapp TLS_KEY - < ./id_rsa --type ssh_key
```

## get

```sh
sec get PROJECT [NAME] [--env] [--json]
```

With `NAME`, prints the plaintext value (ready to pipe). Without `NAME`,
prints all secrets of the project.

- `--env` — print `NAME=VALUE` lines (useful for docker-compose / shell).
- `--json` — print machine-readable JSON.

```sh
sec get myapp DB_PASS
DB_PASS=$(sec get myapp DB_PASS)
sec get myapp --env
sec get myapp --json | jq -r '.[] | select(.name=="GITHUB_TOKEN") | .value'
```

## list

```sh
sec list [--project P] [--tags t1,t2] [--json]
```

Lists secrets without values.

```sh
sec list
sec list --project myapp
sec list --tags prod
```

## update

```sh
sec update PROJECT NAME VALUE
```

Replaces the value and records the previous version.

## rm

```sh
sec rm PROJECT NAME [--force]
```

Deletes a secret and its history. Asks for confirmation unless `--force`.

## rotate

```sh
sec rotate PROJECT NAME [--random] [--length N]
```

Regenerates a secret with a new value. Without `--random`, prompts for the new
value and shows the current one. With `--random`, generates `N` random bytes
(default 32), base64-encoded. The old value is preserved in history.

## rollback

```sh
sec rollback PROJECT NAME --version N
```

Restores a previous version of a secret (see `sec versions`).

## versions

```sh
sec versions PROJECT NAME
```

Shows the version history of a secret with values.

## rotate-master

```sh
sec rotate-master
```

Changes the master password. Prompts for the new password (or uses
`SEC_MASTER_NEW`). Re-wraps the vault key; existing secrets are not
re-encrypted.

## tokens

```sh
sec tokens create PROJECT [--name NAME] [--expires DATE]
sec tokens list [--project P] [--json]
sec tokens revoke ID
```

Create, list and revoke project-scoped API tokens. The raw token is printed
exactly once at creation.

```sh
sec tokens create myapp --name ci --expires 2027-01-01T00:00:00Z
sec tokens list
sec tokens revoke 3
```

## serve

```sh
sec serve [--host H] [--port N] [--config PATH]
```

Starts the local HTTP API (default `127.0.0.1:9090`). The vault is unlocked
once at startup and kept in memory. See [API.md](API.md).

## status

```sh
sec status [--json]
```

Shows vault health: path, initialized state, secret/token/audit counts, backup
directory and last backup, plus warnings for expired secrets.

## audit

```sh
sec audit [--limit N] [--json]
```

Shows recent audit log entries (default 50).

## export

```sh
sec export                                    # encrypted backup (SQLite copy)
sec export --project P --env [--out FILE]     # plaintext env export
sec export --project P --json [--out FILE]    # plaintext JSON export
```

Backups land in the configured backup directory with retention pruning
(`keep` newest). See [OPERATIONS.md](OPERATIONS.md).

## import

```sh
sec import FILE --project P [--type TYPE]
```

Imports secrets from a `.env` (`KEY=VALUE` lines) or `.json`
(`{"KEY":"value"}`) file. Existing names are skipped.

## completions

```sh
sec completions bash
sec completions zsh
sec completions fish
```

Prints a completion script to stdout. Example for bash:

```sh
source <(sec completions bash)
```

## help / version

```sh
sec help
sec version
```
