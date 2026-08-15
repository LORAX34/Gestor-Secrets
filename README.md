# cli-secret

Encrypted secrets vault for your machine, written in Go. Store API keys, tokens and passwords per project, serve them to your own apps over a local HTTP API, and keep everything encrypted with a single master password.

> A personal, self-hosted alternative for keeping secrets near your projects — nothing is stored in the cloud.

## Features

- **Encrypted at rest** — AES-256-GCM values, Argon2id master password, and a wrapped random vault key (rotating the master password does not re-encrypt every secret).
- **Project namespaces** — secrets are grouped by project.
- **Local HTTP API** — your apps consume secrets from `127.0.0.1` using scoped Bearer tokens; each token only sees its own project.
- **Version history** — `update`, `rotate` and `rollback` without losing data.
- **Expiration** — set `--expires` per secret; `sec status` warns about expired entries.
- **Audit log** — every access is recorded with actor, action and result.
- **Backups** — online SQLite backup with retention pruning.
- **Import/export** — `.env` and `.json` import; env/JSON project export; shell completions for bash/zsh/fish.
- **Auto-lock** — optional idle timeout that re-locks the API.
- **No CGO** — pure Go binary, cross-compiles trivially.

## Install

```sh
go install github.com/ivanperez/cli-secret@latest
```

or build from source:

```sh
git clone <repo-url>
cd cli-secret
make build        # produces ./bin/sec
```

The binary is `sec`.

## Quickstart

```sh
sec init                     # creates ~/.cli-secret, asks for a master password
sec add myapp DB_PASS sup3rsecret --type password
sec add myapp GITHUB_TOKEN ghp_xxx --type token
sec get myapp DB_PASS        # prints the value (asks for master password)
sec list
sec serve                    # starts the local API on 127.0.0.1:9090
sec tokens create myapp      # prints a project-scoped token
curl -H "Authorization: Bearer <token>" http://127.0.0.1:9090/v1/secrets/myapp
```

## Documentation

- [Commands](docs/COMMANDS.md) — every subcommand with examples.
- [Configuration](docs/CONFIG.md) — `config.toml` reference.
- [HTTP API](docs/API.md) — endpoints, auth, curl examples, integrations.
- [Architecture](docs/ARCHITECTURE.md) — crypto and storage design.
- [Operations](docs/OPERATIONS.md) — backups, rotation, expiry, troubleshooting.
- [Threat model](docs/THREAT_MODEL.md) — what this protects against, and what it does not.

## Development

```sh
make test       # go test ./...
make vet        # go vet ./...
make build      # build ./bin/sec
```

The project is fully tested (`internal/crypto`, `internal/vault`, `internal/api`, `internal/config`). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security notes

- The master password is never stored. It is derived with Argon2id at unlock time.
- All secret values are encrypted with AES-256-GCM before touching disk.
- The API binds to `127.0.0.1` by default and is not exposed to the network.
- Read the [threat model](docs/THREAT_MODEL.md) before using this in production.

## License

[MIT](LICENSE)
