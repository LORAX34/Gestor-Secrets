# Contributing

Thanks for considering a contribution to `cli-secret`.

## Development setup

```sh
git clone <repo-url>
cd cli-secret
go build ./...
```

Requirements: Go 1.22+ (uses `golang.org/x/term`, `modernc.org/sqlite` — no CGO).

## Commands

```sh
make test        # go test ./...
make vet         # go vet ./...
make build       # build ./bin/sec
```

## Project layout

```
main.go                    entry point
internal/cli/              subcommands, prompt handling
internal/api/              local HTTP server
internal/vault/            encrypted SQLite storage
internal/crypto/           Argon2id + AES-256-GCM primitives
internal/config/           TOML configuration
docs/                      user documentation
```

## Conventions

- Follow existing style: standard library `flag`-based subcommands, no external
  CLI frameworks.
- Every public function and non-trivial method gets a doc comment.
- Keep the CLI composable and scriptable (`--json`, `--env`, stdin support).
- Add or extend tests in the package you change (`go test ./...` must pass).
- Do not add dependencies without a good reason; the project intentionally
  stays dependency-light.

## Submitting changes

1. Fork and create a branch.
2. Make the change, add tests.
3. Run `make test && make vet`.
4. Open a pull request describing the change and its motivation.

## Reporting issues

Include: `go version`, OS, the command you ran, and the full error output.
Security issues should be reported privately in the repository issues with a
`[security]` prefix.
