# Configuration

`cli-secret` uses a single TOML config file, written by `sec init`.
Default location: `~/.cli-secret/config.toml`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `db_path` | string | `~/.cli-secret/vault.db` | Path to the encrypted SQLite database |
| `host` | string | `127.0.0.1` | Bind address for the HTTP API |
| `port` | int | `9090` | Port for the HTTP API |
| `auto_lock_minutes` | int | `0` | Idle minutes before the API re-locks (`0` = disabled) |
| `backup.enabled` | bool | `true` | Enable backup retention pruning |
| `backup.dir` | string | `~/.cli-secret/backups` | Directory for `sec export` backups |
| `backup.keep` | int | `10` | Number of backups to keep |

## Example

```toml
db_path = "/home/alice/.cli-secret/vault.db"
host = "127.0.0.1"
port = 9090
auto_lock_minutes = 0

[backup]
  enabled = true
  dir = "/home/alice/.cli-secret/backups"
  keep = 10
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SEC_CONFIG` | Alternate config file path |
| `SEC_MASTER` | Master password for non-interactive CLI use (e.g. CI) |
| `SEC_MASTER_NEW` | New master password when calling `sec rotate-master` |

> Use `SEC_MASTER` with care: it bypasses the interactive prompt. In CI
> pipelines prefer to inject it from a secret store, not commit it.

## Argon2id parameters

The KDF parameters are stored in the vault's `meta` table when it is created
(currently the defaults: `time=3`, `memory=64 MiB`, `threads=2`, `key=32`).
They apply to the whole vault and cannot be changed per-secret.
