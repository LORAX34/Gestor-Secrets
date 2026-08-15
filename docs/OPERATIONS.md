# Operations

Practical guidance for running `cli-secret` as a DevOps engineer or operator.

## Day-to-day

```sh
# Initialize on a new machine
sec init

# Store secrets for a service
sec add backend DB_PASS "$DB_PASS" --type password --tag prod
sec add backend REDIS_URL redis://... --type text --tag prod

# Let each app consume its own namespace
sec tokens create backend --name runner --expires 2027-01-01T00:00:00Z
sec serve
```

## Backups

`sec export` creates an online SQLite backup (the file is already fully
encrypted — safe to copy anywhere). Backups are timestamped
(`vault-YYYYMMDDTHHMMSSZ.db`) and pruned to `backup.keep` newest files.

```sh
sec export                          # manual backup
crontab -e                          # nightly automatic backup
# 0 2 * * *  HOME=/home/alice /usr/local/bin/sec export >> /var/log/sec-backup.log 2>&1
```

### Restore

To restore from a backup, stop `sec serve`, replace the database file and
start again:

```sh
cp ~/.cli-secret/backups/vault-20260901T000000Z.db ~/.cli-secret/vault.db
sec serve
```

The master password is unchanged. **If you lose the master password, backups
are unrecoverable** — there is no backdoor. Keep the master password in a
password manager.

## Rotating secrets

```sh
sec rotate backend DB_PASS --random --length 32   # new value, old kept in history
sec rotate backend GITHUB_TOKEN                   # interactive, shows current value
sec rollback backend DB_PASS --version 1          # revert if something breaks
sec versions backend DB_PASS                      # inspect history
```

Rotating a secret owned by a third party (e.g. an AWS or GitHub token) must
still be done at the provider; `sec rotate` only replaces the stored value.
You can pair it with `sec status` to spot secrets nearing expiry.

## Expiration & drift

```sh
sec add backend GITHUB_TOKEN ghp_xxx --expires 2026-12-31T00:00:00Z
sec status          # warns about expired secrets
sec list --project backend
```

Recommended workflow: set `--expires` on anything with a natural lifetime and
check `sec status` (or `sec audit --json`) in your monitoring.

## Changing the master password

```sh
sec rotate-master
```

Prompts for the new password twice (or use `SEC_MASTER_NEW`). Only the wrapped
vault key is re-encrypted; all secret values stay as-is.

## Auditing

```sh
sec audit --limit 100
sec audit --json | jq -r '.[] | select(.result=="error")'
```

Every CLI and API operation is logged with actor (`cli` or `api:<project>`),
action, project, secret and result. Use it to detect unexpected access.

## Non-interactive / CI use

`SEC_MASTER` allows scripting, e.g. generating a bootstrap `.env`:

```sh
export SEC_MASTER="$(cat ~/.sec-master)"
sec get backend --env > .env
```

> Never commit `SEC_MASTER`; inject it from a CI secret store.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `error: vault not initialized` | Run `sec init` first |
| `error: vault: wrong master password` | Wrong `SEC_MASTER` or password; check `rotate-master` did not re-wrap with the old one |
| `error: vault: locked` | The API auto-locked (`auto_lock_minutes`). Call `POST /v1/unlock` |
| `connection refused` on API | `sec serve` not running, or wrong `host`/`port` in config |
| Two processes writing the vault | `cli-secret` is designed for one vault per host; stop `sec serve` before restoring backups |
| `.env` lines skipped on import | Lines without `=`, comments, or duplicate names are skipped |
