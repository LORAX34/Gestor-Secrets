# Threat model

This document describes what `cli-secret` protects against, and — just as
importantly — what it does **not** protect against. Read it before deploying
this tool for anything beyond personal use.

## Assets

- Secret values (API keys, passwords, tokens, keys).
- The master password.
- The audit log (metadata only).

## What it protects against

1. **Theft of the vault file.** The SQLite database contains only ciphertext
   (per-value AES-256-GCM) plus a wrapped vault key and an Argon2id salt.
   Without the master password it is computationally infeasible to recover
   values, assuming the master password has sufficient entropy.
2. **Idle reading of the database.** Nothing plaintext is written to disk at
   any point; values are only decrypted in memory on demand.
3. **Network exposure of the API.** By default the server binds to
   `127.0.0.1`. Tokens are project-scoped, so one leaked token cannot read
   other projects' secrets, and a token alone does not decrypt the vault file
   (the master password still gates the CLI).
4. **Casual inspection.** Unauthorized users without the master password and
   without a token cannot obtain values.

## What it does NOT protect against

1. **A compromised account on the machine.** Anyone with your OS user can run
   `sec` after you unlock, read `SEC_MASTER`, or install a keylogger. The API
   process holds the vault key in memory while serving. This is a **local
   machine** trust model: the vault is as secure as the session it runs in.
2. **Keyloggers / screen scrapers.** The master password is typed locally.
3. **Malware running as your user.** It can read memory, the API responses,
   and prompt you for the password. `cli-secret` adds no protection here.
4. **Loss of the master password.** There is no recovery path. Backups are
   encrypted with the same master password and are equally unrecoverable.
5. **Tampering with the vault file.** There is no authenticated integrity
   check against a trusted value stored outside the file (defense in depth via
   AES-GCM authenticates each value, but a determined attacker with write
   access could delete or replace the whole vault).
6. **Timing/side-channel attacks** on the local API. The API is plain HTTP and
   intended for trusted local processes; tokens can be sniffed by processes
   with root or by other users if the host is shared.
7. **Third-party secret rotation.** `sec rotate` only changes the stored
   value; it cannot rotate a secret that a provider (AWS, GitHub, ...) owns.

## Recommended hardening

- Use a strong, unique master password and store it in a password manager.
- Do not set `SEC_MASTER` in your interactive shell; only use it in isolated
  CI/script contexts.
- Keep `host = "127.0.0.1"`; if you must expose the API, put it behind TLS and
  network policy, and enable `auto_lock_minutes`.
- Run backups to a different volume and keep them encrypted (they already are).
- If the host is shared, prefer running `sec serve` under a dedicated user
  with `auto_lock_minutes > 0`.

## FAQ

**Can I use this as a team vault?** Not really. It is single-user, single-host
by design. For shared/team secrets consider a server-based tool.

**Is the database "encrypted" if someone copies it?** Yes. All values are
ciphertext; the wrapped key is useless without the master password.

**Does the API use TLS?** No, by default. It listens on localhost. If exposed,
terminate TLS at a reverse proxy.
