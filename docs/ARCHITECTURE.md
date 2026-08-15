# Architecture

`cli-secret` is a single binary with four layers:

```
main.go
├── internal/cli      command parsing, prompting, orchestration
│   ├── internal/api  local HTTP server (127.0.0.1)
│   └── internal/vault  encrypted SQLite storage + crypto operations
│       └── internal/crypto  Argon2id + AES-256-GCM
└── internal/config   TOML config load/save
```

## Cryptographic design

The goal is that nothing plaintext ever touches disk, and rotating the master
password should not require re-encrypting every secret.

```
Master password
      │  Argon2id
      ▼
      KEK ──► wraps ──► random Vault Key (VK)
                             │
   each secret value ────────┴──► AES-256-GCM (nonce || ciphertext)
```

- The **master password** is never stored. Argon2id derives the KEK.
- A random 32-byte **vault key (VK)** encrypts every value with AES-256-GCM
  (unique 12-byte nonce per value).
- Only the **wrapped VK** is stored in the `meta` table, along with the Argon2id
  salt and parameters.
- `sec rotate-master` generates a new salt + KEK and re-wraps the same VK —
  fast, and existing secrets are untouched.

## Storage

SQLite (pure Go driver, `modernc.org/sqlite`, no CGO), WAL mode.

### Tables

| Table | Purpose |
|-------|---------|
| `meta` | Schema version, KDF (`argon2id`), salt, params, wrapped VK |
| `secrets` | `project`, `name`, `type`, `value_enc`, `notes`, `tags`, timestamps, `expires_at`, `version`; unique `(project, name)` |
| `versions` | Previous `value_enc` snapshots per secret (history / rollback) |
| `api_tokens` | `project`, `name`, `token_hash` (SHA-256 of the raw token), `expires_at`, `last_used` |
| `audit_log` | Timestamped records of every operation: actor, action, project, secret, result |

### Concurrency

The vault serializes access with a mutex and `db.SetMaxOpenConns(1)`.
Decryption happens inline while scanning rows (no nested queries), so single
connection constraints never deadlock. The API keeps one unlocked vault in
memory; the CLI opens/unlocks per invocation.

## API

- Bearer tokens are hashed and scoped to a project; the server rejects any
  request for another project with `403`.
- `auto_lock_minutes` (config) re-locks the in-memory vault after idle time;
  secret endpoints then return `401` until `POST /v1/unlock` with the master
  password.
- The server binds to `127.0.0.1` by default.

## Design decisions

- **SQLite over a JSON file**: queries for projects/expiry/history, atomic
  updates, and online backups.
- **Project namespaces over a flat list**: matches how secrets are consumed per
  application and enables per-project tokens.
- **Per-value encryption over whole-file encryption**: lets the API decrypt only
  what it returns and keeps rotation cheap.
- **Versioning**: `update`/`rotate` move the previous ciphertext to `versions`
  so rollbacks do not require the old plaintext.
