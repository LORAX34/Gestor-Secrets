# HTTP API

The API is a local HTTP server started with `sec serve`. It binds to
`127.0.0.1:9090` by default. It is **not** meant to be exposed on a network.

## Authentication

Every request to `/v1/secrets/*` requires a project-scoped Bearer token:

```sh
curl -H "Authorization: Bearer <token>" http://127.0.0.1:9090/v1/secrets/myapp
```

Tokens are created with the CLI and only ever see their own project:

```sh
sec tokens create myapp --name ci
```

- The token is hashed (SHA-256) at rest; the raw value is shown once.
- Tokens can have an expiry (`--expires`) and be revoked (`sec tokens revoke ID`).

## Endpoints

### `GET /v1/health`

No auth. Reports service status.

```json
{ "status": "ok", "locked": false, "version": "0.1.0" }
```

### `GET /v1/secrets/{project}`

Returns all secrets of a project, decrypted.

```json
[
  {
    "id": 1,
    "project": "myapp",
    "name": "DB_PASS",
    "type": "password",
    "value": "sup3rsecret",
    "tags": ["prod"],
    "created_at": "2026-08-15T10:19:30Z",
    "updated_at": "2026-08-15T10:19:31Z",
    "version": 1
  }
]
```

### `GET /v1/secrets/{project}/{name}`

Returns a single secret as a JSON object (same shape as above).

### `POST /v1/secrets/{project}/{name}`

Creates or updates a secret. Body:

```json
{
  "value": "new-value",
  "type": "token",
  "notes": "rotated",
  "tags": ["prod", "ci"],
  "expires_at": "2027-01-01T00:00:00Z"
}
```

All fields except `value` are optional. Returns `201` when created, `200`
when updated, with the stored secret as body.

### `DELETE /v1/secrets/{project}/{name}`

Deletes a secret. Returns `204` on success.

### `POST /v1/unlock` and `POST /v1/lock`

Admin control when `auto_lock_minutes` is enabled. `unlock` accepts
`{"master_password": "..."}` and re-opens the vault; `lock` locks it.
While locked, all secret endpoints return `401`.

## Error responses

Errors are JSON with an `error` field:

```json
{ "error": "invalid or expired API token" }
```

| Status | Meaning |
|--------|---------|
| `401` | Missing/invalid token, or vault is locked |
| `403` | Token not authorized for this project |
| `404` | Project/secret not found |
| `409` | Conflict (duplicate on create) |
| `400` | Malformed body |

## Integration examples

### Shell / docker-compose

```sh
export DB_PASS=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:9090/v1/secrets/backend | jq -r '.[] | select(.name=="DB_PASS") | .value')
docker compose up -d
```

### Python

```python
import os, requests

r = requests.get(
    "http://127.0.0.1:9090/v1/secrets/backend",
    headers={"Authorization": f"Bearer {os.environ['TOKEN']}"},
)
secrets = {s["name"]: s["value"] for s in r.json()}
```

### Node.js

```js
const fetch = require("node-fetch");

const res = await fetch("http://127.0.0.1:9090/v1/secrets/backend", {
  headers: { Authorization: `Bearer ${process.env.TOKEN}` },
});
const secrets = Object.fromEntries((await res.json()).map(s => [s.name, s.value]));
```

### CI/CD

Tokens can be short-lived (`--expires`) and created per pipeline. The API is
local, so in a runner this pattern works when the vault runs on the same host
or is reachable over a private network — never expose it publicly.
