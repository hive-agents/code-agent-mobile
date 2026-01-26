# claude-agent-mobile

Mobile-first web UI for Claude Code data using Claude Agent SDK with a WebSocket backend.

![cam0](https://github.com/user-attachments/assets/425bcfe0-ee56-4f03-852f-b570e14e3c0c)

![cam1](https://github.com/user-attachments/assets/48903685-c36d-4a2a-a3bd-5bb74025c410)

<img width="1179" height="2556" alt="cam2" src="https://github.com/user-attachments/assets/aabda5b8-eb08-49d0-ae86-02e7cc081571" />


## Setup

```bash
npm install
```

## Run (dev)

```bash
npm run dev
```

The backend listens on `ws://localhost:8787/cam-ws` by default.
The dev server uses `tsc --watch` plus `node --watch` for the backend.

## Run (prod)

```bash
npm run build
node server/dist/index.js
```

Serve `dist/` with nginx or similar. Set `VITE_WS_URL` at build time to point to your production WebSocket URL.

If you run the backend behind a reverse proxy, ensure the proxy forwards:
- WebSocket path (default `/cam-ws`)
- Auth endpoints (`/cam-auth/status`, `/cam-login`, `/cam-logout`) or custom paths if you override them.

## Environment

- `ANTHROPIC_API_KEY`: optional if you have Claude OAuth already configured; otherwise required to send prompts.
- `ANTHROPIC_MODEL`: optional, defaults to `claude-sonnet-4-5-20250929`.
- `CLAUDE_HOME`: optional override for `~/.claude`.
- `CAM_MOBILE_PORT`: optional override for the WebSocket port.
- `CAM_MOBILE_WS_PATH`: optional override for the WebSocket path (defaults to `/cam-ws`).
- `CAM_MOBILE_ROOT`: optional root directory for the project picker (defaults to your home directory).
- `CAM_MOBILE_SHOW_HIDDEN`: set to `1` to show hidden folders in the picker.
- `VITE_WS_URL`: optional override for the frontend WebSocket URL.
- `VITE_HTTP_URL`: optional override for the frontend HTTP base URL used for auth endpoints.

## Auth (builtin + external)

Auth is enforced on the WebSocket upgrade using a session cookie. There are three modes:

- `CAM_AUTH_MODE=off`: allow all connections (local dev).
- `CAM_AUTH_MODE=builtin`: show the password modal; `/cam-login` issues a session cookie.
- `CAM_AUTH_MODE=external`: accept a host-provided cookie and verify it with an auth endpoint.

Builtin mode expects a bcrypt hash, and the client sends a bcrypt-hashed password over TLS.

Required env for builtin:
- `CAM_AUTH_PASSWORD_BCRYPT`: bcrypt hash of the password.
- `CAM_AUTH_SIGNING_SECRET`: HMAC secret used to sign the session cookie.

Note: wrap bcrypt hashes in quotes when exporting in a shell, because they contain `$`.

Optional env:
- `CAM_AUTH_COOKIE_NAME`: cookie name (default `cam_session`).
- `CAM_AUTH_COOKIE_TTL_SECONDS`: session TTL seconds (default 30 days).
- `CAM_AUTH_COOKIE_SECURE`: set `true` when using HTTPS.
- `CAM_AUTH_LOGIN_PATH`: login endpoint (default `/cam-login`).
- `CAM_AUTH_LOGOUT_PATH`: logout endpoint (default `/cam-logout`).
- `CAM_AUTH_STATUS_PATH`: status endpoint (default `/cam-auth/status`).
- `CAM_AUTH_EXTERNAL_SIGNING_SECRET`: if set, external mode verifies the cookie signature.
- `CAM_AUTH_EXTERNAL_VERIFY_URL`: required in external mode; e.g. `https://apiary.host/api/me`.
- `CAM_AUTH_EXTERNAL_VERIFY_TIMEOUT_MS`: request timeout in ms (default `5000`).
- `CAM_AUTH_CORS_ORIGIN`: comma-separated list or `*` to allow cross-origin auth requests.

Generate a bcrypt hash:

```bash
node -e "const bcrypt=require('bcryptjs'); console.log(bcrypt.hashSync('your-password', 10))"
```

If login fails on a hosted setup, double-check that your reverse proxy exposes `/cam-login` and `/cam-auth/status` in addition to the WebSocket path.

### Example configurations

1) Localhost (no auth)

```bash
CAM_AUTH_MODE=off
```

2) VPS self-hosted (builtin cookie auth)

```bash
CAM_AUTH_MODE=builtin
CAM_AUTH_PASSWORD_BCRYPT="$2a$10$...your bcrypt hash..."
CAM_AUTH_SIGNING_SECRET="replace-with-random-secret"
CAM_AUTH_COOKIE_SECURE=true
```

3) Hosted (external auth cookie from hosting service)

```bash
CAM_AUTH_MODE=external
CAM_AUTH_COOKIE_NAME="cam_session"
CAM_AUTH_EXTERNAL_SIGNING_SECRET="shared-secret-from-host" # optional
CAM_AUTH_EXTERNAL_VERIFY_URL="https://apiary.host/api/me"
```
