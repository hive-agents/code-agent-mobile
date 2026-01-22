# claude-agent-mobile

Mobile-first web UI for Claude Code data using Claude Agent SDK with a WebSocket backend.

## Setup

```bash
npm install
```

## Run (dev)

```bash
npm run dev
```

The backend listens on `ws://localhost:8787` by default.
The dev server uses `tsc --watch` plus `node --watch` for the backend.

## Environment

- `ANTHROPIC_API_KEY`: optional if you have Claude OAuth already configured; otherwise required to send prompts.
- `ANTHROPIC_MODEL`: optional, defaults to `claude-sonnet-4-5-20250929`.
- `CLAUDE_HOME`: optional override for `~/.claude`.
- `CC_MOBILE_PORT`: optional override for the WebSocket port.
- `CC_MOBILE_ROOT`: optional root directory for the project picker (defaults to your home directory).
- `CC_MOBILE_SHOW_HIDDEN`: set to `1` to show hidden folders in the picker.
- `VITE_WS_URL`: optional override for the frontend WebSocket URL.
