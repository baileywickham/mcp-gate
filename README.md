# mcp-gate

A single-user **OAuth 2.1 authorization server and reverse proxy** for remote MCP
servers. Put it in front of MCP endpoints that only speak bearer tokens (or nothing),
and clients that insist on OAuth — claude.ai custom connectors, Claude Code, the
MCP Inspector — get a real login flow: discovery, dynamic client registration, PKCE,
refresh tokens. You get a password prompt once per client.

Built on the auth handlers in `@modelcontextprotocol/sdk`; the custom part is small
and **stateless**: client ids, authorization codes and tokens are all signed JWTs, so
there is no database and restarts lose nothing.

```
client ──OAuth──▶ mcp-gate ──Bearer <upstream token>──▶ http://mcp-on-the-lan/mcp
                  https://gate.example.com/<name>/mcp
```

## Run

Environment:

| Var | Meaning |
|---|---|
| `MCP_GATE_ISSUER` | Public base URL, e.g. `https://apple.lxpr.org` |
| `MCP_GATE_PASSWORD` | The one login password (≥ 12 chars) |
| `MCP_GATE_SIGNING_KEY` | HS256 key for all tokens (≥ 32 chars, e.g. `openssl rand -hex 32`) |
| `MCP_GATE_UPSTREAMS` | JSON: `{"apple": {"url": "http://192.168.0.50:8000/mcp", "token": "…"}}` |
| `PORT` | default 8080 |
| `MCP_GATE_SERVICE_TOKENS` | Optional. Comma-separated long-lived bearer tokens (≥ 32 chars each, e.g. `openssl rand -base64 36`) for non-interactive callers — scripts and cloud routines that cannot do the OAuth login. Each is accepted in place of an access token on `/<name>/mcp` and is revoked on its own by removing it here; the OAuth flow is unaffected. |
| `MCP_GATE_ACCESS_TTL` / `MCP_GATE_REFRESH_TTL` | seconds; default 1 h / 30 d |

```sh
bun install
MCP_GATE_ISSUER=http://localhost:8080 MCP_GATE_PASSWORD=… MCP_GATE_SIGNING_KEY=… \
MCP_GATE_UPSTREAMS='{"apple":{"url":"http://192.168.0.50:8000/mcp","token":"…"}}' bun src/index.ts
```

Each upstream is served at `/<name>/mcp`. Add `https://<issuer>/<name>/mcp` to your
client; it discovers `/.well-known/oauth-protected-resource/<name>/mcp`, registers
itself, sends you to the password page, and is done.

Endpoints: `/authorize`, `/token`, `/register`, `/login`, `/.well-known/*`, `/healthz`.

## Security notes

- One password, one user. Five wrong attempts lock an IP for 15 minutes.
- All clients are public clients with mandatory PKCE (S256); no client secrets exist.
- Codes live 5 minutes and are single-use for the life of the process; access tokens
  1 hour; refresh tokens 30 days. Rotate everything by changing the signing key.
- Run it behind TLS. It trusts `X-Forwarded-*` from the proxy in front.

## Development

`bun test` runs an end-to-end flow against a fake upstream. `bun run typecheck`.
Image: `ghcr.io/baileywickham/mcp-gate` (built by the workflow on push to main).
