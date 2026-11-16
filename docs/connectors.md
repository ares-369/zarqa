# Connectors

Zarqa reaches other intel platforms and services through MCP servers. A connector is one MCP
server plus a few settings in `config.yaml`. Sources with no MCP server of their own can use a
built-in [bridge](bridges.md) (STIX/TAXII 2.1, REST/OpenAPI, public web).

## Roles

Zarqa asks for a role, never a product:

| Role | Typical data |
|---|---|
| `intel_platform` | another threat intel platform or sharing server: indicators, reports, actors |
| `enrichment` | reputation, WHOIS/RDAP, DNS and passive DNS, certificates, geolocation, ASN |
| `search` | web search and page fetch |
| `vuln` | vulnerability and exploit data |
| `malware` | file and sample lookups, sandbox reports |
| `brand` | domain registrations and lookalike sources |
| `analysis` | local helpers (decoding, parsing); not a data source |

| `sharing` | where Zarqa sends intel (another platform): written to only by the sharing module, never offered to a model |
| `ticketing` | ticket systems: written to only by outputs, never offered to a model |

A connector can carry more than one role.

## Transports and auth

- `stdio`: Zarqa starts the server as a child process. The child gets only
  `PATH`, `HOME`, `LANG` and `TMPDIR` from the parent, plus the `env:` you set.
- `http`: streamable HTTP (JSON or event-stream responses; the session header is kept).

`auth.type` for `http`:

| type | settings |
|---|---|
| `none` | |
| `bearer` | `token_env` |
| `api_key` | `api_key_env`, `header` (default `X-API-Key`), optional `prefix` |
| `oauth_client_credentials` | `token_url`, `client_id`, `client_secret_env`, optional `scope`, `audience` |
| `oauth` | interactive sign-in (authorization code + PKCE); optional `client_id`, `client_secret_env`, `scope`, `redirect_port`. See below |

Secrets never go in `config.yaml`. Use `*_env` keys or `${VAR}` references to
values in `.env`; a plain-text secret is rejected at startup.

## Who may use a connector

`access: [group, "role:admin", "user:name"]` limits a connector to those people; work that read it
is then visible only to them.

## Read-only by default

For each tool, in order:

1. A match in `tools.deny` (glob) blocks it.
2. If `tools.allow` is set, anything not matching it is blocked.
3. A response or destructive action is always blocked. This covers names with
   words such as isolate, contain, quarantine, kill, terminate, delete, remove,
   purge, wipe, disable, revoke, ban, block, uninstall, shutdown, reboot, lock,
   reset or remediate, and any tool the server marks `destructiveHint`. No
   setting enables these, not even `allow_write`. Zarqa takes no response actions.
4. A tool that looks like it changes state is blocked unless the connector has
   `allow_write: true` **and** the tool is named exactly in `tools.allow`. On a
   `sharing` or `ticketing` connector it is blocked on this path whatever the
   settings: models never get write tools.

## Sending intel to another platform

A connector with the `sharing` role is where Zarqa pushes what it produced (for example a STIX
bundle). Pushes never come from a model; the sharing module sends them, with the name of the
person or schedule behind each one. A push needs all of:

- the `sharing` role,
- `allow_write: true`,
- the tool named exactly in `tools.allow`,
- not a destructive or response tool (refused whatever the config says).

```yaml
  - name: platform-out
    roles: [sharing]
    transport: http
    url: https://platform.example/mcp
    auth: {type: bearer, token_env: PLATFORM_WRITE_TOKEN}
    allow_write: true
    tools: {allow: [add_bundle]}
```

Pushes are not retried, so a write never runs twice. Each is in the audit log as `shared` or
`share_error`.

"Looks like it changes state" means the server marks it `destructiveHint` or
`readOnlyHint: false`, or its name contains a word such as delete, update,
isolate, block, run or send. Server hints are not proof, so a write-like name
is blocked even if the server says the tool is read-only. Name matching can be
wrong in both directions; use `tools.deny` for anything you are unsure of.

Zarqa refuses server-to-client requests (sampling, elicitation, roots), so a
data source cannot ask the model or the user for anything.

## Tool output is data

Every result is wrapped in `UNTRUSTED-DATA` markers with a random nonce before it
reaches a model. Copies of the marker inside the data are altered so a source
cannot close the block early. The model is told to treat the block as evidence
only. This lowers prompt-injection risk; it does not remove it.

## Retries, pacing, audit

- Each call is paced to `rate_per_min` per connector.
- A failed call is retried twice (1 s, then 2 s backoff, with a fresh
  connection), then recorded as an error.
- Every call, including blocked ones, goes to an append-only audit log
  (`data/audit.sqlite`) with redacted arguments, outcome, attempts and timing.
  Admins can read it at `/api/audit`.
- Each audit row stores a SHA-256 of the previous row's hash plus its own content.
  `GET /api/audit/verify` (admin; the Connectors page shows it) walks the chain and
  names any row that was changed or removed. Rows written before this existed are
  counted but not checked. Cutting rows off the end does not break the chain:
  note the `head` hash somewhere else if that matters to you.

## Commands

```bash
zarqa connectors                 # list
zarqa connectors test            # connect and count allowed tools
zarqa connectors tools platform  # show every tool and whether it is allowed
```

## Sign in with OAuth (browser login)

For HTTP MCP servers that ask users to sign in:

```yaml
  - name: remote-platform
    roles: [intel_platform]
    transport: http
    url: https://mcp.example.internal/mcp
    auth: {type: oauth}          # optional: client_id, client_secret_env, scope, redirect_port
```

Then run `zarqa connectors login remote-platform`. Zarqa finds the authorization server from
the MCP server's metadata, registers itself if no `client_id` is set, and opens a one-time
listener on `127.0.0.1:8765` for the sign-in to return to (PKCE S256, state checked). On a
headless server add `--manual`: open the printed URL on any device, sign in, then paste the
address the browser ended on. Tokens are stored in `data/oauth/<name>.json` (mode 600) and
refreshed automatically; sign in again when the refresh token expires.

## Tested third-party servers

Checked on 2026-11-16 against the public MCP reference servers over stdio: `everything` (9 of 13
tools allowed), `filesystem` (10 of 14; `write_file`, `edit_file`, `move_file` never allowed,
`create_directory` blocked as a write) and `memory` as a `sharing` connector with
`create_entities` allowed (the push went through the sharing path and was audited as `shared`;
`delete_entities` was refused as destructive; on the read path `create_entities` stayed blocked).
