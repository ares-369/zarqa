# Bridges

A bridge is a small MCP server, built into Zarqa, for a source that has no MCP
server of its own. A connector starts it with `command: zarqa` and
`args: [bridge, <kind>, ...]`. Credentials reach the bridge only through the
connector's `env:`:

| Variable | Use |
|---|---|
| `BRIDGE_TOKEN` | `Authorization: Bearer ...` |
| `BRIDGE_API_KEY` | API key, sent in `BRIDGE_API_KEY_HEADER` (default `Authorization`), with optional `BRIDGE_API_KEY_PREFIX` |
| `BRIDGE_USERNAME` / `BRIDGE_PASSWORD` | HTTP Basic |

Every bridge accepts `--insecure` (skip TLS checks, lab only) and `--ca-bundle`.

## taxii

For a STIX/TAXII 2.1 API root.

```yaml
- name: sharing-server
  roles: [intel_platform]
  transport: stdio
  command: zarqa
  args: [bridge, taxii, --url, "${TAXII_ROOT}"]
  env: { BRIDGE_USERNAME: "${TAXII_USER}", BRIDGE_PASSWORD: "${TAXII_PASS}" }
```

Tools: `list_collections`, `get_objects`, `get_object`, `find_indicator`.
`find_indicator` pages through indicators (at most `--max-pages`) and matches
the value as a substring of the STIX pattern or name, so it can return near
matches and is slow on very large collections.

## openapi

Turns an OpenAPI 3 document into tools.

```yaml
- name: reputation
  roles: [enrichment]
  transport: stdio
  command: zarqa
  args: [bridge, openapi, --spec, "${REP_API}/openapi.json", --include, "get*", --include, "lookup*"]
  env: { BRIDGE_API_KEY: "${REP_KEY}", BRIDGE_API_KEY_HEADER: "X-API-Key" }
```

- Every `GET` operation becomes a tool, filtered by `--include`/`--exclude`
  (globs on operationId or path).
- A `POST` operation is exposed only when named with `--allow-post <operationId>`.
  This is for APIs whose searches are POST requests. Name only operations that read.
- `PUT`, `PATCH` and `DELETE` are never exposed.
- Path values are URL-encoded, so a value cannot change the path.
- At most `--max-tools` (default 150) operations; narrow large specs with `--include`.

The connector's own read-only policy still applies on top of all of this.

## web

Public web lookups: `fetch_page` (a page or PDF as text) and, with `--search-url`, `search_web` against
a search service with a JSON API (`GET <url>?q=...&format=json` returning `results` with `title`,
`url` and `content`). Turn it on with:

```yaml
web:
  tools: true
  search_url: ""        # optional
```

It is added as the built-in connector `web` (role `search`).

- **Leak guard.** Queries and URLs are refused if they hold a private or internal IP address, an
  email address, or any `privacy.terms` / `privacy.patterns` value.
- **Safe fetching.** Only http(s); every redirect hop is checked; hosts that resolve to private,
  loopback, link-local or reserved addresses are refused, and the checked address is pinned for the
  request so DNS cannot be swapped in between.
