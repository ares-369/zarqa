# Sharing

Zarqa works next to your other platforms: it can hand them what it found in standard formats, serve it for
them to pull, or push it to them when a person decides to.

## Exports (always available)

| Format | UI | CLI | API |
|---|---|---|---|
| STIX 2.1 bundle | document page: STIX | `zarqa export stix [--document ID \| --entity ID ... \| --since ISO --type T]` | `GET /api/export/stix?document=ID` (or `entities=1,2`, `since=`, `types=`, `min_confidence=`) |
| MISP-format event (JSON) | document page: MISP format | `zarqa export misp --document ID` | `GET /api/export/misp?document=ID` |

STIX object ids are derived from content, so the same indicator exported twice has the same id. Indicators
become `indicator` objects, actors `intrusion-set` (with ATT&CK aliases), malware, tools, campaigns, CVEs
(`vulnerability`), techniques (`attack-pattern`), targeted sectors and countries, relations as `relationship`
objects with the sentence that states them, and a document as a `report` with its URL. Indicators labelled
benign, victim or reference in every mention, and entities marked false positive, allow-listed or expired, are
left out. Zarqa reads its own STIX back without loss of the parts above.

The MISP-format event holds indicators and CVEs as attributes (CVEs with `to_ids` false), the source link, and
actors, malware, tools, campaigns and techniques as tags.

## TAXII 2.1 server (read-only)

```yaml
share:
  taxii: true
  taxii_token_env: ZARQA_TAXII_TOKEN     # in .env; platforms send Authorization: Bearer <token>
```

`/taxii2/` (discovery), API root `/taxii2/zarqa/`, collections `Indicators` and `Intel`, objects with
`added_after`, `limit`, `next` and `match[type]`. Behind the normal login, or the token, which is valid for
TAXII only. Nothing can be written.

## Pushing to another platform

A push goes through a connector with the `sharing` role (see [connectors](connectors.md)):

```yaml
connectors:
  - name: platform-out
    roles: [sharing]
    transport: http
    url: https://platform.example/mcp
    auth: {type: bearer, token_env: PLATFORM_WRITE_TOKEN}
    allow_write: true
    tools: {allow: [add_bundle]}
share:
  targets:
    - {name: platform, connector: platform-out, tool: add_bundle, argument: bundle, format: stix}
```

A person with the operator role chooses what to send (the Share button on a document, `zarqa share platform
--document ID`, `POST /api/share`). The push is never made by a model, never retried, and recorded in the audit
log as `shared` with who sent it.

## Zarqa as an MCP server

`zarqa mcp` (stdio) or `POST /mcp` (behind the login, or a bearer token from `mcp.token_env`, role
`mcp.token_role`, default viewer). Tools: `lookup`, `search_entities`, `search_documents`, `read_document`,
`attack_info`, `get_investigation`, `brand_findings`, `export_stix` (read), and `ask` (starts an investigation;
operator role, and marked as not read-only, so read-only consumers block it unless they allow it). Collected text
is returned inside untrusted-data markers.

## Tested

On 2026-11-17, Zarqa to Zarqa: a second instance pulled 199 indicators from the first one's TAXII server through
the built-in TAXII bridge (bearer token), and looked a value up in it through `zarqa mcp` over stdio; its
read-only policy allowed 8 of 9 tools and blocked `ask`.
