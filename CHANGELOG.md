# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Foundation: configuration (`config.yaml` + `.env`), home folder (`ZARQA_HOME` or `~/.zarqa`),
  `zarqa init | serve | doctor | version | models | users | hash-password`.
- Login modes none, basic, local, OIDC and reverse proxy, with viewer, operator and admin roles and
  identity-provider group mapping. The server refuses to listen on a network address without a login.
- Model providers per role (extractor, analyst, reporter): Ollama, Anthropic, Gemini, OpenAI, Azure
  OpenAI, OpenAI-compatible endpoints and a local model CLI, with fallbacks and rate-limit backoff.
- Privacy layer for cloud models: emails, private IPs, user names and listed terms are masked; public
  IPs are kept because they are the indicators.
- Background jobs (SQLite by default, PostgreSQL optional) and a task registry.
- Web shell: overview, jobs, settings (models with a diff before saving, model test, health check).
  Strict content security policy, no external assets, icon-font subset.
- Logo (an eye with a horizon and something on it) in the UI, login page, favicon and README.
- Connectors: MCP client (stdio and streamable HTTP; bearer, API key, OAuth client credentials and
  browser sign-in with PKCE), hub by role, read-only policy, untrusted-data wrapping, pacing, retries,
  append-only audit log with a hash chain. `zarqa connectors list|test|tools|login`, Connectors page.
- Sharing path: intel is pushed to another platform only through a `sharing` connector with
  `allow_write` and the tool named exactly; never offered to a model, never retried, always audited.
- Bridges: STIX/TAXII 2.1 (read), REST/OpenAPI (GET, POST by name only) and public web (page fetch and
  optional search with a leak guard and SSRF-safe fetching). `zarqa bridge taxii|openapi|web`.
- Collection: sources in config (RSS/Atom feeds with article fetch, pages, indicator lists in text, csv, json
  or STIX, and pulls from connectors), scheduled by the server; add text, URLs, files and indicator lists by
  hand. `zarqa sources | add | process`.
- STIX 2.x import with structure: indicators, actors, malware, tools, campaigns, CVEs, techniques, targets,
  relationships and report text.
- Knowledge store: documents, entities, mentions with the source sentence and how each was found, relations,
  expiry per indicator type, false-positive and allow-list marks. `zarqa entities | lookup | stats`.
- Extraction: rules (defang-aware indicators, private addresses and the publisher's domain dropped, CVE and
  ATT&CK IDs), ATT&CK group and campaign names with aliases, and an optional extractor model whose every item
  must quote the document; unsupported items are dropped and listed. Prompt-injection check on every document.
- ATT&CK 20.1 reference data (techniques, retired IDs, groups, software and campaigns with aliases), built by
  `scripts/build_attack_data.py`.
- UI: Overview counts, Intel feed, document page (what was found, with quotes), Entities, entity page (where
  it was found, relations, what ATT&CK knows), Add, Sources.

- Enrichment: connectors declare which tool looks up which value type (`enrich:`); built-in EPSS and RDAP
  lookups, off by default, never sent own or internal values; results cached and kept per entity; optional
  automatic enrichment of new malicious indicators with a daily cap. `zarqa enrich`.
- Relevance: organization profile and intelligence requirements; every report scored 0-100 with the reasons
  (products, brands, domains, sectors and regions named or targeted, known-exploited and likely-exploited CVEs,
  requirements matched); optional analyst-model check; documents tagged `pir:<name>`. `zarqa rescore`.

- Investigations: ask a question; the analyst model uses Zarqa's own read-only tools (lookup, search, read,
  ATT&CK, enrich) and connector tools, and every finding must cite evidence. Findings without valid evidence, or
  naming indicators not in the cited evidence, are set aside; no supported finding means not_enough_data.
  `zarqa ask`, Ask page, `/api/investigations`.

- Brand watch: lookalikes of your domains (12 techniques), optional certificate-log search, DNS and MX, RDAP
  registration age (paced), page check (brand shown, password asked, parked, redirects), 0-100 score, tracked
  findings with status and notes; lookalikes that redirect to your own domain score low. `zarqa brand`,
  Brand page, extra `dns`.

- Sharing: STIX 2.1 export (stable ids, actors with aliases, relations with their sentence, reports with
  the source link) and MISP-format events; read-only TAXII 2.1 server (`share.taxii`, optional token);
  person-initiated pushes through sharing connectors (`share.targets`, `zarqa share`); `zarqa export`.
- Zarqa as an MCP server: `zarqa mcp` and `POST /mcp` (token role viewer by default; `ask` needs operator).

- Brief (`zarqa brief`, `/api/brief`, Overview) and per-document reports, Markdown or HTML (escaped, its own
  strict content security policy).
- Demo: `zarqa demo [--run]` and `docker compose --profile demo up demo`: fictional sample data processed offline
  by a scripted stand-in for the model (labelled, not AI); UI banner. CI runs it from the wheel and the container.
- Relations from the model may end at a CVE or technique ID the rules found.

- Extraction benchmark on AnnoCTR (`benchmarks/annoctr/run.py`, results in docs/benchmarks.md).

### Fixed

- A model's name was dropped when it added a generic word the document did not use ("Groove Gang" for
  "GROOVE"); found in the benchmark.
- Investigation checks compared a claim's refanged indicator with defanged evidence text and set true claims
  aside.
- IPv4 addresses at the end of a sentence ("... 10.0.0.5.") were not found by the indicator rules.
