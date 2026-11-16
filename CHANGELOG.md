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
