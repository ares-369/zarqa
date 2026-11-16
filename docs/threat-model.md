# Threat model

What Zarqa protects, from whom, and how. This page grows with each phase.

## Assets

- Credentials for connected sources and model providers (`.env`).
- What your organization profile and intel requirements say about you.
- The intel store and investigation history.

## Threats and controls (built)

| Threat | Control |
|---|---|
| Anyone on the network reads the UI | The server refuses to listen on a non-loopback address with no login, unless explicitly allowed. |
| Forged identity headers in proxy mode | Proxy mode requires `proxy_trusted_ips`; headers from other addresses are ignored. |
| A viewer changes settings | Role checks on every request: viewers read only, operators cannot change settings or connectors. |
| Secrets in config files | Secrets are read from `.env` or `${VAR}` references only; a connector with a plain token in `config.yaml` is refused. |
| Internal names sent to a cloud model | Prompts to cloud providers are masked (emails, private IPs, user names, listed terms) and unmasked in replies. |
| A connector changes or deletes data on a source | Tools are read-only by default; write-like names are blocked unless allowed by name; response and destructive tools are never called; models never get write tools. |
| Intel pushed to another platform without an owner | Sharing runs only from the sharing module, needs the sharing role, `allow_write` and the exact tool name, records who sent it, and is never retried. |
| A connector's output tells the model what to do | Results are wrapped as untrusted data with a random nonce; markers inside the data are altered. |
| A source asks the model or user for something | Server-to-client requests (sampling, elicitation, roots) are refused. |
| Tampering with the record of what was called | Append-only audit log with a SHA-256 hash chain. |
| Internal names sent to the web | The web bridge refuses queries with private IPs, emails or listed internal terms. |
| Server-side request forgery through a URL | Only http(s); private, loopback, link-local and reserved addresses refused on every redirect hop; the checked address is pinned. |
| Own or internal values sent to a public lookup service | Built-in enrichers refuse internal addresses, `privacy.terms`, `privacy.patterns` and `organization.domains`; they are off by default. |
| A feed's API key sent to another host | `headers_env` headers are not sent after a redirect to a different host. |
| Script injection through collected content | The UI sets text with `textContent` only and has a strict content security policy with no inline scripts. |

| Prompt injection in collected pages and reports | Document text reaches a model only inside untrusted-data markers; every document is scanned for text addressing an AI and marked for review; models cannot add indicators and every item they return must quote the document. |

| Brand watch fetches attacker pages | The safe fetcher (no scripts run, private addresses refused, size cap); turn off with `brand.page_check: false`. |
| A model states something no source says | Investigation findings must cite successful evidence, and indicators named in a finding must be in that evidence; the rest is set aside and listed. |

## Threats planned for later phases

- Sharing (phase 9) will add its own rows here.
