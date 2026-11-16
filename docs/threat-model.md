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
| Script injection through collected content | The UI sets text with `textContent` only and has a strict content security policy with no inline scripts. |

## Threats planned for later phases

- Prompt injection in collected pages and reports (content will be marked as untrusted data, and
  checked for injection patterns before it reaches a model).
- Server-side request forgery through URL import (private addresses and redirects will be refused).
- A connector writing to another platform without permission (writes off by default, per-connector
  allow list).
