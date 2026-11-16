# Security

## Reporting a vulnerability

Please report vulnerabilities privately, through the repository's
[private security advisory](https://github.com/ares-369/zarqa/security/advisories/new) feature, not in
a public issue. Include steps to reproduce and the version or commit.

Zarqa is maintained by one person in spare time, so responses are best-effort: I aim to acknowledge a
report within a week and keep you updated on a fix. Reporters are credited in the changelog unless they
prefer otherwise.

## Supported versions

Zarqa is beta software. Fixes go into the latest release only.

## More

- [docs/threat-model.md](docs/threat-model.md): what it tries to protect, and how.
- [docs/known-limitations.md](docs/known-limitations.md): known gaps.

Deployment advice:

- Give every connector a read-only account on its source.
- Keep `bind_host: 127.0.0.1` unless a login mode is set.
- Use `auth.mode: proxy` only with `proxy_trusted_ips`.
- Keep `.env` readable only by the service user.
