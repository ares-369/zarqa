# Zarqa

[![CI](https://github.com/ares-369/zarqa/actions/workflows/ci.yml/badge.svg)](https://github.com/ares-369/zarqa/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10–3.12](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](pyproject.toml)

**An open-source, AI-powered threat intelligence tool.** Zarqa collects intel from the internet and
from the threat intel platforms you already use, turns it into structured, sourced intel, ranks it by
how much it matters to your organization, and answers questions about it with cited evidence.

It is not a replacement for anything. It works next to your existing platforms, reads from them, and
can send what it finds back to them in standard formats.

Named after Zarqa al-Yamama, who in Arabian legend could see an army coming days before it arrived.

> **Early development.** Zarqa is in its first build phase: the foundation (configuration, login and
> roles, model providers, background jobs, web shell, health check) works and is tested. Nothing
> collects or analyses intel yet. See the [roadmap](docs/roadmap.md) for what is planned and in what
> order. Solo-maintained.

## What it will do

Each item below is planned, not built. The roadmap tracks progress.

- **Ingest from the internet.** RSS/Atom feeds, advisories, blog and report pages, PDFs, pasted text
  and web search, on a schedule.
- **Connect to other intel platforms, both ways.** Read through MCP connectors and generic
  STIX/TAXII 2.1 and REST bridges; send results back as STIX 2.1, over TAXII or in MISP format. Writing
  is off by default and enabled per connector.
- **Turn text into structured intel.** Indicators, CVEs, threat actors, malware, ATT&CK techniques and
  the relations between them, each linked to the sentence it came from.
- **Rank by relevance.** You describe your organization (sectors, regions, products, brands); each
  item is scored against that profile, with the reason shown.
- **Investigate with evidence.** Ask a question; the analyst model plans, queries your sources, pivots,
  and answers with every claim tied to evidence. It says when the data is not enough.
- **Watch your brand.** Lookalike domains, new registrations and page checks for the brands you list.
- **Any model.** Local models through Ollama, or cloud providers, chosen per role. Prompts to cloud
  models are masked (emails, private IPs, user names and your own terms).

## Try it

```bash
pip install -e '.[dev]'          # from a checkout; PyPI comes with the first release
zarqa init                       # config.yaml, .env (mode 600) and data/ in the home folder
zarqa doctor                     # checks the setup and says what to fix
zarqa serve                      # http://127.0.0.1:8621
```

Docker: `docker compose up -d` (non-root, read-only container, loopback port).

## Configuration

`config.example.yaml` documents every setting. Secrets go in `.env` only. Login modes: none
(loopback only), basic, local, OIDC and reverse-proxy headers, with viewer, operator and admin roles.
The server refuses to listen on a network address without a login.

## Project

- Licence: Apache-2.0. No paid edition.
- [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
- [CONTRIBUTING.md](CONTRIBUTING.md) for running the tests.
- [docs/project-standard.md](docs/project-standard.md): the rules this project shares with its sibling
  projects.
