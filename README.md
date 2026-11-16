<p align="center"><img src="docs/img/logo.svg" width="120" alt="Zarqa logo"></p>

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

> **Early development, solo-maintained.** Collection, extraction, enrichment, relevance ranking,
> investigations and the connector layer work and are tested; brand monitoring and sharing are next. See the
> [roadmap](docs/roadmap.md).

## What works today

- **Collect from the internet and from other platforms.** RSS/Atom feeds (with the full article), pages,
  PDFs, indicator lists (text, CSV, JSON, STIX), and pulls from other intel platforms through MCP
  connectors or the built-in STIX/TAXII 2.1 and REST bridges. On a schedule, or by hand.
  ([collection](docs/collection.md))
- **Turn text into structured intel you can check.** Indicators (defanged or not), CVEs, ATT&CK techniques,
  threat actors, malware, tools, campaigns and targets, and the relations between them. Each one links to
  the sentence it came from and says how it was found. ([extraction](docs/extraction.md))
- **Models are checked, not trusted.** The extractor model must quote the document for every item; items
  whose quote is not in the text are dropped, and a model can label indicators but never add one. Rules
  and ATT&CK names work with no model at all.
- **Aliases resolved.** "Fancy Bear", "Sednit" and "Forest Blizzard" are one actor (APT28), from MITRE
  ATT&CK data shipped with Zarqa.
- **Ranked for you.** Describe your organization and your intelligence requirements; every report gets a
  0-100 score with the reasons (your products named, your sector targeted, known-exploited CVEs, a
  requirement answered). ([relevance](docs/relevance.md))
- **Ask, and get a cited answer.** "What do we know about this IP?" The analyst model searches the store and
  your connectors; every finding cites its evidence, unsupported claims are set aside, and "not enough data"
  is an allowed answer. ([investigations](docs/investigations.md))
- **Enrichment on request.** Connectors declare their lookups; built-in EPSS and RDAP are opt-in and never
  sent your own or internal values. ([enrichment](docs/enrichment.md))
- **Connectors, read-only by default.** Writes to another platform go only through a sharing connector
  with the exact tool allowed, never from a model, always audited. ([connectors](docs/connectors.md))
- **Any model.** Local models through Ollama, or cloud providers, per role. Prompts to cloud models are
  masked (emails, private IPs, user names and your own terms).

## Planned

Brand and lookalike-domain monitoring, sharing out (STIX 2.1, TAXII, MISP-format, MCP server),
reports and a daily brief, a demo mode and a published benchmark.

## Try it

```bash
pip install -e '.[dev]'          # from a checkout; PyPI comes with the first release
zarqa init                       # config.yaml, .env (mode 600) and data/ in the home folder
zarqa doctor                     # checks the setup and says what to fix
zarqa serve                      # http://127.0.0.1:8621

zarqa add --url https://...      # a report, extracted straight away
zarqa sources pull               # pull every source in config.yaml now
zarqa lookup 203.0.113.66        # everything known about a value, with the sentences
zarqa ask "What do we know about 203.0.113.66?"
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
