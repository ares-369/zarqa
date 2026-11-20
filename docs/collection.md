# Collection

Zarqa collects from the internet, from other intel platforms, and from what people add by hand. Each item
becomes a **document**, stored once (by content), then [extracted](extraction.md).

## Built-in sources (on by default)

Zarqa ships with about 30 well-known public sources, so a fresh install starts collecting without any setup
(`zarqa sources` lists them; the list is `zarqa/collect/catalog.yaml`):

| Category | Sources | Reliability |
|---|---|---|
| government | national CERT and cyber-agency advisories (US, UK, Canada, EU, Australia) | B |
| research | research teams and incident responders: SANS ISC, Talos, Unit 42, Microsoft, Google Threat Intelligence, Securelist, ESET, Check Point, SentinelLabs, The DFIR Report, Huntress, Sophos, Volexity, Proofpoint (B); Malwarebytes, Recorded Future (C) | B/C |
| news | BleepingComputer, The Hacker News, SecurityWeek, The Record, Dark Reading, Krebs on Security, Help Net Security | C |
| lists | CISA known-exploited vulnerabilities (A, tags CVEs `kev`), abuse.ch Feodo Tracker botnet C2 addresses (B, CC0), Emerging Threats compromised hosts (C) | A-C |

Turn them off:

```yaml
default_sources:
  enabled: false              # every built-in source off (air-gapped installs, or only your own feeds)
  disable: [recorded-future]  # or single ones by name
```

or `zarqa sources disable --all`, `zarqa sources disable talos unit42`, `zarqa sources enable talos`, or the switches on
the Sources page (admins). A source of your own with the same name replaces the built-in one (for example to change
its interval or reliability); `enabled: false` switches one of your own off. A switched-off source can still be
pulled by hand. The reliability letters are a starting point: change them to your own judgement. The demo has no
built-in sources.

All built-in URLs were checked reachable on 2026-11-17. Some publishers refuse some networks (one advisory feed
returned 403 from one of our test addresses and worked from another): `zarqa sources` shows the last error.

## Your own sources

Listed under `sources:` in `config.yaml`. Pulled every `interval_minutes` by the server's scheduler
(`0` = only by hand), or now with `zarqa sources pull [NAME]` or the Sources page.

| Kind | What it reads | Settings |
|---|---|---|
| `feed` | RSS 2.0 or Atom. Each new item's article is fetched too (`fetch_articles`). Items are remembered by link. | `url`, `max_items` (20), `keywords`, `fetch_articles` |
| `page` | One page or PDF, stored again only when its text changes. | `url`, `keywords` |
| `list` | Indicator lists: `text` (one per line), `csv`, `json` or `stix`. | `url`, `format`, `type`, `value_field`, `list_key`, `context` (default `malicious`), `max_items`, `headers_env` |
| `connector` | Calls a tool on a [connector](connectors.md). STIX in the result is imported with its structure; other text becomes a document. | `connector`, `tool`, `arguments` |

Every source can also set `tags` and `confidence` (0-100, default 50; lists 50, STIX 60).

`headers_env` sends a header whose value comes from `.env`, for feeds that need a key:
`headers_env: {X-API-Key: FEED_KEY}`. The header is not sent again if the feed redirects to another host.

## Safe fetching

- http(s) only.
- Hosts that resolve to private, loopback, link-local or reserved addresses are refused, on every redirect
  hop; the checked address is pinned for the request so DNS cannot be switched in between.
  `collect.allow_private_urls: true` allows feeds on your own network.
- At most 15 MB per response and 200,000 characters of text per document (`collect.max_document_chars`).
- Feeds that declare a DOCTYPE or XML entities are refused.

## Article text

When a feed item links to an article, Zarqa reads the page and keeps the article text. Page furniture is left
out: menus, headers, footers, sidebars, forms, and any block that is mostly links with headline-length text
(the "Don't miss" or "Related" lists of other articles). Those lists used to leak other articles' headlines and
CVEs into a report, so it matched requirements and gained CVEs it was not about. Short link lists, such as CVE IDs
linked to an advisory, are kept.

Documents collected by an earlier version can be read again with the current rules:

```sh
zarqa refetch                      # every collected article (feeds and pages), up to --limit 1000
zarqa refetch --source talos       # one source
zarqa refetch 265 266              # given documents
```

Each changed document is extracted and scored again; documents that cannot be fetched keep their old text.

## STIX

A STIX 2.x bundle (from a `list` source with `format: stix`, a `connector` source, `zarqa add --file x.json`,
the Add page or `POST /api/import/stix`) is read with its structure:

- indicator patterns become indicators;
- threat actors and intrusion sets, malware, tools, campaigns, vulnerabilities (CVE), attack patterns with an
  ATT&CK ID, and targeted sectors and countries become entities;
- relationships between them become relations;
- reports, notes and opinions become documents, which then go through extraction.

## Adding by hand

| How | CLI | API |
|---|---|---|
| Paste text | `zarqa add < report.txt` | `POST /api/documents {"text", "title"}` |
| A URL | `zarqa add --url URL` | `POST /api/documents {"url"}` |
| A file (text, HTML, PDF, STIX JSON) | `zarqa add --file PATH` | (STIX: `POST /api/import/stix`) |
| Indicators | `zarqa add --values < list.txt` | `POST /api/values {"values": [...]}` |

PDF text needs the `pdf` extra: `pip install 'zarqa[pdf]'`.

## Tested

On 2026-11-16 against three public sources: an RSS feed of full diary posts (8 items), a government
advisory feed (5 items) and a plain-text IP list (300 values). All pulled and stored; the second pull of
each feed added nothing new.
