# Relevance

Each document gets a score from 0 to 100 for how much it matters to you, with the reasons. The Intel page can
sort by it ("most relevant first"). Nothing is scored until you describe your organization or list
requirements, because a score with nothing behind it would mislead.

## Describe your organization

On the **Profile** page (admins), or in `config.yaml`. Saving from the Profile page writes `config.yaml` (the old one
is kept as `config.yaml.bak`) and scores every report collected so far again in the background.

Once a profile exists, the Intel page and the Overview show **only intel relevant to you** (score 30 or more) by
default; "highly relevant" (70 or more) and "everything" are one click away. The API filter is
`/api/documents?min_relevance=30`.

```yaml
organization:
  name: "Example Utility"
  sectors: [energy]
  regions: [Europe, Poland]
  products: ["<VPN appliance>", "<mail platform>", "<OT vendor>"]
  brands: ["exampleutil"]
  domains: ["exampleutil.com"]
```

## Intelligence requirements

The questions your team needs answered. A requirement matches a document when one of its terms is in the
title, the summary or the opening (first 700 characters), or appears at least twice. One mention deep in a page
(a menu, a "related articles" box, an aside) does not count. The document is tagged `pir:<name>` and can be
listed with `/api/documents?tag=pir:<name>`.

```yaml
requirements:
  - name: ransomware
    question: "Which ransomware groups are hitting our sector, and how do they get in?"
    terms: [ransomware, extortion, data leak site]
```

## How the score is made

Rules, always, no model:

| Signal | Points |
|---|---|
| names one of your domains / brands / products | 45 / 40 / 35 |
| names your sector / region | 15 / 10, plus 15 if extraction found it as a target |
| a CVE tagged `kev` (from a known-exploited list source) | 20 |
| a CVE tagged `epss-top10` (from EPSS enrichment) | 10 |
| matches one of your requirements | 25 |
| malicious indicators, when anything else matched | 5 |
| a named product is installed on your hosts (asset inventory) | 10 |
| ...and a host's installed version is in the range the report states | 10 |

Capped at 100. Indicator lists and STIX bundle records are not scored.

Model, if `relevance.model: true`: for documents the rules matched at all, the `analyst` model reads your
profile and the document and gives its own score and a one-sentence reason, which replace the rules score;
the rule reasons stay listed. Your organization profile is sent to that model, so list your names under
`privacy.terms` if the model is a cloud provider.

## What you run: asset inventory

Give Zarqa the installed software of your hosts and relevance says which hosts a report is about:
"installed: OpenSSH on 3 hosts (web1, web2, db1)". A product that is installed weighs 10 more than one that is
only listed.

Import it on the Profile page ("What you run"), or:

```sh
zarqa inventory import packages.csv          # CSV: host,name,version[,vendor], or JSON
zarqa inventory                              # sources, and where each profile product runs
zarqa inventory suggest                      # products to add to the profile
```

Read without any mapping: rows with `host`/`hostname`/`agent`, `name`/`product`/`package`, `version`, `vendor`;
search results (`hits.hits[]._source` with `agent.name` and `package.name`/`package.version`, the shape of a
SIEM inventory index); API results (`data.affected_items[]`). Anything else: map the columns.

To pull it from a read-only connector on a schedule:

```yaml
inventory:
  from: {connector: siem-index, tool: search, arguments: {index: "inventory-packages-*", size: 10000}}
  source: siem                 # the snapshot name
  every_hours: 24              # 0 = only by hand ("Pull from connector", zarqa inventory pull)
  rows: ""                     # dotted path to the list, if it is not found by itself
  fields: {}                   # e.g. {host: device.name, name: app.title, version: app.ver}
```

Or push it from wherever the inventory lives, on that machine's schedule, with a token that can only do this:

```yaml
inventory:
  token_env: ZARQA_INVENTORY_TOKEN     # in .env; accepted only on POST /api/inventory/import
```

```sh
curl -X POST -H "Authorization: Bearer $ZARQA_INVENTORY_TOKEN" -H "Content-Type: application/json" \
     -d "{\"source\": \"siem\", \"content\": $(jq -Rs . < packages.csv)}" https://zarqa.example.org/api/inventory/import
```

Each import replaces the earlier rows from the same source. A failed pull keeps the last good snapshot and
waits as long as a good one before trying again.

Package names become product names (`openssh-server` and `ssh` -> OpenSSH, `libssl3` -> OpenSSL,
`Mozilla Firefox (x64 en-US)` -> Firefox); libraries, fonts, compilers, documentation and base-system
packages are left out. **Nothing is added to your profile by itself**: package names such as `less`, `file` or
`expect` would match half the news. Suggestions list well-known products and any product named in the reports
collected so far, most-named first; you add the ones you want. `zarqa inventory suggest --all` lists everything.

Tried on 2026-11-20 with a real inventory (19 hosts, 10,000 package rows) against 500 collected reports: 969
products after the noise filter; the first 30 suggestions were all real software (PHP, Python, Java, Node.js,
PowerShell, the Linux kernel, curl, Chrome, PostgreSQL, Docker, ...), in about 1.3 seconds.

### Affected versions

When a report states which versions are affected, in a sentence that names the product ("OpenSSH before 9.8",
"fixed in 9.8p1", "1.25.0 through 1.25.3", "10.2.2 and earlier", "up to and including 5.2"), Zarqa compares
each host's installed version:

* hosts in the stated range: the reason lists them ("installed version in the affected range the report states:
  OpenSSH before 9.8 on web1 9.2p1") and the score rises by 10;
* every installed version outside it: the reason says so and the "installed" bonus is not given.

Installed versions are read as upstream versions (an epoch such as `1:` and a distribution revision such as
`-2+deb12u3` are dropped). This reads the report's wording; it is not a vulnerability database. Distributions
often fix a flaw without changing the upstream version (a backport), so "in range" means "check this host", not
"this host is vulnerable".

`zarqa rescore` (or "Score again") scores documents again after you change the profile.

## Tested

On 2026-11-16 with a sample profile (energy and manufacturing, Europe, four products) over 14 collected
documents: the four ICS advisories naming a listed vendor scored 70, the infostealer write-up matching a
requirement 65, a patch-day post 55, and general items 0-25.
