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

The questions your team needs answered. A requirement matches a document when one of its terms is in it; the
document is tagged `pir:<name>` and can be listed with `/api/documents?tag=pir:<name>`.

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

Capped at 100. Indicator lists and STIX bundle records are not scored.

Model, if `relevance.model: true`: for documents the rules matched at all, the `analyst` model reads your
profile and the document and gives its own score and a one-sentence reason, which replace the rules score;
the rule reasons stay listed. Your organization profile is sent to that model, so list your names under
`privacy.terms` if the model is a cloud provider.

`zarqa rescore` (or "Score again") scores documents again after you change the profile.

## Tested

On 2026-11-16 with a sample profile (energy and manufacturing, Europe, four products) over 14 collected
documents: the four ICS advisories naming a listed vendor scored 70, the infostealer write-up matching a
requirement 65, a patch-day post 55, and general items 0-25.
