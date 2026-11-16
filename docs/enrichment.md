# Enrichment

Enrichment looks a value up somewhere else: reputation, registration data, sandbox reports. It runs only
when someone asks (the entity page, `zarqa enrich VALUE`, `POST /api/entities/<id>/enrich`), or for new
malicious indicators if `enrich.auto: true`. Results are kept on the entity, with who asked and when, and
reused for `enrich.cache_hours` (24).

## Through connectors

Any connector can say which of its tools looks up which value type. No model is involved: Zarqa calls the tool
with the value in the argument you name.

```yaml
connectors:
  - name: reputation
    roles: [enrichment]
    transport: stdio
    command: zarqa
    args: [bridge, openapi, --spec, "${REP_API}/openapi.json", --include, "lookup*"]
    env: {BRIDGE_API_KEY: "${REP_KEY}", BRIDGE_API_KEY_HEADER: "X-API-Key"}
    enrich:
      - {types: [ipv4, ipv6], tool: lookupIp, argument: ip}
      - {types: [domain], tool: lookupDomain, argument: domain, arguments: {days: 30}}
```

Types: `ipv4`, `ipv6`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `cve`. The connector's read-only
policy, pacing and audit log apply as for any call.

## Built-in public services

Off until you turn them on:

```yaml
enrich:
  builtin:
    epss: true      # CVEs: exploit likelihood (api.first.org); top 10% are tagged epss-top10
    rdap: true      # domains and IPs: registrar, registration date and age, network, country (rdap.org)
```

A value is never sent to a built-in public service if it is a private or internal address, or contains one
of `privacy.terms`, matches `privacy.patterns`, or is one of `organization.domains`.

## Automatic

```yaml
enrich:
  auto: true
  auto_types: [ipv4, ipv6, domain, url, sha256, sha1, md5]
  max_per_day: 200
```

After a document is extracted, indicators the model labelled malicious in it are enriched, once each, up to
`max_per_day` automatic lookups per day. Without a model nothing is labelled, so nothing is enriched
automatically.

## Tested

On 2026-11-16 against the live services: EPSS returned a score and percentile for a 2026 CVE; RDAP returned
the registrar and a registration date five days earlier for a ClickFix fake-CAPTCHA domain, and the network
name, country and range for a scanning IP address.
