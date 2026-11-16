# Investigations

Ask a question in plain language (the Ask page, `zarqa ask "..."` or `POST /api/investigations`). The
`analyst` model works through read-only tools in turns, then gives an assessment in which every claim cites
the evidence it rests on.

## Tools it can use

| Connector | Tools |
|---|---|
| `zarqa` (built in) | `lookup` (everything stored about a value, with the sentences), `search_entities`, `search_documents`, `read_document`, `attack_info` (MITRE ATT&CK), `enrich` (the enrichers you configured) |
| your connectors | every allowed tool of connectors with the roles `intel_platform`, `enrichment`, `search`, `vuln`, `malware` or `analysis` |

Every call goes through the connector policy, pacing and audit log (`ref` = `investigation:<id>`). Each result
is evidence `E1`, `E2`, ..., wrapped as untrusted data before the model sees it.

## The assessment, and how it is checked

```
outcome: answered | partial | not_enough_data
answer, confidence (0-100), findings [{claim, evidence: [E..]}], gaps, next_steps
```

Before it is kept:

- a finding that cites no evidence that exists and succeeded is set aside;
- a finding naming an indicator or CVE that is not in the evidence it cites (or the question) is set aside;
- set-aside claims are listed with the reason, and confidence is capped at 70 when any were set aside;
- with no supported finding, the outcome becomes `not_enough_data` and confidence is capped at 30;
- text in any result that addresses an AI marks the investigation for review.

"Not enough data" is a correct answer when the sources do not say.

## Limits

`limits:` in config: `max_steps` (tool calls, default 20), `max_runtime_sec` (600), `max_tokens` (0 = no cap),
`max_result_bytes` per result, `max_query_sec` per call. At the limit the model is told to answer with what it
has.

## Tested

On 2026-11-16 with a local 7B model (`qwen2.5-coder:7b` on Ollama) over the test store: asked about a C2 IP
address from a public ClickFix write-up, it looked the IP up, searched for the report, and answered correctly
(campaign and malware named), both findings cited, in 55 seconds and 2 tool calls. Its confidence (90) was high
for two calls; treat model confidence as the model's own estimate.
