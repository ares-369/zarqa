# Confidence

Relevance says how much something matters to you ([relevance](relevance.md)). Confidence says how far it can be
trusted. They are kept apart: a highly relevant report from an unknown source with nothing to back it up should
not look confirmed.

Zarqa rates every entity on the NATO **Admiralty scale**, shown as a letter and a digit (for example `B2`), and
turns that into a **confidence** number from 0 to 100.

## Source reliability (A-F)

Set per source in `config.yaml`; sources without a letter are `collect.default_reliability` (F), and what people
add by hand is `collect.manual_reliability` (F).

| Letter | Meaning | Score |
|---|---|---|
| A | completely reliable | 90 |
| B | usually reliable | 75 |
| C | fairly reliable | 60 |
| D | not usually reliable | 40 |
| E | unreliable | 20 |
| F | reliability cannot be judged | 50 |

An entity takes the best letter among the sources that support it.

```yaml
sources:
  - {name: gov-advisories, kind: feed, url: "https://example.org/advisories.xml", reliability: B}
```

## Information credibility (1-6)

From what the sources say about the entity. Independent means different source names: the same feed twice
counts once.

| Digit | Meaning | When |
|---|---|---|
| 1 | confirmed | three or more independent sources support it |
| 2 | probably true | two |
| 3 | possibly true | one |
| 4 | doubtful | sources disagree: one calls an indicator malicious, another benign, a victim or a reference |
| 5 | improbable | an indicator only ever described as benign, a victim or a reference |
| 6 | cannot be judged | no usable mention |

Names (actors, malware, campaigns, ...) have no roles, so only the number of sources counts for them.

## Confidence (0-100)

The best supporting source's score, plus 10 for each further independent source (at most 20), minus 25 when
sources disagree; 10 when credibility is 5. Recomputed whenever a document is extracted or a list or STIX bundle
is imported.

A source's own confidence values (for example a STIX `confidence` property) are not taken at face value: rate the
source instead.

## Where it shows

- the entity page, the Entities list and `zarqa lookup`;
- the investigation `lookup` tool, so the analyst model sees how well each value is supported;
- STIX exports: `confidence`, and `x_zarqa_admiralty_rating` with the letter and digit;
- MISP-format exports: the standard `admiralty-scale` tags on each attribute;
- `min_confidence` filters (STIX export, TAXII is unfiltered).
