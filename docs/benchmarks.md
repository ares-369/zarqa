# Benchmarks

## Extraction: AnnoCTR

**Dataset.** [AnnoCTR](https://github.com/boschresearch/anno-ctr-lrec-coling-2024) (Bosch Research, LREC-COLING
2024, CC-BY-SA 4.0): threat reports from five vendors, annotated by a domain expert and linked to MITRE ATT&CK.
We use the 34 reports of the test split (about 9,000 characters each). The data is not copied into this
repository; `benchmarks/annoctr/run.py` explains how to run it.

**What is scored**, per report, on sets, summed over reports:

- **names**: the annotated malware, groups and tools. Zarqa's actors, malware, tools and campaigns count as a match
  when the name equals the annotated name, any way the report wrote it, or the same ATT&CK entry (aliases).
- **techniques**: annotated ATT&CK technique IDs, exactly and at the parent level (T1566.001 counts as T1566).
  The annotations link descriptions of behaviour ("email lure with a link") to techniques, so most of them can only
  be found by understanding the text, not by finding an ID.

### Results (2026-11-17)

Rules and ATT&CK names only (no model), all 34 reports, 9 seconds:

| | Precision | Recall | F1 |
|---|---|---|---|
| Names | 0.917 (11 of 12) | 0.107 (11 of 103) | 0.191 |
| Techniques, exact | 0.741 | 0.259 | 0.384 |
| Techniques, parent | 0.943 | 0.301 | 0.457 |

Rules plus a local 7B model (`qwen2.5-coder:7b` on Ollama, 4 GB GPU): the run stopped after **27 of 34 reports**
at a two-hour limit (about 4-5 minutes per report). On those same 27 reports:

| | Rules only | Rules + 7B |
|---|---|---|
| Names precision | 1.000 (11 of 11) | 0.652 (15 of 23) |
| Names recall | 0.128 (11 of 86) | 0.174 (15 of 86) |
| Techniques (parent) precision | 0.952 | 0.937 |
| Techniques (parent) recall | 0.262 | 0.262 |

### What this says

- **Without a model, Zarqa rarely says something wrong, and misses most of what is there.** It finds names and
  technique IDs only when they are written out (an ATT&CK group name or alias, `T1566`).
- **The 7B model added little.** It found 4 more names, added 8 wrong ones, and no techniques. We looked at
  its replies on two reports:
  - on a report with 12 annotated names, it returned only 3 items, two of them with empty quotes (dropped by the
    quote check) and one, "Groove Gang", whose quote said only "GROOVE". That one was dropped by a check that was
    too strict about generic words; this is fixed (generic words such as gang, group, ransomware and campaign
    no longer decide a match), after the run.
  - on another report the model did not answer within 600 seconds.
  So the low recall is mostly the small model returning little; the checks removed what it made up.
- **A stronger model is the obvious next measurement.** It has not been run: it costs money and needs the
  maintainer's go-ahead. The numbers above are what a free local model on a small GPU gives today.

### Not measured yet

- the remaining 7 reports with the 7B model (`--start 27`);
- a stronger model on the same set;
- indicator extraction (AnnoCTR does not annotate indicators);
- relevance ranking, investigations and the brand watch, beyond the spot checks in their own pages.

Raw results (names and IDs only, no report text): `benchmarks/annoctr/results/`.
