# Benchmarks

## Adversarial ingestion (2026-11-17)

**Prompt-injection scan.** `benchmarks/injection/cases.yaml`: 16 short reports with planted instructions (plain,
addressed to "the AI analyst", role changes, chat-template tags, fake JSON verdicts, an override marker, words split
with hyphens, base64, French, a wrapper escape) and 6 clean security texts that use words like "ignore",
"instructions", "benign" or "AI" innocently. First run: 15 of 16 attacks flagged ("You are now a helpful
assistant..." was missed), 0 of 6 clean texts flagged. After widening that pattern: 16 of 16, 0 of 6, now a test
in CI. The same person wrote the patterns and the cases, so this shows what the scan covers, not how it does on
attacks nobody anticipated. The wider pattern also flags "You are the best malware analyst team in town": a flag
only marks the document for review.

A real article *about* prompt injection that quotes an attack is flagged too: the scan cannot tell quoting from
attacking.

**A model that obeys the report** (`tests/test_adversarial.py`, scripted). Planted text told the model to report
the indicators as benign, add an indicator and attribute the activity to a named group. What the checks stopped:
an invented malware name (quote not in the document), an indicator that is not in the document, a relation whose
quote names only one end. What they cannot stop, and do not pretend to: a label that contradicts the evidence
("benign" for a real C2 address) and anything the report itself writes down (a planted group name, a planted
indicator). Those are limited by the review flag on the document, by the planted indicator's rating (one unrated
source: F3, confidence 50; the "benign" one is rated 5, improbable), and in investigations by a review note on every
step that cites a flagged document. An investigation model told to call a sharing tool or an unknown tool got
"unknown tool" (sharing tools are never offered), and its findings that cited missing evidence were set aside.

**Hostile files.** An XML entity bomb in a feed is refused before parsing; a broken PDF and a PDF whose stream
expands to megabytes raise a clean error; oversized text is cut at `collect.max_document_chars`.

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

### Alias resolution (no model)

Every AnnoCTR mention (all splits; nothing in Zarqa was trained on them) that the annotators linked to an ATT&CK
group or software entry, 1,351 mentions of 101 entries, resolved with Zarqa's ATT&CK data:

| | Right | Wrong | Unresolved |
|---|---|---|---|
| exact names and aliases | 998 (73.9%) | 45 | 308 |
| plus loose matching (spaces and one generic suffix ignored, only when one entry fits) | 1,180 (87.3%) | 47 | 124 |

The loose matching was written after seeing the first row's misses (JSSLoader for JSS Loader, NetwireRAT for
NETWIRE, Winnti for Winnti Group), so the second row is in-sample. Most "wrong" results are not Zarqa's: 28 are
TA456, which current ATT&CK lists under CURIUM while the 2021 annotations link it to Cleaver; 9 are "TrickBot"
annotated as Tor and 5 "Netwire" annotated as Remcos. What stays unresolved is mostly names ATT&CK does not list
(vendor tracking names such as TA406 and TA415, organisations such as GRU and FSB) and "Beacon" for Cobalt Strike.

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
