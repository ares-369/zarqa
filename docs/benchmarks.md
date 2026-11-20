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

Rules plus a local 7B model (`qwen2.5-coder:7b` on Ollama, 4 GB GPU), current code (after the alias, generic-word,
relation and confidence changes): **26 of 34 reports** finished (the run was stopped after 17 + 9; about 2.7 minutes
per report). On those 26:

| | Rules only | Rules + 7B |
|---|---|---|
| Names precision | 1.000 (10 of 10) | 0.667 (24 of 36) |
| Names recall | 0.130 (10 of 77) | 0.312 (24 of 77) |
| Techniques (parent) precision | 0.935 | 0.857 |
| Techniques (parent) recall | 0.153 | 0.158 |

The model more than doubles name recall and costs a third of name precision; it adds almost nothing to techniques.

**What the checks dropped** (first 17 reports, where the full record was kept): the model returned 208 items; 107
were kept and 101 dropped (49%):

| Reason | Items |
|---|---|
| a relation whose end was not kept, or an unknown relation type | 43 |
| ungrounded: the quote is not in the report | 18 |
| a name that is not in its own quote | 14 |
| an indicator the rules did not find (models cannot add indicators) | 14 |
| a CVE ID not in its quote | 4 |
| unknown type or no name | 4 |
| a relation quote that does not name both ends | 2 |
| a technique without a valid ATT&CK ID | 2 |

The **ungrounded** share, quotes that do not exist in the report, is 18 of 208 (8.7%): the closest measure here of
how often the model makes something up. Those never reach the store.

An earlier 7B run on older code (27 reports, before the alias and generic-word fixes) gave names precision 0.652 and
recall 0.174; it is kept in `results/` but superseded by the table above.

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

### Results (2026-11-20): technique names, behaviour phrases and software names, no model

Three deterministic additions, measured on the same 34 test reports with no model:

* ATT&CK technique names written out in the text ("Process Hollowing", "Password Spraying");
* a curated list of behaviour phrases ("dumped LSASS memory" -> T1003.001, "deleted volume shadow copies" ->
  T1490, "side-loaded a malicious DLL" -> the DLL technique); see `zarqa/intel/behaviours.py`;
* ATT&CK software names (malware and tools), except 93 that are ordinary English words ("Empire", "Royal").

The scorer now maps the gold labels' ATT&CK IDs to current ones (AnnoCTR predates a renumbering: five labels
used a retired ID), so the baseline is scored again the same way:

| | Before (rules only) | After | Change |
|---|---|---|---|
| Names precision | 0.917 (11 of 12) | 0.900 (45 of 50) | -0.017 |
| Names recall | 0.107 (11 of 103) | **0.437 (45 of 103)** | x4 |
| Names F1 | 0.191 | **0.588** | |
| Techniques (parent) precision | 0.972 | 0.904 | -0.068 |
| Techniques (parent) recall | 0.310 | **0.398** | +0.088 |
| Techniques (parent) F1 | 0.470 | **0.552** | |
| Techniques (exact) precision | 0.767 | 0.601 | -0.166 |

The phrase list and the excluded names were tuned on the test reports, so the same before/after comparison was run
on the dev and train splits, which were not looked at (`--split dev`, `--split train`):

| Split (reports) | Names P / R / F1 before | after | Techniques (parent) P / R / F1 before | after |
|---|---|---|---|---|
| test (34, tuned on) | 0.92 / 0.11 / 0.19 | 0.90 / 0.44 / **0.59** | 0.97 / 0.31 / 0.47 | 0.90 / 0.40 / **0.55** |
| dev (16, unseen) | 0.78 / 0.10 / 0.18 | 0.87 / 0.57 / **0.69** | 0.35 / 0.06 / 0.11 | 0.40 / 0.18 / **0.25** |
| train (67, unseen) | 0.89 / 0.17 / 0.28 | 0.81 / 0.44 / **0.57** | 0.91 / 0.30 / 0.45 | 0.77 / 0.40 / **0.52** |

On unseen reports, name recall still roughly triples and F1 rises on every split; technique precision on the train
split falls from 0.91 to 0.77, the price of the extra recall. (The dev split has few technique labels, which
explains its low technique scores before and after.)

Without any model, name recall is now higher than the 7B model gave before (0.31), at much better precision
(0.90 against 0.67). Most of the drop in exact technique precision is a sub-technique named where the annotators
labelled only the parent (T1059.001 against T1059). Noisy entries were removed by looking at the false hits on
this set (everyday phrases such as "social media", "IP addresses", "VPN", and "sandbox detection", which in
reports usually means a sandbox detected the malware); the phrase list was tuned on this test set, so the numbers
are somewhat optimistic for unseen reports.


- **Without a model, Zarqa rarely says something wrong.** Since 2026-11-20 it also finds software names, technique
  names and common behaviour wordings, which roughly quadruples name recall; it still misses most behaviour that is
  described in a way the phrase list does not know.
- **A small local model helps with names, not techniques.** On the current code it more than doubles name recall
  (0.13 to 0.31) at a cost in precision (1.00 to 0.67), and leaves technique recall where the rules have it. We looked at
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

- the 7B model on top of the 2026-11-20 rules (all 34 reports);
- the phrase list on reports it was not tuned on;
- a stronger model on the same set;
- indicator extraction (AnnoCTR does not annotate indicators);
- relevance ranking, investigations and the brand watch, beyond the spot checks in their own pages.

Raw results (names and IDs only, no report text): `benchmarks/annoctr/results/`.
