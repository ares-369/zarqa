# Known limitations

- Extraction recall is low without a strong model: on AnnoCTR, rules alone find about 11% of annotated names and
  26-30% of techniques; a local 7B model doubled name recall (0.13 to 0.31, precision 1.00 to 0.67) and added little
  to techniques ([benchmarks](benchmarks.md)). Other features have spot
  checks only.
- The TAXII server pages by position: an object added between two page requests can shift a page. It is
  read-only and has no per-collection access control beyond the login or token.
- Brand watch does not compare registrants, so a brand's own defensive registrations can score as middling
  findings; a lookalike that redirects to your domain is recognised. The page check reads HTML only (no
  scripts), so pages built entirely by scripts look empty.
- The quote check proves an item is *in* the document, not that the model judged it right: a small local
  model labelled an author's contact email as a victim in testing. Treat model labels as leads.
- Indicator rules are patterns: they can miss indicators written in unusual ways, and in pasted text they keep
  every link, including references. Use `extract.ignore_domains` for sites you never want as indicators.
- Long documents are cut to `max_chunks` x `chunk_chars` for the model; the rules read the whole text.
- A patch-day article can add hundreds of CVEs at once. They are real CVE IDs, not indicators, and relevance
  ranking (planned) is what will separate the ones that matter to you.
- Group and campaign names are recognised from ATT&CK only; newer names come from the model, not the
  dictionary.
- Jobs run on the server's own threads only (`jobs.mode: local`); separate worker processes are not
  supported yet.
- The privacy layer is pattern-based and can miss values, for example a name in free text. List
  anything that must never leave under `privacy.terms` or `privacy.patterns`.
- A hostile report can plant an indicator or a name by writing it down; the rules extract it like any other.
  Defences: the document is flagged for review if the planted text addresses an AI, the value carries its source's
  rating (one unrated source: F3), and investigations note when they cite a flagged document. A model's label that
  contradicts the evidence (calling a real C2 address benign) cannot be caught by the quote checks.
- The prompt-injection scan is patterns, tested on a hand-written set by the same author; it also flags articles
  that quote attacks.
