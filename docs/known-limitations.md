# Known limitations

- Reports, a daily brief, the demo and a published benchmark are not built yet (see the [roadmap](roadmap.md)).
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
