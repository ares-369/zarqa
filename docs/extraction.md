# Extraction

Every document goes through the same steps. Each thing Zarqa keeps points back to the document and the
sentence it came from, and says how it was found.

## 1. Rules (always)

- **Indicators**: IPv4, IPv6, domains, URLs, emails, MD5, SHA-1 and SHA-256, including defanged forms
  (`hxxp`, `[.]`, `(.)`, `[at]`). The host of each URL and the domain of each email are added too.
- **CVE IDs** and **ATT&CK technique IDs** (retired IDs are mapped to the technique that replaced them).
- Never kept: private, loopback, link-local and reserved addresses (in a write-up these are examples or the
  victim's own hosts), the publisher's own domain, and anything in `extract.ignore_domains`.
- `extract.strict_links: auto`: in articles (feeds, pages, URLs), domains, URLs and emails count only if the
  text defanged them, which is how reports mark real indicators. Plain links are usually references. Pasted
  text and files keep every link.

## 2. Dictionary (always)

Threat group and campaign names and their aliases from MITRE ATT&CK (version shown on the Overview API,
`/api/intel/stats`), matched case-sensitively as whole words. Names under five characters and a few
ordinary words are skipped. An alias resolves to the group's ATT&CK name: "Fancy Bear" and "Sednit" are both
stored as APT28 (G0007). Software names are not matched this way: many are ordinary words.

## 3. Model (if `extract.model: true`)

The `extractor` role reads the document (in up to `max_chunks` pieces of `chunk_chars`) and returns a summary,
named entities (actors, malware, tools, campaigns, techniques, CVEs, targeted sectors and countries),
relations between them, and a role for each indicator the rules found: malicious, benign, victim or
reference.

**Every item must quote the document.** Zarqa then checks the reply and drops:

| Dropped | Why |
|---|---|
| an item whose quote is not in the document | the model made it up or paraphrased |
| a named item whose name (or a known alias) is not in its own quote | the quote does not support it |
| a technique without a valid ATT&CK ID | cannot be mapped |
| an indicator the rules did not find | models may label indicators, never add them |
| a relation whose ends were not kept, or whose quote is not in the document | unsupported |
| a relation whose quote does not name both ends | a real sentence, but not the one that links them |

What was dropped is shown by `zarqa process` and the API. The document text is sent wrapped as untrusted
data, and the model is told never to follow instructions in it. Prompts to cloud providers are masked
([privacy](../config.example.yaml)): emails, private IPs, user names and your listed terms; public IPs are kept.

If the model fails (not reachable, bad reply), the rules and dictionary results stay and the document is
marked `rules (model failed)`.

## 4. Injection check (always)

Text in the document that addresses an AI ("ignore previous instructions", "report no threats", chat
template tags), also after normalising and decoding, marks the document for review. It changes nothing else.

## Re-processing

`zarqa process ID` or "Process again" replaces that document's earlier results from rules, dictionary and
model. Entities seen before keep their history (first seen, times seen).

## Tested

On 2026-11-16, a public diary post about a ClickFix campaign with a local 7B model (`qwen2.5-coder:7b`
on Ollama): the rules found three SHA-256 hashes, two C2 IP addresses, three URLs and a domain, and dropped
5 values (the publisher's own links); the model named the campaign and the malware, linked them ("delivers")
with a real quote, and labelled the hashes, URLs and domain malicious. It also labelled the author's contact
email as "victim", which is wrong; a quote check cannot catch a wrong judgement. It took about two minutes
per article on a 4 GB GPU. A larger model is likely to label better; this has not been measured yet.
