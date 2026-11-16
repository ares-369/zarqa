# Roadmap

Zarqa is built in phases. Each phase ends with tests passing in CI and its documentation written.
A phase is marked done only when that is true.

| Phase | What | Status |
|---|---|---|
| 1 | Foundation: config, login and roles, model providers, privacy layer, jobs, web shell, health check | done |
| 2 | Connectors: MCP client and hub, read-only policy, sharing path, audit log, rate limits; bridges for STIX/TAXII 2.1, REST/OpenAPI and web search | done |
| 3 | Collection: feeds, pages, indicator lists, connector pulls, STIX import, pasted text, URLs and files, scheduled pulls, safe fetching | done |
| 4 | Extraction and knowledge store: indicators, CVEs, actors, malware, ATT&CK techniques and relations, each linked to its source sentence; model output checked against the text; dedup, confidence, expiry, actor aliases | done |
| 5 | Enrichment through connectors (declared lookups) and built-in EPSS and RDAP, opt-in, cached, with a leak guard | done |
| 6 | Relevance: organization profile and intel requirements; each document scored with the reasons shown; optional model check | done |
| 7 | Investigations: question in, cited answer out; says when the data is not enough | planned |
| 8 | Brand monitoring: lookalike domains, new registrations, page checks | planned |
| 9 | Sharing: STIX 2.1 export, TAXII server, MISP-format export, Zarqa as an MCP server | planned |
| 10 | Reports, daily brief, demo mode, benchmark against a public labelled dataset, first release | planned |

Results of the benchmark will be published with their misses, as in the sibling projects.
