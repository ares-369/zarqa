# Correlation

Zarqa connects what different sources say, so one event covered by five outlets, or an actor's infrastructure
named across reports, is visible as a whole.

## Related reports (report page, `GET /api/documents/<id>/related`)

Other reports that name the same things, weighted by how rare each shared name is: a CVE, malware family or IP
address seen in three reports links them much more than PowerShell seen in two hundred (weight
`log(N / reports naming it)`). A link needs at least one shared actor, malware, tool, campaign, CVE or indicator,
or three shared techniques; one shared technique, sector or country is too weak.

**Same story**: published within 7 days of each other and sharing two or more specific, uncommon names, or with
nearly the same title. Typically the vendor write-up, the news coverage and the government advisory of one event.

## Seen with (entity page, `GET /api/entities/<id>/connections`)

The entities most often named in the same reports as this one, rarer and more frequent first, with the reports
(click through) and any stated relations between them.

Being named together is **not** a relation. It is a lead to read the reports listed, which are the evidence.
For that reason co-mentions are not given to the investigation model as evidence: a hostile report could plant an
indicator next to a real one, and the model could then "prove" a link with it.

Indicator lists and STIX bundle records are left out of both: they name thousands of values without saying
anything about them.

## Tested

On 2026-11-20 against the live collection (about 280 reports): three reports on one vCenter zero-day were marked
the same story (shared CVEs); two PHP advisories were linked by their two CVEs; a phishing report was linked to a
Zimbra campaign write-up by four shared domains; Akira was seen with the IP addresses and domains two reports named
for it. Each lookup took under 0.1 s.
