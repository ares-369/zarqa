"""Hand a hunt over to a threat hunting tool: Zarqa writes the hypothesis and context, a person starts the hunt.

```yaml
handoff:
  hunt:
    name: Hunting                     # shown on the button
    url: "https://hunt.example.org/#hunts?hypothesis={hypothesis}&context={context}&from={from}"
```

``{hypothesis}``, ``{context}`` and ``{from}`` are replaced, URL-encoded. The button opens the link in the person's
browser; nothing is sent server to server and nothing runs until someone starts it in the hunting tool.

The context lists what the collected reports say: the entity, its stated relations, indicators and techniques
named in the same reports (marked as such: being named together is a lead, not proof), and the reports themselves.
"""

from __future__ import annotations

from urllib.parse import quote

from ..intel import attack
from ..intel.correlate import connections
from ..intel.store import INDICATOR_TYPES, KnowledgeStore

MAX_CONTEXT = 3000


def settings(cfg) -> dict | None:
    h = (((cfg.raw or {}).get("handoff") or {}).get("hunt") or {}) if cfg is not None else {}
    url = str(h.get("url") or "")
    if not url:
        return None
    return {"name": str(h.get("name") or "Hunting")[:40], "url": url}


def validate(raw: dict) -> None:
    h = (raw.get("handoff") or {}).get("hunt") if isinstance(raw.get("handoff"), dict) else None
    if raw.get("handoff") is not None and not isinstance(raw.get("handoff"), dict):
        raise ValueError("handoff: a mapping (hunt: {name, url})")
    if not h:
        return
    url = str(h.get("url") or "")
    if not url.startswith(("https://", "http://")) or "{hypothesis}" not in url:
        raise ValueError("handoff.hunt.url: an http(s) link containing {hypothesis}")


def _link(s: dict, hypothesis: str, context: str, source: str) -> str:
    return (s["url"].replace("{hypothesis}", quote(hypothesis, safe=""))
            .replace("{context}", quote(context[:MAX_CONTEXT], safe="")).replace("{from}", quote(source, safe="")))


def for_entity(cfg, store: KnowledgeStore, entity_id: int) -> dict:
    s = settings(cfg)
    if not s:
        raise LookupError("no hunting tool configured (handoff.hunt.url)")
    e = store.entity(entity_id)
    if not e:
        raise ValueError(f"no entity {entity_id}")
    label = {"actor": "the threat actor", "malware": "the malware", "tool": "the tool", "campaign": "the campaign",
             "cve": "exploitation of", "technique": "the technique"}.get(e["type"], f"the {e['type']}")
    conn = connections(store, entity_id, limit=60)
    iocs = [x for x in conn if x["type"] in INDICATOR_TYPES][:20]
    techs = [x for x in conn if x["type"] == "technique"][:10]
    cves = [x for x in conn if x["type"] == "cve"][:8]
    known = attack.known(e["ref"]) if e.get("ref") else None
    known_techs = [t for t in (known or {}).get("tech", [])][:12]
    hyp = f"Look for signs of {label} {e['display']} in our environment"
    parts = []
    if iocs:
        parts.append("its indicators")
    if techs or known_techs:
        parts.append("the techniques reports describe")
    if cves:
        parts.append("exploitation of " + ", ".join(x["display"] for x in cves[:3]))
    if parts:
        hyp += ": " + ", ".join(parts)
    hyp += "."
    lines = [f"From Zarqa threat intelligence about {e['type']} {e['display']} (rating {e.get('rating') or '-'})."]
    rels = [r for r in store.relations(entity_id=entity_id, limit=20)]
    if rels:
        lines.append("Stated in reports: " + "; ".join(
            f"{r['src_display']} {r['rel'].replace('_', ' ')} {r['dst_display']}" for r in rels[:8]))
    if iocs:
        lines.append("Indicators named in the same reports (a lead, not proof): "
                     + ", ".join(f"{x['display']}" for x in iocs))
    if techs:
        lines.append("Techniques named in the same reports: " + ", ".join(x["display"] for x in techs))
    if known_techs:
        lines.append("Techniques ATT&CK lists for it: " + ", ".join(known_techs))
    if cves:
        lines.append("CVEs named with it: " + ", ".join(x["display"] for x in cves))
    docs = store.mentions(entity_id=entity_id, limit=5)
    if docs:
        lines.append("Reports: " + "; ".join(f"{m['title']}" + (f" ({m.get('url')})" if m.get("url") else "")
                                              for m in docs[:5]))
    context = "\n".join(lines)
    return {"tool": s["name"], "hypothesis": hyp, "context": context[:MAX_CONTEXT],
            "url": _link(s, hyp, context, "Zarqa")}


def for_document(cfg, store: KnowledgeStore, doc_id: int) -> dict:
    s = settings(cfg)
    if not s:
        raise LookupError("no hunting tool configured (handoff.hunt.url)")
    d = store.document(doc_id)
    if not d:
        raise ValueError(f"no document {doc_id}")
    ms = store.mentions(document_id=doc_id, limit=500)
    iocs = [m["display"] for m in ms if m["type"] in INDICATOR_TYPES and m.get("context") in ("", "malicious")][:20]
    techs = sorted({m["display"] for m in ms if m["type"] == "technique"})[:10]
    names = sorted({m["display"] for m in ms if m["type"] in ("actor", "malware", "tool", "campaign")})[:6]
    cves = sorted({m["display"] for m in ms if m["type"] == "cve"})[:6]
    hyp = f"Look for the activity described in \"{d['title'][:150]}\" in our environment"
    bits = [f"{len(iocs)} indicators" if iocs else "", f"{len(techs)} techniques" if techs else "",
            ("exploitation of " + ", ".join(cves[:3])) if cves else ""]
    bits = [b for b in bits if b]
    hyp += (": " + ", ".join(bits) if bits else "") + "."
    lines = [f"From Zarqa: report \"{d['title']}\" ({d['source']}{', ' + d['url'] if d.get('url') else ''})."]
    if d.get("summary"):
        lines.append("Summary: " + d["summary"][:600])
    if names:
        lines.append("Named: " + ", ".join(names))
    if iocs:
        lines.append("Indicators (not labelled benign): " + ", ".join(iocs))
    if techs:
        lines.append("Techniques: " + ", ".join(techs))
    if cves:
        lines.append("CVEs: " + ", ".join(cves))
    context = "\n".join(lines)
    return {"tool": s["name"], "hypothesis": hyp, "context": context[:MAX_CONTEXT],
            "url": _link(s, hyp, context, "Zarqa")}
