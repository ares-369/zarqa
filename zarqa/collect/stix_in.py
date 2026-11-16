"""Read a STIX 2.x bundle (from a file, a feed or another platform) into the knowledge store.

* ``indicator`` patterns: each value becomes an indicator entity.
* ``report`` (and ``note``/``opinion`` text): becomes a document, processed like any other text.
* ``threat-actor``/``intrusion-set``, ``malware``, ``tool``, ``campaign``, ``vulnerability`` (CVE names),
  ``attack-pattern`` (with an ATT&CK ID) and ``identity``/``location`` targets: entities.
* ``relationship`` objects between those: relations.

Everything is linked to one document per bundle, so it stays traceable to where it came from.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..intel.extract import guess_type
from ..intel.store import KnowledgeStore

_VAL = re.compile(r"(?:value|hashes\.'?[A-Za-z0-9-]+'?)\s*=\s*'([^']+)'")
_REL = {"uses": "uses", "targets": "targets", "exploits": "exploits", "attributed-to": "attributed_to",
        "communicates-with": "communicates_with", "drops": "drops", "delivers": "delivers",
        "variant-of": "variant_of", "indicates": "related_to", "related-to": "related_to"}


def _ext(o: dict, source: str) -> str:
    return next((r.get("external_id", "") for r in o.get("external_references") or []
                 if r.get("source_name") == source), "")


def _entity_for(o: dict) -> tuple[str, str] | None:
    t = o.get("type")
    name = str(o.get("name", "")).strip()
    if t in ("threat-actor", "intrusion-set") and name:
        return "actor", name
    if t in ("malware", "tool", "campaign") and name:
        return t, name
    if t == "vulnerability":
        cve = _ext(o, "cve") or (name if re.fullmatch(r"CVE-\d{4}-\d{4,7}", name, re.I) else "")
        return ("cve", cve) if cve else None
    if t == "attack-pattern":
        tid = _ext(o, "mitre-attack")
        return ("technique", tid) if tid else None
    if t == "identity" and o.get("identity_class") == "class" and name:
        return "sector", name
    if t == "location":
        c = o.get("country") or o.get("name")
        return ("country", str(c)) if c else None
    return None


def load(content: str | dict) -> list[dict]:
    data = json.loads(content) if isinstance(content, str) else content
    if isinstance(data, list):
        return [o for o in data if isinstance(o, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("objects"), list):
            return [o for o in data["objects"] if isinstance(o, dict)]
        if data.get("type") and data.get("id"):
            return [data]
    raise ValueError("not a STIX bundle or object list")


def import_bundle(store: KnowledgeStore, content: str | dict, *, source: str, url: str = "", confidence: int = 60,
                  tags: list[str] | None = None, method: str = "feed", added_by: str = "") -> dict[str, Any]:
    objs = load(content)
    summary = {"objects": len(objs), "indicators": 0, "entities": 0, "relations": 0, "reports": [], "skipped": 0}
    head = f"STIX bundle from {source}: {len(objs)} objects"
    body = "\n".join(f"{o.get('type')}: {o.get('name') or o.get('pattern') or o.get('id')}" for o in objs[:2000])
    doc = store.add_document(source=source, kind="stix", text=f"{head}\n{body}", url=url, title=head,
                             tags=tags, added_by=added_by)
    store.update_document(doc["id"], status="extracted", method="stix")
    ids: dict[str, int] = {}
    for o in objs:
        t = o.get("type")
        if t == "indicator":
            for v in _VAL.findall(str(o.get("pattern", ""))):
                kind = guess_type(v)
                if not kind or kind == "technique":
                    summary["skipped"] += 1
                    continue
                try:
                    e = store.upsert_entity(kind, v, confidence=int(o.get("confidence", confidence) or confidence),
                                            tags=[*(tags or []), *[str(x) for x in o.get("labels") or []]])
                except ValueError:
                    summary["skipped"] += 1
                    continue
                store.add_mention(e["id"], doc["id"], method=method, snippet=str(o.get("name") or o.get("description")
                                                                                 or "")[:300], context="malicious")
                ids.setdefault(o.get("id", ""), e["id"])
                summary["indicators"] += 1
        elif t in ("report", "note", "opinion"):
            text = "\n\n".join(str(x) for x in (o.get("name"), o.get("description"), o.get("content"),
                                                o.get("explanation")) if x)
            if text.strip():
                r = store.add_document(source=source, kind="report", text=text, url=url,
                                       title=str(o.get("name") or o.get("abstract") or "STIX report")[:300],
                                       published=str(o.get("published") or o.get("created") or ""), tags=tags,
                                       added_by=added_by)
                if r["new"]:
                    summary["reports"].append(r["id"])
        else:
            ent = _entity_for(o)
            if not ent:
                continue
            try:
                e = store.upsert_entity(ent[0], ent[1], confidence=confidence, tags=tags)
            except ValueError:
                summary["skipped"] += 1
                continue
            store.add_mention(e["id"], doc["id"], method=method,
                              snippet=str(o.get("description") or o.get("name") or "")[:300])
            ids[o.get("id", "")] = e["id"]
            summary["entities"] += 1
    for o in objs:
        if o.get("type") != "relationship":
            continue
        rel = _REL.get(str(o.get("relationship_type", "")))
        a, b = ids.get(o.get("source_ref", "")), ids.get(o.get("target_ref", ""))
        if rel and a and b and store.add_relation(a, rel, b, doc["id"], method=method,
                                                  snippet=str(o.get("description") or "")[:300]):
            summary["relations"] += 1
    summary["document_id"] = doc["id"]
    return summary
