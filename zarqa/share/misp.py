"""Export as a MISP-format event (JSON), the format many sharing platforms import.

One event per export. Indicators become attributes (``to_ids`` true), CVEs become ``vulnerability``
attributes (``to_ids`` false), actors, malware, tools, campaigns and techniques become tags.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..intel.store import KnowledgeStore
from .stix_out import NS, exportable

_ATTR = {"ipv4": ("ip-dst", "Network activity"), "ipv6": ("ip-dst", "Network activity"),
         "domain": ("domain", "Network activity"), "url": ("url", "Network activity"),
         "email": ("email-src", "Payload delivery"), "md5": ("md5", "Payload delivery"),
         "sha1": ("sha1", "Payload delivery"), "sha256": ("sha256", "Payload delivery"),
         "cve": ("vulnerability", "External analysis")}
_TAG = {"actor": "threat-actor", "malware": "malware", "tool": "tool", "campaign": "campaign", "technique": "mitre-attack",
        "sector": "sector", "country": "country"}


def event(store: KnowledgeStore, *, info: str, entity_ids: list[int] | None = None, document_id: int | None = None,
          producer: str = "Zarqa", limit: int = 5000) -> dict:
    ents: list[dict] = []
    url = ""
    if document_id is not None:
        d = store.document(document_id, with_text=False)
        if not d:
            raise ValueError("no such document")
        info = info or d["title"]
        url = d.get("url", "")
        seen = set()
        for m in store.mentions(document_id=document_id, limit=limit):
            if m["context"] in ("benign", "victim", "reference") or m["entity_id"] in seen:
                continue
            seen.add(m["entity_id"])
            e = store.entity(m["entity_id"])
            if e and e["status"] == "active":
                ents.append({**e, "_snippet": m["snippet"]})
    else:
        for i in (entity_ids or [])[:limit]:
            e = store.entity(int(i))
            if e and exportable(store, e):
                ents.append(e)
    attrs, tags = [], [{"name": f"source:{producer}"}]
    for e in ents:
        if e["type"] in _ATTR:
            typ, cat = _ATTR[e["type"]]
            attrs.append({"uuid": str(uuid.uuid5(NS, f"misp:{e['type']}:{e['value']}")), "type": typ, "category": cat,
                          "value": e["value"], "to_ids": e["type"] != "cve",
                          "comment": (e.get("_snippet") or "")[:500], "first_seen": e["first_seen"][:19],
                          "last_seen": e["last_seen"][:19]})
        elif e["type"] in _TAG:
            tags.append({"name": f"{_TAG[e['type']]}:\"{e['display']}\""})
    if url:
        attrs.append({"uuid": str(uuid.uuid5(NS, f"misp:link:{url}")), "type": "link", "category": "External analysis",
                      "value": url, "to_ids": False})
    today = datetime.now(timezone.utc).date().isoformat()
    return {"Event": {"uuid": str(uuid.uuid4()), "info": (info or "Zarqa export")[:500], "date": today,
                      "threat_level_id": "2", "analysis": "1", "distribution": "0", "published": False,
                      "Orgc": {"name": producer}, "Attribute": attrs, "Tag": tags}}
