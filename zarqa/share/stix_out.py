"""STIX 2.1 export of what Zarqa knows.

Object ids are derived from the content (UUIDv5), so the same indicator or actor exported twice has the same
id and a platform that imports both keeps one. Every object carries ``created_by_ref`` to the producer
identity (``zarqa.instance_name``). Reports become ``report`` objects with the source URL and refer to what
was found in them; relations become ``relationship`` objects with the sentence that states them, whether the source stated
or the model inferred it (``x_zarqa_basis``) and when it happened by the source (``x_zarqa_observed``).

An indicator is left out when every mention of it is labelled benign, victim or reference (by the model or a
source); unlabelled ones are exported. Entities marked false positive, allow-listed or expired are left out.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..intel import attack
from ..intel.store import INDICATOR_TYPES, KnowledgeStore

NS = uuid.UUID("2d0f6a7e-9c43-4f0b-8f1d-5a7c3e1b9d62")
_HASH = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
_OBJ = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url", "email": "email-addr"}
_SDO = {"actor": "intrusion-set", "malware": "malware", "tool": "tool", "campaign": "campaign"}
_REL = {"uses": "uses", "targets": "targets", "exploits": "exploits", "attributed_to": "attributed-to",
        "communicates_with": "communicates-with", "drops": "drops", "delivers": "delivers", "variant_of": "variant-of",
        "related_to": "related-to"}
EPOCH = "2026-01-01T00:00:00.000Z"


def ts(value: str | None = None) -> str:
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else datetime.now(timezone.utc)
    except ValueError:
        d = datetime.now(timezone.utc)
    d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    d = d.astimezone(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NS, key)}"


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def pattern(etype: str, value: str) -> str | None:
    if etype in _HASH:
        return f"[file:hashes.'{_HASH[etype]}' = '{_esc(value.lower())}']"
    if etype in _OBJ:
        return f"[{_OBJ[etype]}:value = '{_esc(value)}']"
    return None


def identity(name: str) -> dict:
    return {"type": "identity", "spec_version": "2.1", "id": sid("identity", f"producer:{name}"), "created": EPOCH,
            "modified": EPOCH, "name": name, "identity_class": "system"}


def entity_object(e: dict, producer: str) -> dict | None:
    t, v = e["type"], e["value"]
    base = {"spec_version": "2.1", "created": ts(e["first_seen"]), "modified": ts(e["last_seen"]),
            "created_by_ref": producer}
    if e.get("confidence") is not None:
        base["confidence"] = int(e["confidence"])
    if e.get("tags"):
        base["labels"] = [str(x)[:100] for x in e["tags"]][:20]
    if e.get("rating"):
        base["x_zarqa_admiralty_rating"] = e["rating"]     # source reliability A-F + credibility 1-6
    if t in INDICATOR_TYPES:
        pat = pattern(t, v)
        if not pat:
            return None
        o = {**base, "type": "indicator", "id": sid("indicator", f"{t}:{v.lower()}"), "name": f"{t}: {v}"[:250],
             "pattern": pat, "pattern_type": "stix", "valid_from": ts(e["first_seen"]),
             "indicator_types": ["malicious-activity"]}
        if e.get("expires"):
            o["valid_until"] = ts(e["expires"])
        return o
    if t == "cve":
        return {**base, "type": "vulnerability", "id": sid("vulnerability", v.upper()), "name": v.upper(),
                "external_references": [{"source_name": "cve", "external_id": v.upper()}]}
    if t == "technique":
        tech = attack.technique(v) or {"name": v}
        return {**base, "type": "attack-pattern", "id": sid("attack-pattern", v), "name": tech["name"],
                "external_references": [{"source_name": "mitre-attack", "external_id": v,
                                         "url": f"https://attack.mitre.org/techniques/{v.replace('.', '/')}/"}]}
    if t in _SDO:
        o = {**base, "type": _SDO[t], "id": sid(_SDO[t], f"{t}:{v}"), "name": e["display"]}
        if t == "malware":
            o["is_family"] = True
        if e.get("ref"):
            o["external_references"] = [{"source_name": "mitre-attack", "external_id": e["ref"]}]
        hit = attack.lookup(e["display"]) if t in ("actor", "campaign") else None
        if hit and hit["aliases"]:
            o["aliases"] = hit["aliases"][:30]
        return o
    if t == "sector":
        return {**base, "type": "identity", "id": sid("identity", f"sector:{v}"), "name": e["display"],
                "identity_class": "class", "sectors": [v.replace(" ", "-")[:60]]}
    if t == "country":
        return {**base, "type": "location", "id": sid("location", f"country:{v}"), "name": e["display"]}
    return None


def exportable(store: KnowledgeStore, e: dict) -> bool:
    if e["type"] not in INDICATOR_TYPES:
        return True
    ms = store.mentions(entity_id=e["id"], limit=200)
    return any(m["context"] in ("", "malicious") for m in ms)


def export(store: KnowledgeStore, *, producer_name: str = "Zarqa", entity_ids: list[int] | None = None,
           document_id: int | None = None, since: str | None = None, types: list[str] | None = None,
           min_confidence: int = 0, limit: int = 5000) -> dict:
    """A STIX 2.1 bundle: one document and what was found in it, chosen entities, or the store
    (filtered by ``since`` last seen, ``types`` and ``min_confidence``)."""
    prod = identity(producer_name)
    objs: list[dict] = [prod]
    ents: dict[int, dict] = {}
    docs: list[dict] = []
    if document_id is not None:
        d = store.document(document_id, with_text=False)
        if not d:
            raise ValueError("no such document")
        docs.append(d)
        for m in store.mentions(document_id=document_id, limit=limit):
            if m["context"] not in ("benign", "victim", "reference") and m["entity_id"] not in ents:
                e = store.entity(m["entity_id"])
                if e and e["status"] == "active":
                    ents[e["id"]] = e
    elif entity_ids:
        for i in entity_ids[:limit]:
            e = store.entity(int(i))
            if e:
                ents[e["id"]] = e
    else:
        for e in store.entities(etype=",".join(types) if types else None, limit=limit, order="last_seen"):
            if (not since or e["last_seen"] >= since) and e["confidence"] >= min_confidence:
                ents[e["id"]] = e
    if document_id is None and not entity_ids:
        ents = {k: v for k, v in ents.items() if exportable(store, v)}
    ids: dict[int, str] = {}
    for e in ents.values():
        o = entity_object(e, prod["id"])
        if o:
            objs.append(o)
            ids[e["id"]] = o["id"]
    rels = store.relations(document_id=document_id, limit=limit) if document_id is not None else [
        r for eid in list(ids)[:500] for r in store.relations(entity_id=eid, limit=50)]
    seen = set()
    for r in rels:
        a, b = ids.get(r["src"]), ids.get(r["dst"])
        if not a or not b or r["id"] in seen:
            continue
        seen.add(r["id"])
        objs.append({"type": "relationship", "spec_version": "2.1", "id": sid("relationship", f"{a}|{r['rel']}|{b}"),
                     "created": EPOCH, "modified": EPOCH, "relationship_type": _REL.get(r["rel"], "related-to"),
                     "source_ref": a, "target_ref": b, "description": r["snippet"][:1000], "created_by_ref": prod["id"],
                     **({"x_zarqa_basis": r["basis"]} if r.get("basis") else {}),
                     **({"x_zarqa_observed": r["observed"], "x_zarqa_observed_from": r["observed_from"]}
                        if r.get("observed") else {})})
    for d in docs:
        refs = [o["id"] for o in objs if o["type"] not in ("identity",) or o["id"] != prod["id"]][1:] or [prod["id"]]
        rep = {"type": "report", "spec_version": "2.1", "id": sid("report", f"doc:{d['id']}:{d['title']}"),
               "created": ts(d["fetched"]), "modified": ts(d.get("extracted") or d["fetched"]), "name": d["title"][:300],
               "published": ts(d.get("published") or d["fetched"]) if _iso(d.get("published")) else ts(d["fetched"]),
               "report_types": ["threat-report"], "object_refs": refs, "created_by_ref": prod["id"]}
        if d.get("summary"):
            rep["description"] = d["summary"]
        if d.get("url"):
            rep["external_references"] = [{"source_name": d["source"], "url": d["url"]}]
        objs.append(rep)
    return bundle(objs)


def _iso(v) -> bool:
    try:
        datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def bundle(objects: list[dict]) -> dict:
    seen, objs = set(), []
    for o in objects:
        if o and o["id"] not in seen:
            seen.add(o["id"])
            objs.append(o)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}
