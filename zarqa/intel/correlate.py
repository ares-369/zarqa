"""Connecting reports and entities across sources.

* ``related_documents``: other reports that share entities with this one, weighted by how rare each shared entity
  is (a CVE or a malware family seen in three reports links them much more than PowerShell seen in two hundred).
  A link needs at least one shared actor, malware, tool, campaign, CVE or indicator, or three shared techniques.
  Reports within 7 days of each other that share two or more specific entities (actors, malware, tools,
  campaigns, CVEs, indicators), or whose titles are nearly the same, are marked ``same_story``: the same event
  covered by several outlets.
* ``connections``: the entities most often named in the same reports as this one, with how many reports and
  which, and any stated relations between them.

Rarity is ``log(N / reports naming the entity)`` over reports (indicator lists and STIX bundle records are left out:
they name thousands of values without saying anything about them). Being named together is not a relation: it
is a lead to read the reports, and the evidence is the reports listed.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone

from .store import INDICATOR_TYPES, KnowledgeStore

SPECIFIC = {"actor", "malware", "tool", "campaign", "cve", *INDICATOR_TYPES}
_REPORT_KINDS = "('list', 'stix')"
_WORD = re.compile(r"[a-z0-9]{3,}")


def _reports(store: KnowledgeStore) -> int:
    with store._conn() as c:
        return int(c.execute(f"SELECT COUNT(*) FROM documents WHERE kind NOT IN {_REPORT_KINDS}").fetchone()[0])  # nosec B608


def _df(store: KnowledgeStore, entity_ids: list[int]) -> dict[int, int]:
    out: dict[int, int] = {}
    for chunk in (entity_ids[i:i + 500] for i in range(0, len(entity_ids), 500)):
        marks = ",".join("?" * len(chunk))
        with store._conn() as c:
            for eid, n in c.execute(
                    f"SELECT m.entity_id, COUNT(DISTINCT m.document_id) FROM mentions m JOIN documents d ON "  # nosec B608
                    f"d.id = m.document_id WHERE d.kind NOT IN {_REPORT_KINDS} AND m.entity_id IN ({marks}) "
                    f"GROUP BY m.entity_id", chunk):
                out[int(eid)] = int(n)
    return out


def _idf(n_reports: int, df: int) -> float:
    return math.log((n_reports + 1) / (df + 0.5))


def _when(doc: dict) -> datetime | None:
    from .timeline import published_date
    v = published_date(doc.get("published", "")) or (doc.get("fetched") or "")[:10]
    try:
        return datetime.fromisoformat(v).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _title_words(t: str) -> set[str]:
    return set(_WORD.findall((t or "").lower())) - {"the", "and", "for", "with", "from", "new", "how", "what"}


def related_documents(store: KnowledgeStore, doc_id: int, *, limit: int = 10) -> list[dict]:
    doc = store.document(doc_id)
    if not doc:
        raise ValueError(f"no document {doc_id}")
    with store._conn() as c:
        mine = {int(r[0]): (r[1], r[2]) for r in c.execute(
            "SELECT DISTINCT e.id, e.type, e.display FROM mentions m JOIN entities e ON e.id = m.entity_id "
            "WHERE m.document_id = ? AND e.status = 'active'", (int(doc_id),))}
    if not mine or doc.get("kind") in ("list", "stix"):
        return []
    n = _reports(store)
    df = _df(store, list(mine))
    shared: dict[int, list[int]] = {}
    ids = list(mine)
    for chunk in (ids[i:i + 500] for i in range(0, len(ids), 500)):
        marks = ",".join("?" * len(chunk))
        with store._conn() as c:
            for other, eid in c.execute(
                    f"SELECT DISTINCT m.document_id, m.entity_id FROM mentions m JOIN documents d ON "  # nosec B608
                    f"d.id = m.document_id WHERE m.entity_id IN ({marks}) AND m.document_id != ? AND d.kind NOT IN "
                    f"{_REPORT_KINDS}", (*chunk, int(doc_id))):
                shared.setdefault(int(other), []).append(int(eid))
    me_when, me_words = _when(doc), _title_words(doc.get("title", ""))
    out = []
    for other, eids in shared.items():
        score = sum(_idf(n, df.get(e, 1)) for e in eids)
        specific = [e for e in eids if mine[e][0] in SPECIFIC and df.get(e, 1) <= max(3, n // 20)]
        if not any(mine[e][0] in SPECIFIC for e in eids) and len(eids) < 3:
            continue                     # one or two shared techniques, sectors or countries: too weak a link
        if score < 2.0 and not specific:
            continue
        od = store.document(other) or {}
        ow = _title_words(od.get("title", ""))
        title_sim = len(me_words & ow) / max(1, len(me_words | ow))
        close = (me_when and _when(od) and abs((me_when - _when(od)).days) <= 7)
        same = bool(close and (len(specific) >= 2 or title_sim >= 0.5))
        top = sorted(eids, key=lambda e: -_idf(n, df.get(e, 1)))
        out.append({"document_id": other, "title": od.get("title", ""), "source": od.get("source", ""),
                    "published": od.get("published", ""), "fetched": od.get("fetched", ""),
                    "score": round(score + (5 if same else 0), 2), "same_story": same,
                    "shared": [{"id": e, "type": mine[e][0], "display": mine[e][1]} for e in top[:8]],
                    "shared_count": len(eids)})
    out.sort(key=lambda x: -x["score"])
    return out[:limit]


def connections(store: KnowledgeStore, entity_id: int, *, limit: int = 20) -> list[dict]:
    e = store.entity(entity_id)
    if not e:
        raise ValueError(f"no entity {entity_id}")
    with store._conn() as c:
        docs = [int(r[0]) for r in c.execute(
            f"SELECT DISTINCT m.document_id FROM mentions m JOIN documents d ON d.id = m.document_id "  # nosec B608
            f"WHERE m.entity_id = ? AND d.kind NOT IN {_REPORT_KINDS}", (int(entity_id),))]
    if not docs:
        return []
    co: dict[int, set[int]] = {}
    for chunk in (docs[i:i + 500] for i in range(0, len(docs), 500)):
        marks = ",".join("?" * len(chunk))
        with store._conn() as c:
            for eid, did in c.execute(
                    f"SELECT DISTINCT m.entity_id, m.document_id FROM mentions m JOIN entities x ON x.id = m.entity_id "  # nosec B608
                    f"WHERE m.document_id IN ({marks}) AND m.entity_id != ? AND x.status = 'active'",
                    (*chunk, int(entity_id))):
                co.setdefault(int(eid), set()).add(int(did))
    n = _reports(store)
    df = _df(store, list(co))
    rels: dict[int, set[str]] = {}
    for r in store.relations(entity_id=entity_id, limit=500):
        other = r["dst"] if r["src"] == entity_id else r["src"]
        rels.setdefault(other, set()).add(r["rel"])
    out = []
    for eid, ds in co.items():
        x = store.entity(eid)
        if not x:
            continue
        score = len(ds) * _idf(n, df.get(eid, 1)) + (3 if eid in rels else 0)
        if len(ds) < 2 and eid not in rels and x["type"] not in SPECIFIC:
            continue                     # one shared report about a common thing is noise
        out.append({"id": eid, "type": x["type"], "display": x["display"], "documents": len(ds),
                    "document_ids": sorted(ds)[-5:], "relations": sorted(rels.get(eid, set())),
                    "score": round(score, 2)})
    out.sort(key=lambda x: -x["score"])
    return out[:limit]
