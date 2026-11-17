"""Confidence, kept apart from relevance: how far can an entity be trusted, whatever it means to you?

Uses the NATO Admiralty scale:

* **Source reliability** A-F, set per source in config (``reliability:``), default F ("cannot be judged"):
  A completely reliable, B usually reliable, C fairly reliable, D not usually reliable, E unreliable,
  F cannot be judged. An entity takes the best letter among the sources that mention it.
* **Information credibility** 1-6, from what the sources say:
  1 confirmed by three or more independent sources, 2 probably true (two), 3 possibly true (one),
  4 doubtful (sources disagree: one calls an indicator malicious, another benign or a reference),
  5 improbable (only ever described as benign, a victim or a reference), 6 cannot be judged (no usable mention).
  Independent means different source names; the same feed twice counts once.

The **confidence** number (0-100) comes from both: the best source's score (A 90, B 75, C 60, D 40, E 20, F 50),
plus 10 for each further independent source (at most 20), minus 25 when sources disagree; 10 when the
information is improbable. It is what exports carry (STIX ``confidence``) and what ``min_confidence`` filters on.
"""

from __future__ import annotations

from .store import INDICATOR_TYPES, KnowledgeStore

LETTERS = ("A", "B", "C", "D", "E", "F")
SOURCE_SCORE = {"A": 90, "B": 75, "C": 60, "D": 40, "E": 20, "F": 50}
_BAD = ("benign", "victim", "reference")


def valid_letter(v) -> bool:
    return str(v or "").upper() in LETTERS


def _best(letters: list[str]) -> str:
    known = [x for x in letters if x in LETTERS and x != "F"]
    return min(known) if known else "F"          # "A" < "B" < ... alphabetically = better first


def assess(store: KnowledgeStore, entity_id: int) -> dict:
    with store._conn() as c:
        rows = c.execute("SELECT d.source, d.reliability, m.context FROM mentions m JOIN documents d "
                         "ON d.id = m.document_id WHERE m.entity_id = ?", (int(entity_id),)).fetchall()
        etype = (c.execute("SELECT type FROM entities WHERE id=?", (int(entity_id),)).fetchone() or [""])[0]
    return rate(etype, [(r[0], (r[1] or "F").upper(), r[2] or "") for r in rows])


def rate(etype: str, mentions: list[tuple[str, str, str]]) -> dict:
    """``mentions``: (source name, reliability letter, context) for each mention."""
    indicator = etype in INDICATOR_TYPES
    by_source: dict[str, set[str]] = {}
    letters: dict[str, str] = {}
    for src, letter, ctx in mentions:
        by_source.setdefault(src, set()).add(ctx)
        letters[src] = min(letters.get(src, "F"), letter) if letter in LETTERS else letters.get(src, "F")
    if not by_source:
        return {"rating": "F6", "reliability": "F", "credibility": 6, "confidence": 0, "sources": 0,
                "contradicted": False}
    if indicator:
        supporting = [s for s, ctxs in by_source.items() if ctxs - set(_BAD)]   # malicious or unlabelled
        against = [s for s, ctxs in by_source.items() if ctxs & set(_BAD)]
    else:
        supporting, against = list(by_source), []
    contradicted = bool(indicator and against and any("malicious" in by_source[s] for s in supporting))
    n = len(supporting)
    if indicator and not supporting:
        cred = 5
    elif contradicted:
        cred = 4
    elif n >= 3:
        cred = 1
    elif n == 2:
        cred = 2
    else:
        cred = 3
    best = _best([letters[s] for s in (supporting or list(by_source))])
    if cred == 5:
        conf = 10
    else:
        conf = SOURCE_SCORE[best] + 10 * min(2, max(0, n - 1)) - (25 if contradicted else 0)
    conf = max(0, min(100, conf))
    return {"rating": f"{best}{cred}", "reliability": best, "credibility": cred, "confidence": conf,
            "sources": len(by_source), "contradicted": contradicted}


def refresh(store: KnowledgeStore, entity_ids) -> int:
    """Recompute and store the rating and confidence of these entities. Returns how many."""
    ids = sorted({int(i) for i in entity_ids})
    n = 0
    for chunk in (ids[i:i + 500] for i in range(0, len(ids), 500)):
        marks = ",".join("?" * len(chunk))
        with store._conn() as c:
            rows = c.execute(f"SELECT m.entity_id, e.type, d.source, d.reliability, m.context FROM mentions m "  # nosec B608
                             f"JOIN documents d ON d.id = m.document_id JOIN entities e ON e.id = m.entity_id "
                             f"WHERE m.entity_id IN ({marks})", chunk).fetchall()
        grouped: dict[int, tuple[str, list]] = {}
        for eid, etype, src, rel, ctx in rows:
            grouped.setdefault(eid, (etype, []))[1].append((src, (rel or "F").upper(), ctx or ""))
        with store._lock, store._conn() as c:
            for eid, (etype, ms) in grouped.items():
                r = rate(etype, ms)
                c.execute("UPDATE entities SET confidence=?, rating=? WHERE id=?", (r["confidence"], r["rating"], eid))
                n += 1
            c.commit()
    return n


def refresh_document(store: KnowledgeStore, document_id: int) -> int:
    return refresh(store, [m["entity_id"] for m in store.mentions(document_id=document_id, limit=100_000)])
