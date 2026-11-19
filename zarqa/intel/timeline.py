"""When things happened, kept apart from when Zarqa heard about them, and how sure the source was.

Every relation carries:

* ``basis``: ``stated`` when the source says it outright (a STIX relationship object, or a quote with a verb for
  that relation: "exploited", "attributed to", "dropped", "contacted" ...), ``inferred`` when the model read it
  from context (the quote names both ends but no such verb);
* ``observed``: when it happened, by the source: a date written in the quote ("in March 2024", "on 2024-03-12"),
  else the report's publication date, else empty; ``observed_from`` says which (``text``, ``published``);
* ``created``: when Zarqa stored it (ingested).

``timeline(store, entity_id)`` lists what the sources say about an entity in date order: its relations, and the
reports that name it without a relation, each with the date and where the date came from.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .store import KnowledgeStore

MONTHS = {m: i for i, m in enumerate(("january", "february", "march", "april", "may", "june", "july", "august",
                                      "september", "october", "november", "december"), 1)}
MONTHS.update({k[:3]: v for k, v in list(MONTHS.items())})
_M = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_Y = r"((?:19|20)\d\d)"
_DATES = [
    ("ymd", re.compile(r"\b" + _Y + r"-(\d\d)-(\d\d)\b")),
    ("dmy", re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?" + _M + r"\.?,?\s+" + _Y + r"\b", re.I)),
    ("mdy", re.compile(r"\b" + _M + r"\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+" + _Y + r"\b", re.I)),
    ("my", re.compile(r"\b" + _M + r"\.?,?\s+(?:of\s+)?" + _Y + r"\b", re.I)),
    ("y", re.compile(r"\b(?:in|since|during|from|early|late|mid|throughout|until)[\s-]+" + _Y + r"\b", re.I)),
]

# verbs that make a relation stated rather than read from context
_VERBS = {
    "uses": r"\b(us(e|es|ed|ing)|deploy\w*|leverag\w*|employ\w*|rel(y|ies|ied) on|wield\w*|toolkit|arsenal|ran|run\w*|"
            r"execut\w*|install\w*|load\w*|abus\w*)\b",
    "targets": r"\b(target\w*|attack\w*|aim\w*|compromis\w*|breach\w*|hit|struck|went after|victim\w*|focus\w* on)\b",
    "exploits": r"\b(exploit\w*|abus\w*|weaponi[sz]\w*|leverag\w*)\b",
    "attributed_to": r"\b(attribut\w*|linked to|tied to|associated with|assess\w* (to be|as)|believed to be|"
                     r"operated by|behind|tracked as|aka|also known as|overlap\w*)\b",
    "communicates_with": r"\b(contact\w*|connect\w*|communicat\w*|beacon\w*|c2|c&c|command[- ]and[- ]control|"
                         r"call\w* (back|home|out)|reach\w* out|send\w*|sent|post\w* to|exfiltrat\w*|resolv\w*)\b",
    "drops": r"\b(drop\w*|download\w*|fetch\w*|retriev\w*|writ\w*|unpack\w*|extract\w*|install\w*)\b",
    "delivers": r"\b(deliver\w*|distribut\w*|spread\w*|push\w*|serv\w*|lur\w*|attach\w*)\b",
    "variant_of": r"\b(variant|version of|fork\w*|based on|derived from|successor|rebrand\w*|new strain|offshoot)\b",
    "related_to": r"\b(indicat\w*|relat\w*|associat\w*|link\w*|tied)\b",
}
_VERB_RE = {k: re.compile(v, re.I) for k, v in _VERBS.items()}


def _valid(y: int, m: int = 1, d: int = 1) -> bool:
    try:
        dt = datetime(y, m, d, tzinfo=timezone.utc)
    except ValueError:
        return False
    return y >= 1990 and dt <= datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1)


def date_in(text: str) -> str:
    """The first date written in a passage, as YYYY-MM-DD, YYYY-MM or YYYY; '' if none."""
    best = None
    for kind, rx in _DATES:
        for m in rx.finditer(text or ""):
            g = m.groups()
            if kind == "ymd":
                y, mo, d = int(g[0]), int(g[1]), int(g[2])
                val = f"{y:04d}-{mo:02d}-{d:02d}" if _valid(y, mo, d) else ""
            elif kind == "dmy":
                y, mo, d = int(g[2]), MONTHS[g[1].lower()[:3]], int(g[0])
                val = f"{y:04d}-{mo:02d}-{d:02d}" if _valid(y, mo, d) else ""
            elif kind == "mdy":
                y, mo, d = int(g[2]), MONTHS[g[0].lower()[:3]], int(g[1])
                val = f"{y:04d}-{mo:02d}-{d:02d}" if _valid(y, mo, d) else ""
            elif kind == "my":
                y, mo = int(g[1]), MONTHS[g[0].lower()[:3]]
                val = f"{y:04d}-{mo:02d}" if _valid(y, mo) else ""
            else:
                y = int(g[0])
                val = f"{y:04d}" if _valid(y) else ""
            if val and (best is None or m.start() < best[0]):
                best = (m.start(), val)
        if best:
            break                              # the most precise kind found wins
    return best[1] if best else ""


def published_date(published: str) -> str:
    """A feed's publication date (RFC 822 or ISO 8601) as YYYY-MM-DD; '' if it cannot be read."""
    p = (published or "").strip()
    if not p:
        return ""
    try:
        return datetime.fromisoformat(p.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(p).date().isoformat()
    except (TypeError, ValueError, IndexError):
        pass
    m = re.search(r"\b((?:19|20)\d\d)-(\d\d)-(\d\d)\b", p)
    return m.group(0) if m and _valid(int(m.group(1)), int(m.group(2)), int(m.group(3))) else ""


def basis_of(rel: str, method: str, snippet: str) -> str:
    if method in ("stix", "feed", "taxii") or method.startswith("stix"):
        return "stated"                      # the source platform asserted the relationship itself
    rx = _VERB_RE.get(rel)
    return "stated" if rx and rx.search(snippet or "") else "inferred"


def observed_of(snippet: str, published: str) -> tuple[str, str]:
    d = date_in(snippet)
    if d:
        return d, "text"
    p = published_date(published)
    return (p, "published") if p else ("", "")


def backfill(store: KnowledgeStore, *, only_missing: bool = True) -> int:
    """Set basis and observed on relations stored before they existed (or all, ``only_missing=False``)."""
    with store._conn() as c:
        sql = ("SELECT r.id, r.rel, r.method, r.snippet, d.published FROM relations r JOIN documents d "
               "ON d.id = r.document_id WHERE r.basis = '' OR r.basis IS NULL" if only_missing else
               "SELECT r.id, r.rel, r.method, r.snippet, d.published FROM relations r JOIN documents d "
               "ON d.id = r.document_id")
        rows = c.execute(sql).fetchall()
    if not rows:
        return 0
    with store._lock, store._conn() as c:
        for rid, rel, method, snip, pub in rows:
            obs, src = observed_of(snip or "", pub or "")
            c.execute("UPDATE relations SET basis=?, observed=?, observed_from=? WHERE id=?",
                      (basis_of(rel, method or "", snip or ""), obs, src, rid))
        c.commit()
    return len(rows)


def timeline(store: KnowledgeStore, entity_id: int, *, limit: int = 200) -> dict:
    """What the sources say about one entity, newest first, with the date each event happened by the source."""
    e = store.entity(entity_id)
    if not e:
        raise ValueError(f"no entity {entity_id}")
    events = []
    with_rel: set[int] = set()
    for r in store.relations(entity_id=entity_id, limit=limit):
        with_rel.add(r["document_id"])
        events.append({"kind": "relation", "date": r.get("observed") or "", "date_from": r.get("observed_from") or "",
                       "ingested": r.get("created", ""), "text": f"{r['src_display']} {r['rel'].replace('_', ' ')} "
                       f"{r['dst_display']}", "rel": r["rel"], "src": r["src"], "dst": r["dst"],
                       "src_display": r["src_display"], "dst_display": r["dst_display"],
                       "basis": r.get("basis") or "", "snippet": r["snippet"], "method": r["method"],
                       "document_id": r["document_id"], "title": r["title"]})
    for m in store.mentions(entity_id=entity_id, limit=limit):
        if m["document_id"] in with_rel:
            continue
        doc = store.document(m["document_id"]) or {}
        obs, src = observed_of(m.get("snippet") or "", doc.get("published", ""))
        events.append({"kind": "mention", "date": obs, "date_from": src, "ingested": m.get("created", ""),
                       "text": f"named in {doc.get('source', 'a report')}", "basis": "", "snippet": m.get("snippet", ""),
                       "method": m["method"], "document_id": m["document_id"], "title": doc.get("title", ""),
                       "context": m.get("context", "")})
    events.sort(key=lambda x: (x["date"] or x["ingested"][:10], x["ingested"]), reverse=True)
    dated = sorted(x["date"] for x in events if x["date"])
    return {"entity": {k: e[k] for k in ("id", "type", "display")},
            "first_reported": dated[0] if dated else "", "last_reported": dated[-1] if dated else "",
            "documents": len({x["document_id"] for x in events}),
            "stated": sum(1 for x in events if x["basis"] == "stated"),
            "inferred": sum(1 for x in events if x["basis"] == "inferred"),
            "events": events[:limit]}
