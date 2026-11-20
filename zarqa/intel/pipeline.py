"""Process one document: fixed rules first, then (optionally) the extractor model.

1. Rules: indicators (defang-aware, private addresses and the publisher's own domain dropped), CVE IDs
   and ATT&CK technique IDs, each with the sentence it came from.
2. Dictionary: known threat group and campaign names and aliases (from ATT&CK).
3. Model (``extract.model: true``): actors, malware, tools, campaigns, techniques, targets, relations and
   the role of each indicator, every item checked against the text (see ``model_extract``).
4. Injection check: text that addresses an AI marks the document for review.

Re-processing a document replaces its earlier rules, dictionary and model results.
"""

from __future__ import annotations

from typing import Any

from . import attack
from .extract import snippet
from .injection import scan
from .store import INDICATOR_TYPES, KnowledgeStore


def settings(cfg) -> dict:
    s = ((cfg.raw or {}).get("extract") or {}) if cfg is not None else {}
    return {"model": bool(s.get("model", True)), "chunk_chars": int(s.get("chunk_chars", 12_000)),
            "max_chunks": int(s.get("max_chunks", 4)), "strict_links": s.get("strict_links", "auto"),
            "model_max_per_day": max(0, int(s.get("model_max_per_day", 0) or 0)),
            "ignore_domains": list(s.get("ignore_domains") or [])}


def model_runs_today(store: KnowledgeStore) -> int:
    """Documents the model extracted in the last 24 hours (for ``extract.model_max_per_day``)."""
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="microseconds")
    with store._conn() as c:
        return int(c.execute("SELECT COUNT(*) FROM documents WHERE method LIKE '%model%' AND method NOT LIKE "
                             "'%model failed%' AND extracted >= ?", (since,)).fetchone()[0])


def _strict(doc: dict, mode) -> bool:
    if mode in (True, False):
        return bool(mode)
    return doc.get("kind") in ("feed", "page", "url")      # articles: only defanged links are indicators


def process(store: KnowledgeStore, doc_id: int, *, cfg=None, llm=None, use_model: bool | None = None,
            confidence: int = 50) -> dict[str, Any]:
    doc = store.document(doc_id)
    if not doc:
        raise ValueError(f"no document {doc_id}")
    s = settings(cfg)
    text = doc["text"]
    out: dict[str, Any] = {"document_id": doc_id, "rules": 0, "dictionary": 0, "model": None, "dropped": [],
                           "review": ""}
    for m in ("rules", "dictionary", "model"):
        store.clear_extraction(doc_id, m)

    from .extract import indicators
    found, dropped = indicators(text, url=doc.get("url", ""), strict_links=_strict(doc, s["strict_links"]),
                                ignore_domains=s["ignore_domains"])
    out["dropped"] += [{"item": d, "why": "rules"} for d in dropped[:50]]
    by_value: dict[str, int] = {}
    for kind, vals in found.items():
        for v in vals[:2000]:
            etype = "technique" if kind == "technique" else kind
            try:
                e = store.upsert_entity(etype, v, confidence=confidence)
            except ValueError:
                continue
            store.add_mention(e["id"], doc_id, method="rules", snippet=snippet(text, v))
            if kind in INDICATOR_TYPES:
                by_value[v.lower()] = e["id"]
            out["rules"] += 1
    for hit in attack.find_names(text):
        try:
            e = store.upsert_entity(hit["kind"], hit["name"], confidence=confidence)
        except ValueError:
            continue
        store.add_mention(e["id"], doc_id, method="dictionary", snippet=snippet(text, hit["matched"]))
        out["dictionary"] += 1
    from .behaviours import find_techniques
    for hit in find_techniques(text):
        try:
            e = store.upsert_entity("technique", hit["id"], confidence=confidence)
        except ValueError:
            continue
        store.add_mention(e["id"], doc_id, method="dictionary", snippet=snippet(text, hit["matched"]))
        out["dictionary"] += 1

    want_model = s["model"] if use_model is None else use_model
    if want_model and llm is not None and use_model is None and s["model_max_per_day"]:
        used = model_runs_today(store)
        if used >= s["model_max_per_day"]:
            want_model = False             # automatic runs only; "process again" by a person still uses the model
            out["model_skipped"] = f"daily model cap reached ({used} of {s['model_max_per_day']}); rules only"
    if want_model and llm is not None:
        from .model_extract import extract_with_model
        r = extract_with_model(llm, doc, list(by_value_display(found)), chunk_chars=s["chunk_chars"],
                               max_chunks=s["max_chunks"])
        out["model"] = {"calls": r["calls"], "model": r["model"], "items": len(r["items"]),
                        "relations": len(r["relations"]), "labels": len(r["indicators"]), "errors": r["errors"]}
        out["dropped"] += r["dropped"]
        ids: dict[tuple, int] = {}
        for it in r["items"]:
            try:
                e = store.upsert_entity(it["type"], it["value"], confidence=confidence)
            except ValueError:
                continue
            store.add_mention(e["id"], doc_id, method="model", snippet=it["quote"])
            ids[(it["type"], it["value"])] = e["id"]
        for lab in r["indicators"]:
            eid = by_value.get(lab["value"].lower())
            if eid:
                store.set_context(doc_id, eid, lab["role"], lab["quote"])
        for rel in r["relations"]:
            def end(x):
                kind, val = x
                if kind == "ioc":
                    return by_value.get(val.lower())
                if (kind, val) in ids:
                    return ids[(kind, val)]
                e = store.find(kind, val) if kind in ("cve", "technique") else None   # found by the rules
                return e["id"] if e else None
            a, b = end(rel["source"]), end(rel["target"])
            if a and b:
                store.add_relation(a, rel["type"], b, doc_id, method="model", snippet=rel["quote"])
        if r["summary"]:
            store.update_document(doc_id, summary=r["summary"])
        method = "rules+model" if not r["errors"] or r["items"] else "rules (model failed)"
    else:
        method = "rules (model cap)" if out.get("model_skipped") else "rules"
    hits = scan(text)
    if hits:
        out["review"] = "possible prompt injection: " + "; ".join(h["pattern"] for h in hits)
    from .credibility import refresh_document
    refresh_document(store, doc_id)
    from .store import now
    store.update_document(doc_id, status="extracted", method=method, review=out["review"], extracted=now(),
                          error="; ".join((out["model"] or {}).get("errors") or [])[:500])
    return out


def by_value_display(found: dict[str, list[str]]):
    for kind, vals in found.items():
        if kind in INDICATOR_TYPES:
            yield from vals


def process_new(store: KnowledgeStore, *, cfg=None, llm=None, limit: int = 20, use_model: bool | None = None) -> list[dict]:
    """Process documents still marked new, oldest first."""
    docs = sorted(store.documents(status="new", limit=limit), key=lambda d: d["id"])
    out = []
    for d in docs:
        try:
            out.append(process(store, d["id"], cfg=cfg, llm=llm, use_model=use_model))
        except Exception as exc:          # one bad document must not stop the rest
            store.update_document(d["id"], status="error", error=str(exc)[:500])
            out.append({"document_id": d["id"], "error": str(exc)[:300]})
    return out
