"""What the API, CLI and scheduler call: pull a source, add something by hand, process documents."""

from __future__ import annotations

from typing import Any

from ..collect.collector import Collector, sources_from
from .pipeline import process, settings
from .store import KnowledgeStore, store_for


def _llm(cfg):
    if not settings(cfg)["model"]:
        return None
    from ..llm import privacy_llm
    return privacy_llm(cfg)


def collector(cfg, store: KnowledgeStore | None = None, **kw) -> Collector:
    return Collector(cfg, store or store_for(cfg), **kw)


def source(cfg, name: str) -> dict:
    for s in sources_from(cfg, include_disabled=True):      # a switched-off source can still be pulled by hand
        if s["name"] == name:
            return s
    raise KeyError(f"no source named {name!r}")


def process_documents(cfg, doc_ids: list[int], *, store: KnowledgeStore | None = None, use_model: bool | None = None,
                      llm=None) -> list[dict]:
    store = store or store_for(cfg)
    llm = llm if llm is not None else (_llm(cfg) if use_model is not False else None)
    out = []
    for d in doc_ids:
        try:
            r = process(store, d, cfg=cfg, llm=llm, use_model=use_model)
        except Exception as exc:          # one bad document must not stop the rest
            store.update_document(d, status="error", error=str(exc)[:500])
            out.append({"document_id": d, "error": str(exc)[:300]})
            continue
        try:
            from .relevance import score_document
            r["relevance"] = score_document(cfg, store, d, llm=llm)
        except Exception as exc:
            r["relevance"] = {"error": str(exc)[:200]}
        from .enrich import auto_candidates, enrich
        for eid in auto_candidates(store, cfg, d):
            try:
                enrich(cfg, store, eid, actor="auto")
            except Exception:
                pass
        out.append(r)
    return out


def refetch_documents(cfg, doc_ids: list[int] | None = None, *, sources: list[str] | None = None,
                      store: KnowledgeStore | None = None, use_model: bool | None = None, limit: int = 1000,
                      fetch=None, checkpoint=None) -> dict:
    """Read collected articles again from their URLs and extract them again: after an upgrade that reads pages
    better, so old documents get the same quality as new ones. Feed items keep their title; the feed's own
    summary is not kept (it repeats the article). Documents that cannot be fetched keep their old text."""
    store = store or store_for(cfg)
    col = collector(cfg, store, fetch=fetch)
    if doc_ids:
        docs = [d for d in (store.document(i) for i in doc_ids) if d]
    else:
        docs, offset = [], 0
        while len(docs) < limit:
            page = store.documents(limit=500, offset=offset)
            if not page:
                break
            docs += [d for d in page if d["kind"] in ("feed", "page") and d.get("url")
                     and (not sources or d["source"] in sources)]
            offset += 500
        docs = docs[:limit]
    out = {"checked": 0, "changed": 0, "unchanged": 0, "errors": [], "documents": []}
    llm = _llm(cfg) if use_model is not False else None
    for d in docs:
        if checkpoint is not None and not checkpoint():
            out["stopped"] = True
            break
        if d["kind"] not in ("feed", "page") or not d.get("url"):
            continue
        out["checked"] += 1
        try:
            art = col._get(d["url"])
        except Exception as exc:
            out["errors"].append(f"{d['id']}: {exc}"[:300])
            continue
        text = f"{d['title']}\n\n{art['text']}".strip() if d["kind"] == "feed" else art["text"]
        if not store.replace_text(d["id"], text, max_chars=col.max_chars):
            out["unchanged"] += 1
            continue
        out["changed"] += 1
        out["documents"].append(d["id"])
        process_documents(cfg, [d["id"]], store=store, use_model=use_model, llm=llm)
    if out["changed"]:
        from .credibility import refresh
        with store._conn() as c:
            refresh(store, [r[0] for r in c.execute("SELECT id FROM entities").fetchall()])
    return out


def pull_source(cfg, name: str, *, actor: str = "scheduler", process_new: bool = True, use_model: bool | None = None,
                store: KnowledgeStore | None = None, **kw) -> dict[str, Any]:
    store = store or store_for(cfg)
    r = collector(cfg, store, **kw).pull(source(cfg, name), actor=actor)
    if process_new and r["new_documents"]:
        r["processed"] = process_documents(cfg, r["new_documents"], store=store, use_model=use_model)
    return r


def due_sources(cfg, store: KnowledgeStore) -> list[str]:
    """Sources whose interval has passed since their last pull."""
    from datetime import datetime, timedelta, timezone
    states = store.source_state()
    now = datetime.now(timezone.utc)
    out = []
    for s in sources_from(cfg):
        mins = int(s.get("interval_minutes", 0) or 0)
        if mins <= 0 or s.get("enabled") is False:
            continue
        last = (states.get(s["name"]) or {}).get("last_pull") or ""
        try:
            t = datetime.fromisoformat(last) if last else None
        except ValueError:
            t = None
        if t is None or now - t >= timedelta(minutes=mins):
            out.append(s["name"])
    return out
