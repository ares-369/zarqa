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
    for s in sources_from(cfg):
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
            out.append(process(store, d, cfg=cfg, llm=llm, use_model=use_model))
        except Exception as exc:          # one bad document must not stop the rest
            store.update_document(d, status="error", error=str(exc)[:500])
            out.append({"document_id": d, "error": str(exc)[:300]})
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
