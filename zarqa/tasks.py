"""Named background tasks, so a job can be queued in the database and run by any worker.

Each task takes JSON parameters and returns a small JSON result. Modules register their
tasks here as they are added (feed pulls, extraction, investigations, watches).
"""

from __future__ import annotations

from typing import Any


def _cfg():
    from .config import get_config
    return get_config()


def ping(p: dict, ctl, jobs) -> dict:
    """A no-op task, used by tests and ``zarqa doctor`` to check the job runner."""
    return {"ok": True, "echo": str(p.get("echo", ""))[:100]}


def pull(p: dict, ctl, jobs) -> dict:
    from .intel.service import pull_source
    r = pull_source(_cfg(), p["source"], actor=p.get("actor", ""))
    return {"source": r["source"], "new_documents": len(r["new_documents"]), "values": r["values"],
            "errors": r["errors"][:5]}


def process(p: dict, ctl, jobs) -> dict:
    from .intel.service import process_documents
    ids = [int(x) for x in p.get("document_ids") or []]
    out = []
    for i in ids:
        if ctl is not None and not ctl.checkpoint():
            break
        out += process_documents(_cfg(), [i], use_model=p.get("use_model"))
    return {"processed": len(out), "errors": sum(1 for r in out if r.get("error"))}


def enrich(p: dict, ctl, jobs) -> dict:
    from .intel.enrich import enrich as run
    from .intel.store import store_for
    cfg = _cfg()
    r = run(cfg, store_for(cfg), int(p["entity_id"]), only=p.get("only"), actor=p.get("actor", ""),
            force=bool(p.get("force")))
    return {"entity_id": p["entity_id"], "results": r}


def rescore(p: dict, ctl, jobs) -> dict:
    """Score every collected report again (after the profile changed). Rules only unless relevance.model."""
    from .intel.relevance import score_document
    from .intel.store import store_for
    cfg = _cfg()
    st = store_for(cfg)
    llm = None
    if ((cfg.raw or {}).get("relevance") or {}).get("model"):
        from .llm import privacy_llm
        llm = privacy_llm(cfg)
    from .intel.inventory import Inventory
    assets = Inventory(st).hosts_by_product()
    n, offset = 0, 0
    while True:
        docs = st.documents(status="extracted", limit=500, offset=offset)
        if not docs:
            break
        for d in docs:
            if ctl is not None and not ctl.checkpoint():
                return {"scored": n, "stopped": True}
            score_document(cfg, st, d["id"], llm=llm, assets=assets)
            n += 1
        offset += 500
    return {"scored": n}


def investigate(p: dict, ctl, jobs) -> dict:
    from .investigate.service import run_investigation
    r = run_investigation(_cfg(), int(p["investigation_id"]), actor=p.get("actor", ""),
                          checkpoint=ctl.checkpoint if ctl else None)
    return {"investigation_id": p["investigation_id"], "status": r.get("status"), "outcome": r.get("outcome")}


def brand(p: dict, ctl, jobs) -> dict:
    from .brand.watch import run
    from .intel.store import store_for
    cfg = _cfg()
    r = run(cfg, kstore=store_for(cfg))
    return {k: r[k] for k in ("candidates", "resolving", "new")} | {"errors": r["errors"][:5]}


def refetch(p: dict, ctl, jobs) -> dict:
    """Read collected articles again from their URLs and extract them again."""
    from .intel.service import refetch_documents
    r = refetch_documents(_cfg(), [int(x) for x in p.get("document_ids") or []] or None, sources=p.get("sources"),
                          checkpoint=ctl.checkpoint if ctl else None)
    return {k: v for k, v in r.items() if k != "documents"} | {"errors": r["errors"][:5]}


def inventory(p: dict, ctl, jobs) -> dict:
    """Pull the asset inventory from the configured connector, then score the reports again."""
    from .intel.inventory import pull as run
    from .intel.store import store_for
    cfg = _cfg()
    r = run(cfg, store_for(cfg), actor=p.get("actor", ""))
    if p.get("rescore", True):
        r["rescored"] = rescore({}, ctl, jobs).get("scored", 0)
    return r


TASKS: dict[str, Any] = {"refetch": refetch, "inventory": inventory, "rescore": rescore, "brand": brand, "ping": ping, "pull": pull, "process": process, "enrich": enrich, "investigate": investigate}


def run_task(name: str, params: dict, ctl=None, *, jobs=None) -> dict:
    if name not in TASKS:
        raise ValueError(f"unknown task {name!r}")
    return TASKS[name](params, ctl, jobs) or {}
