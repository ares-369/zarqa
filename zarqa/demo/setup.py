"""``zarqa demo``: a ready home folder with sample data, processed by the scripted demo provider.

Nothing leaves the machine: no model, no feeds, no lookups. Every sample is labelled fictional and the UI shows
a demo banner. Serve it with ``ZARQA_HOME=<dir> zarqa serve``.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import yaml

from .data import BRAND, DOCS, LABEL, ORG, REQUIREMENTS


def build(home: Path, *, run: bool = False) -> dict:
    home = Path(home).expanduser()
    (home / "data").mkdir(parents=True, exist_ok=True)
    roles = {r: {"provider": "demo", "model": "scripted-demo"} for r in ("extractor", "analyst", "reporter")}
    cfg_data = {
        "zarqa": {"instance_name": "Zarqa demo", "bind_host": "127.0.0.1", "bind_port": 8631, "demo": True,
                  "data_dir": str(home / "data")},
        "auth": {"mode": "none"},
        "llm": {"roles": roles, "providers": {"demo": {"default_model": "scripted-demo"}}},
        "organization": ORG, "requirements": REQUIREMENTS,
        "extract": {"model": True}, "relevance": {"model": False},
        "brand": {"watch": [{"domain": "sampleutility.example", "names": ["sampleutility", "Sample Utility"]}]},
        "privacy": {"mask_for": []}, "connectors": [], "sources": [], "default_sources": {"enabled": False},
    }
    (home / "config.yaml").write_text(f"# Zarqa demo: {LABEL}\n" + yaml.safe_dump(cfg_data, sort_keys=False))
    env = home / ".env"
    if not env.exists():
        env.write_text(f"ZARQA_SECRET_KEY={secrets.token_hex(32)}\n")
        env.chmod(0o600)

    import os
    os.environ["ZARQA_HOME"] = str(home)
    os.environ["ZARQA_CONFIG"] = str(home / "config.yaml")
    from .. import config
    cfg = config.get_config(reload=True)
    from ..intel.service import collector, process_documents
    from ..intel.store import store_for
    st = store_for(cfg)
    c = collector(cfg, st)
    ids = []
    for d in DOCS:
        r = c.add_text(d["text"], title=d["title"], url=d["url"], actor="demo", tags=["sample"])
        if r["new"]:
            ids.append(r["id"])
    processed = process_documents(cfg, ids, store=st)

    from ..brand.permute import similarity
    from ..brand.watch import score
    from ..brand.watch import store_for as bstore
    bs = bstore(cfg)
    for b in BRAND:
        ev = {"ips": ["192.0.2.10"], "mx": [], "rdap": {"age_days": b["age"], "registrar": "Sample Registrar (fictional)"},
              "page": ({"title": "Sample Utility sign in (fictional)", "shows_brand": ["Sample Utility"],
                        "asks_password": True} if b["page"] else {"error": "no page"}), "sample": True}
        bs.upsert({"domain": b["domain"], "watched": "sampleutility.example", "technique": b["technique"],
                   "similarity": similarity(b["domain"], "sampleutility.example"),
                   "score": score(b["technique"], similarity(b["domain"], "sampleutility.example"), ev), "evidence": ev})
    out = {"home": str(home), "documents": len(ids), "processed": processed, "investigation": None}
    if run:
        from ..investigate.service import run_investigation
        from ..investigate.store import store_for as istore
        i = istore(cfg).create("What do we know about 203.0.113.45?", "demo")
        out["investigation"] = run_investigation(cfg, i, actor="demo")
    return out
