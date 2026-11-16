"""Start investigations (as background jobs) and run them."""

from __future__ import annotations

from .store import store_for


def run_investigation(cfg, inv_id: int, *, actor: str = "", checkpoint=None, llm=None, hub=None,
                      max_steps: int | None = None) -> dict:
    from ..intel.store import store_for as kstore_for
    from ..llm import privacy_llm
    from .engine import run
    st = store_for(cfg)
    inv = st.get(inv_id)
    if hub is None:
        from ..connectors import get_hub
        hub = get_hub(cfg)
    return run(cfg, inv["question"], inv_id=inv_id, istore=st, kstore=kstore_for(cfg), llm=llm or privacy_llm(cfg),
               hub=hub, actor=actor, checkpoint=checkpoint, max_steps=max_steps)


def start(jobs, cfg, question: str, *, actor: str = "") -> int:
    q = (question or "").strip()
    if len(q) < 5:
        raise ValueError("ask a question (at least 5 characters)")
    st = store_for(cfg)
    inv_id = st.create(q, actor)
    jid = jobs.submit("investigate", {"investigation": inv_id}, None, task="investigate",
                      params={"investigation_id": inv_id, "actor": actor}, deduplicate=False)
    st.set_job(inv_id, jid)
    return inv_id
