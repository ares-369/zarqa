"""Push intel to another platform through a ``sharing`` connector.

    share:
      targets:
        - name: platform
          connector: platform-out        # a connector with roles [sharing], allow_write: true, the tool in tools.allow
          tool: add_bundle
          argument: bundle               # the tool argument that receives the export
          format: stix                   # stix | misp
          arguments: {}                  # other fixed arguments

A person (operator role) chooses what to send: a document and what was found in it, or chosen entities.
Every push is recorded in the audit log with who sent it, and is never retried.
"""

from __future__ import annotations

import re

from ..intel.store import KnowledgeStore
from .misp import event
from .stix_out import export


def targets(cfg) -> list[dict]:
    out = []
    for t in (((cfg.raw or {}).get("share") or {}).get("targets") or []):
        out.append(t)
    return out


def validate(raw: dict) -> None:
    s = raw.get("share") or {}
    if not isinstance(s, dict):
        raise ValueError("share: must be a mapping")
    names = set()
    for t in s.get("targets") or []:
        if not isinstance(t, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", str(t.get("name", ""))):
            raise ValueError("share.targets: each needs a name (lowercase letters, digits, _ or -)")
        for k in ("connector", "tool", "argument"):
            if not t.get(k):
                raise ValueError(f"share target {t['name']}: {k} is required")
        if t.get("format", "stix") not in ("stix", "misp"):
            raise ValueError(f"share target {t['name']}: format must be stix or misp")
        if t["name"] in names:
            raise ValueError(f"duplicate share target {t['name']}")
        names.add(t["name"])


def build(cfg, store: KnowledgeStore, fmt: str, *, document_id: int | None = None,
          entity_ids: list[int] | None = None) -> dict:
    name = cfg.instance_name
    if fmt == "misp":
        return event(store, info="", document_id=document_id, entity_ids=entity_ids, producer=name)
    return export(store, producer_name=name, document_id=document_id, entity_ids=entity_ids)


def push(cfg, store: KnowledgeStore, target: str, *, actor: str, document_id: int | None = None,
         entity_ids: list[int] | None = None, hub=None) -> dict:
    t = next((x for x in targets(cfg) if x["name"] == target), None)
    if t is None:
        raise ValueError(f"no share target {target!r}")
    if not actor:
        raise ValueError("a push needs the name of the person who sends it")
    if document_id is None and not entity_ids:
        raise ValueError("choose a document or entities to send")
    payload = build(cfg, store, t.get("format", "stix"), document_id=document_id, entity_ids=entity_ids)
    if hub is None:
        from ..connectors import get_hub
        hub = get_hub(cfg)
    ref = f"share:{target}:" + (f"document:{document_id}" if document_id is not None else f"entities:{len(entity_ids or [])}")
    r = hub.share(t["connector"], t["tool"], {**(t.get("arguments") or {}), t["argument"]: payload}, actor=actor, ref=ref)
    n = len(payload.get("objects") or (payload.get("Event") or {}).get("Attribute") or [])
    return {**r, "target": target, "items": n}
