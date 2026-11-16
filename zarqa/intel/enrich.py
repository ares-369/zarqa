"""Enrichment: look a value up in other services, only when asked (or for new malicious indicators,
if ``enrich.auto`` is on).

Two kinds of enricher:

* **Connectors** that declare ``enrich:`` in their config: which tool looks up which value types, and
  which argument gets the value. No model is involved::

      connectors:
        - name: reputation
          roles: [enrichment]
          ...
          enrich:
            - {types: [ipv4, ipv6], tool: lookup_ip, argument: ip}
            - {types: [domain], tool: lookup_domain, argument: domain}

* **Built-in public services**, each off until turned on under ``enrich.builtin``:
  ``epss`` (exploit likelihood for CVEs) and ``rdap`` (registration data for domains and IP addresses).

Values that match ``privacy.terms``/``privacy.patterns`` or the organization's own domains are never sent to
a built-in public service. Results are kept per entity and reused for ``enrich.cache_hours``.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from .. import db
from .store import KnowledgeStore, now

BUILTINS = ("epss", "rdap")
_BUILTIN_TYPES = {"epss": ("cve",), "rdap": ("domain", "ipv4", "ipv6")}


def settings(cfg) -> dict:
    s = ((cfg.raw or {}).get("enrich") or {}) if cfg is not None else {}
    b = s.get("builtin") or {}
    return {"builtin": {k: bool(b.get(k, False)) for k in BUILTINS}, "auto": bool(s.get("auto", False)),
            "auto_types": list(s.get("auto_types") or ["ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5"]),
            "max_per_day": int(s.get("max_per_day", 200)), "cache_hours": int(s.get("cache_hours", 24))}


def validate(raw: dict) -> None:
    s = raw or {}
    if not isinstance(s, dict):
        raise ValueError("enrich: must be a mapping")
    bad = set((s.get("builtin") or {}).keys()) - set(BUILTINS)
    if bad:
        raise ValueError(f"enrich.builtin: unknown {sorted(bad)}; use {BUILTINS}")


class Results:
    """Enrichment results per entity, in the knowledge store's database."""

    def __init__(self, store: KnowledgeStore):
        self.store = store
        with store._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS enrichments (id INTEGER PRIMARY KEY AUTOINCREMENT, entity_id INTEGER "
                      "NOT NULL, enricher TEXT NOT NULL, ts TEXT NOT NULL, ok INTEGER NOT NULL, summary TEXT DEFAULT '', "
                      "data TEXT DEFAULT '', actor TEXT DEFAULT '')")
            c.execute("CREATE INDEX IF NOT EXISTS enrichments_entity ON enrichments(entity_id)")
            c.commit()

    def add(self, entity_id: int, enricher: str, *, ok: bool, summary: str, data: Any, actor: str) -> None:
        text = data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
        with self.store._conn() as c:
            c.execute("INSERT INTO enrichments (entity_id, enricher, ts, ok, summary, data, actor) VALUES (?,?,?,?,?,?,?)",
                      (int(entity_id), enricher, now(), int(ok), summary[:500], text[:20_000], actor[:100]))
            c.commit()

    def recent(self, entity_id: int, enricher: str, hours: int) -> bool:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="microseconds")
        with self.store._conn() as c:
            return c.execute("SELECT 1 FROM enrichments WHERE entity_id=? AND enricher=? AND ok=1 AND ts>=?",
                             (int(entity_id), enricher, since)).fetchone() is not None

    def for_entity(self, entity_id: int, limit: int = 50) -> list[dict]:
        with self.store._conn() as c:
            rows = c.execute("SELECT id, enricher, ts, ok, summary, data, actor FROM enrichments WHERE entity_id=? "
                             "ORDER BY id DESC LIMIT ?", (int(entity_id), int(limit))).fetchall()
        out = []
        for r in rows:
            d = dict(zip(("id", "enricher", "ts", "ok", "summary", "data", "actor"), r, strict=True))
            try:
                d["data"] = json.loads(d["data"])
            except ValueError:
                pass
            d["ok"] = bool(d["ok"])
            out.append(d)
        return out

    def count_since(self, hours: int, actor: str) -> int:
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="microseconds")
        with self.store._conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM enrichments WHERE ts>=? AND actor=?", (since, actor)).fetchone()[0])


def _own(cfg) -> tuple[list[str], list[re.Pattern]]:
    raw = (cfg.raw or {}) if cfg is not None else {}
    priv = raw.get("privacy") or {}
    org = raw.get("organization") or {}
    terms = [str(t).lower() for t in (priv.get("terms") or []) + (org.get("domains") or []) if str(t).strip()]
    pats = []
    for p in priv.get("patterns") or []:
        try:
            pats.append(re.compile(p))
        except re.error:
            pass
    return terms, pats


def private_value(cfg, value: str) -> bool:
    """True if the value must not go to a public service: an internal address, or one of your own terms."""
    try:
        if not ipaddress.ip_address(value).is_global:
            return True
    except ValueError:
        pass
    terms, pats = _own(cfg)
    low = value.lower()
    return any(t in low for t in terms) or any(p.search(value) for p in pats)


def enrichers_for(cfg, hub, etype: str) -> list[dict]:
    """The enrichers that can look up this type: [{name, kind, ...}]."""
    out = []
    if hub is not None:
        from ..access import can_use
        for s in hub.specs.values():
            if not s.enabled or not can_use(s.name):
                continue
            for e in s.enrich:
                if etype in e["types"]:
                    out.append({"name": f"{s.name}/{e['tool']}", "kind": "connector", "connector": s.name, **e})
    b = settings(cfg)["builtin"]
    for name, types in _BUILTIN_TYPES.items():
        if b.get(name) and etype in types:
            out.append({"name": name, "kind": "builtin"})
    return out


# ---- built-in public services ----
def epss(value: str, fetch) -> tuple[str, dict]:
    doc = fetch(f"https://api.first.org/data/v1/epss?cve={quote(value)}", want_raw=True)
    data = json.loads(doc.get("raw") or doc["text"])
    rows = data.get("data") or []
    if not rows:
        return "no EPSS score published", {"cve": value}
    r = rows[0]
    score, pct = float(r.get("epss", 0)), float(r.get("percentile", 0))
    return (f"EPSS {score:.3f} (higher than {pct * 100:.0f}% of scored CVEs) on {r.get('date', '')}",
            {"cve": value, "epss": score, "percentile": pct, "date": r.get("date", "")})


def _vcard_name(ent: dict) -> str:
    for item in (ent.get("vcardArray") or [None, []])[1] or []:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return str(item[3])
    return ""


def rdap(value: str, etype: str, fetch) -> tuple[str, dict]:
    kind = "domain" if etype == "domain" else "ip"
    doc = fetch(f"https://rdap.org/{kind}/{quote(value)}", want_raw=True)
    data = json.loads(doc.get("raw") or doc["text"])
    events = {e.get("eventAction"): e.get("eventDate", "") for e in data.get("events") or [] if isinstance(e, dict)}
    registrar = next((_vcard_name(e) for e in data.get("entities") or []
                      if isinstance(e, dict) and "registrar" in (e.get("roles") or [])), "")
    out = {"handle": data.get("handle", ""), "name": data.get("name", "") or data.get("ldhName", ""),
           "status": data.get("status") or [], "registered": events.get("registration", ""),
           "expires": events.get("expiration", ""), "last_changed": events.get("last changed", ""),
           "registrar": registrar, "country": data.get("country", ""),
           "range": " - ".join(x for x in (data.get("startAddress", ""), data.get("endAddress", "")) if x)}
    out = {k: v for k, v in out.items() if v}
    if kind == "domain":
        age = ""
        if out.get("registered"):
            try:
                days = (datetime.now(timezone.utc) - datetime.fromisoformat(out["registered"].replace("Z", "+00:00"))).days
                out["age_days"] = days
                age = f", registered {days} days ago"
            except ValueError:
                pass
        return f"{out.get('registrar') or 'registrar unknown'}{age}", out
    return f"{out.get('name', '')} {out.get('country', '')} {out.get('range', '')}".strip(), out


def enrich(cfg, store: KnowledgeStore, entity_id: int, *, only: str | None = None, actor: str = "", hub=None,
           fetch=None, force: bool = False) -> list[dict]:
    """Run every matching enricher (or ``only`` one) on an entity. Returns what each one said."""
    e = store.entity(entity_id)
    if not e:
        raise ValueError(f"no entity {entity_id}")
    s = settings(cfg)
    res = Results(store)
    if hub is None:
        from ..connectors import get_hub
        hub = get_hub(cfg)
    if fetch is None:
        from ..collect.fetch import fetch_url
        fetch = fetch_url
    out = []
    for en in enrichers_for(cfg, hub, e["type"]):
        if only and en["name"] != only:
            continue
        if not force and res.recent(entity_id, en["name"], s["cache_hours"]):
            out.append({"enricher": en["name"], "ok": True, "summary": "cached", "cached": True})
            continue
        try:
            if en["kind"] == "connector":
                args = {**en["arguments"], en["argument"]: e["value"]}
                r = hub.call(en["connector"], en["tool"], args, actor=actor or "enrich", ref=f"entity:{entity_id}")
                from ..collect.collector import _unwrap
                body = _unwrap(r["content"])
                ok = not r.get("is_error")
                summary = body.strip().splitlines()[0][:200] if body.strip() else "(empty)"
                data: Any = body
            else:
                if private_value(cfg, e["value"]):
                    out.append({"enricher": en["name"], "ok": False,
                                "summary": "not sent: an internal address or one of your own terms"})
                    continue
                summary, data = (epss(e["value"], fetch) if en["name"] == "epss"
                                 else rdap(e["value"], e["type"], fetch))
                ok = True
        except Exception as exc:            # one failing enricher must not stop the others
            ok, summary, data = False, str(exc)[:300], ""
        res.add(entity_id, en["name"], ok=ok, summary=summary, data=data, actor=actor or "enrich")
        if ok and en["name"] == "epss" and isinstance(data, dict) and data.get("percentile", 0) >= 0.9:
            store.add_tags(entity_id, ["epss-top10"])
        out.append({"enricher": en["name"], "ok": ok, "summary": summary})
    return out


def auto_candidates(store: KnowledgeStore, cfg, document_id: int) -> list[int]:
    """New malicious indicators in a document, for ``enrich.auto``."""
    s = settings(cfg)
    if not s["auto"]:
        return []
    ids = []
    for m in store.mentions(document_id=document_id, limit=500):
        if m["type"] in s["auto_types"] and m["context"] == "malicious" and m["entity_id"] not in ids:
            ids.append(m["entity_id"])
    res = Results(store)
    used = res.count_since(24, "auto")
    ids = [i for i in ids if not any(r["ok"] for r in res.for_entity(i, limit=1))]
    return ids[: max(0, s["max_per_day"] - used)]


def is_pg() -> bool:
    return db.is_pg()
