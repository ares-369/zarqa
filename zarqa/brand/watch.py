"""Brand watch: which lookalikes of your domains exist, and do they look like they are aimed at you?

For each watched domain (``brand.watch``, or ``organization.domains`` with ``organization.brands`` as the
names to look for in pages):

1. Generate lookalike names (``permute.py``), at most ``max_candidates``.
2. Optionally add names from certificate transparency logs that contain the brand (``brand.ct``).
3. Resolve each name (A/AAAA and MX) with this machine's resolver; names that do not resolve are dropped.
4. For names that resolve: registration date from RDAP (``brand.rdap``) and a page check (``brand.page_check``):
   the page title, whether it shows the brand, and whether it asks for a password.
5. Score 0-100 and keep each finding with its history: first and last seen, the evidence, and a status
   (new, reviewing, benign, takedown, closed) that people set.

Lookups reveal to your DNS resolver, the RDAP service and (with ``ct``) the log search service which names
you are checking. The watch only runs when ``brand.watch`` or organization domains are set.
"""

from __future__ import annotations

import json
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import db
from ..intel.store import now
from .permute import permutations, registered_part, similarity

STATUSES = ("new", "reviewing", "benign", "takedown", "closed")
TECH_WEIGHT = {"homoglyph": 25, "transposition": 20, "omission": 20, "repetition": 18, "replacement": 18,
               "vowel": 15, "insertion": 12, "bitsquat": 10, "hyphen": 15, "word": 20, "tld": 12, "subdomain": 10,
               "ct": 15}


def settings(cfg) -> dict:
    raw = (cfg.raw or {}) if cfg is not None else {}
    b = raw.get("brand") or {}
    org = raw.get("organization") or {}
    watch = []
    for w in b.get("watch") or []:
        if isinstance(w, dict) and w.get("domain"):
            watch.append({"domain": str(w["domain"]).lower().strip("."),
                          "names": [str(x) for x in (w.get("names") or [])] or [str(w["domain"]).split(".")[0]]})
    if not watch:
        names = [str(x) for x in org.get("brands") or []]
        for d in org.get("domains") or []:
            watch.append({"domain": str(d).lower().strip("."), "names": names or [str(d).split(".")[0]]})
    return {"watch": watch, "interval_minutes": int(b.get("interval_minutes", 0) or 0),
            "max_candidates": int(b.get("max_candidates", 3000)), "workers": max(1, min(64, int(b.get("workers", 16)))),
            "ct": bool(b.get("ct", False)), "rdap": bool(b.get("rdap", True)), "page_check": bool(b.get("page_check", True)),
            "min_score": int(b.get("min_score", 0)), "timeout_sec": float(b.get("timeout_sec", 10)),
            "rdap_per_min": max(1, int(b.get("rdap_per_min", 30))),
            "own": [str(x).lower() for x in (b.get("own_domains") or [])] + [str(x).lower() for x in org.get("domains") or []], "ignore": [str(x).lower() for x in b.get("ignore") or []]}


def validate(raw: dict) -> None:
    b = raw.get("brand") or {}
    if not isinstance(b, dict):
        raise ValueError("brand: must be a mapping")
    for w in b.get("watch") or []:
        if not isinstance(w, dict) or "." not in str(w.get("domain", "")):
            raise ValueError("brand.watch: each entry needs a domain (and optional names)")


class BrandStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS brand_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL UNIQUE, watched TEXT NOT NULL,
                technique TEXT, similarity INTEGER, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                score INTEGER, evidence TEXT DEFAULT '{}', status TEXT NOT NULL DEFAULT 'new', note TEXT DEFAULT '',
                updated_by TEXT DEFAULT '', resolves INTEGER DEFAULT 1);
            CREATE TABLE IF NOT EXISTS brand_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT, finished TEXT, candidates INTEGER, resolving INTEGER,
                new INTEGER, errors TEXT DEFAULT '');
            """)

    def _conn(self):
        return db.connect(self.path, timeout=30)

    def upsert(self, f: dict) -> bool:
        ts = now()
        with self._lock, self._conn() as c:
            r = c.execute("SELECT id FROM brand_findings WHERE domain=?", (f["domain"],)).fetchone()
            ev = json.dumps(f["evidence"], ensure_ascii=False)
            if r:
                c.execute("UPDATE brand_findings SET last_seen=?, score=?, evidence=?, resolves=1 WHERE id=?",
                          (ts, f["score"], ev, r[0]))
                c.commit()
                return False
            c.execute("INSERT INTO brand_findings (domain, watched, technique, similarity, first_seen, last_seen, score, "
                      "evidence) VALUES (?,?,?,?,?,?,?,?)", (f["domain"], f["watched"], f["technique"], f["similarity"],
                                                             ts, ts, f["score"], ev))
            c.commit()
            return True

    def mark_gone(self, watched: str, alive: set[str]) -> None:
        with self._lock, self._conn() as c:
            for (d,) in c.execute("SELECT domain FROM brand_findings WHERE watched=? AND resolves=1", (watched,)).fetchall():
                if d not in alive:
                    c.execute("UPDATE brand_findings SET resolves=0 WHERE domain=?", (d,))
            c.commit()

    def set_status(self, fid: int, status: str, note: str, who: str) -> None:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self._lock, self._conn() as c:
            c.execute("UPDATE brand_findings SET status=?, note=?, updated_by=? WHERE id=?", (status, note[:500], who[:100],
                                                                                         int(fid)))
            c.commit()

    def findings(self, *, status: str | None = None, min_score: int = 0, limit: int = 200) -> list[dict]:
        q, args = "SELECT * FROM brand_findings WHERE score >= ?", [int(min_score)]
        if status:
            q += " AND status=?"
            args.append(status)
        q += " ORDER BY resolves DESC, score DESC, last_seen DESC LIMIT ?"
        with self._conn() as c:
            rows = c.execute(q, (*args, int(limit))).fetchall()
        out = []
        for r in rows:
            d = dict(zip(r.keys(), r, strict=True))
            d["evidence"] = json.loads(d["evidence"] or "{}")
            d["resolves"] = bool(d["resolves"])
            out.append(d)
        return out

    def add_run(self, r: dict) -> None:
        with self._lock, self._conn() as c:
            c.execute("INSERT INTO brand_runs (started, finished, candidates, resolving, new, errors) VALUES (?,?,?,?,?,?)",
                      (r["started"], now(), r["candidates"], r["resolving"], r["new"], "; ".join(r["errors"])[:1000]))
            c.commit()

    def last_run(self) -> dict:
        with self._conn() as c:
            r = c.execute("SELECT * FROM brand_runs ORDER BY id DESC LIMIT 1").fetchone()
        return dict(zip(r.keys(), r, strict=True)) if r else {}


def store_for(cfg) -> BrandStore:
    return BrandStore(cfg.data_dir / "brand.sqlite")


def resolve(name: str, timeout: float = 3.0) -> dict:
    """{ips, mx} for a name; empty when it does not resolve. MX needs the optional dnspython package."""
    ips: list[str] = []
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        for info in socket.getaddrinfo(name, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except (OSError, UnicodeError):
        pass
    finally:
        socket.setdefaulttimeout(old)
    mx: list[str] = []
    try:
        import dns.resolver  # optional
        mx = sorted(str(r.exchange).rstrip(".") for r in dns.resolver.resolve(name, "MX", lifetime=timeout))
    except Exception:
        pass
    return {"ips": ips[:8], "mx": mx[:5]}


def ct_names(brand: str, fetch) -> list[str]:
    """Hostnames from certificate transparency logs that contain the brand string (public log search)."""
    doc = fetch(f"https://crt.sh/?q={quote('%' + brand + '%')}&output=json", want_raw=True)
    rows = json.loads(doc.get("raw") or doc["text"] or "[]")
    names = set()
    for r in rows[:5000]:
        for n in str(r.get("name_value", "")).lower().split("\n"):
            n = n.strip().lstrip("*.")
            if brand.lower() in n and "." in n:
                names.add(n)
    return sorted(names)


_PARKED = re.compile(r"for sale|buy this domain|domain (?:is )?parked|parked (?:free|domain)|coming soon|"
                                   r"this domain may be for sale|make an offer|domain name is available|under construction")


def page_check(domain: str, names: list[str], fetch) -> dict:
    from urllib.parse import urlparse
    err = ""
    for scheme in ("https", "http"):
        try:
            doc = fetch(f"{scheme}://{domain}/")
        except Exception as exc:
            err = str(exc)[:120]
            continue
        # the domain's own name is not the brand being shown: parked pages repeat it everywhere
        text = (doc.get("text") or "")[:50_000].lower().replace(domain.lower(), " ")
        raw = (doc.get("raw") or "")[:200_000].lower()
        title = (doc.get("title") or "").lower().replace(domain.lower(), " ")
        final = urlparse(doc.get("url", "")).hostname or domain
        return {"url": doc.get("url", ""), "title": (doc.get("title") or "")[:200],
                "shows_brand": [n for n in names if n.lower() in text or n.lower() in title],
                "asks_password": "password" in text or 'type="password"' in raw or "type=password" in raw,
                "parked": bool(_PARKED.search(f"{title} {text[:5000]}")),
                "redirects_to": final if registered_part(final) != registered_part(domain) else ""}
    return {"error": err or "no page"}


def score(technique: str, sim: int, ev: dict) -> int:
    if ev.get("redirects_to_you"):
        return 5            # sends visitors to your own site: most likely a defensive registration of yours
    s = TECH_WEIGHT.get(technique, 10) + (sim // 5)
    if ev.get("mx"):
        s += 15
    age = (ev.get("rdap") or {}).get("age_days")
    if isinstance(age, int):
        s += 25 if age <= 30 else 10 if age <= 180 else 0
    page = ev.get("page") or {}
    if page.get("parked"):
        s += 0              # registered and waiting: worth watching, nothing on it yet
    elif page.get("shows_brand"):
        s += 20
    if page.get("asks_password") and not page.get("parked"):
        s += 15
    return max(0, min(100, s))


def run(cfg, *, bstore: BrandStore | None = None, kstore=None, resolver=resolve, fetch=None, rdap_fn=None) -> dict[str, Any]:
    s = settings(cfg)
    bstore = bstore or store_for(cfg)
    if fetch is None:
        from ..collect.fetch import fetch_url

        def fetch(url, **kw):
            return fetch_url(url, timeout=s["timeout_sec"], **kw)
    if rdap_fn is None:
        from ..connectors.ratelimit import Pacer
        from ..intel.enrich import rdap as _rdap
        pacer = Pacer()

        def rdap_fn(d):
            pacer.acquire("rdap", s["rdap_per_min"])     # the public RDAP service limits request rates
            return _rdap(d, "domain", fetch)[1]
    out: dict[str, Any] = {"started": now(), "candidates": 0, "resolving": 0, "new": 0, "errors": [], "findings": []}
    if not s["watch"]:
        out["errors"].append("nothing to watch: set brand.watch or organization.domains")
        return out
    for w in s["watch"]:
        cands = dict((c, t) for c, t in permutations(w["domain"], limit=s["max_candidates"]))
        if s["ct"]:
            for n in w["names"]:
                try:
                    for h in ct_names(n, fetch):
                        reg = registered_part(h)
                        if reg != w["domain"] and reg not in cands:
                            cands[reg] = "ct"
                except Exception as exc:
                    out["errors"].append(f"certificate log search for {n}: {str(exc)[:150]}")
        cands = {c: t for c, t in cands.items() if c not in s["ignore"] and registered_part(c) != w["domain"]}
        out["candidates"] += len(cands)
        with ThreadPoolExecutor(max_workers=s["workers"]) as ex:
            results = dict(zip(cands, ex.map(resolver, cands), strict=True))
        alive = {c: r for c, r in results.items() if r["ips"] or r["mx"]}
        out["resolving"] += len(alive)
        own = {d["domain"] for d in s["watch"]} | set(s["own"])

        def check(item, names=tuple(w["names"]), own=frozenset(own)):
            dom, res = item
            ev: dict[str, Any] = {"ips": res["ips"], "mx": res["mx"]}
            if s["rdap"]:
                try:
                    ev["rdap"] = rdap_fn(registered_part(dom))
                except Exception as exc:
                    ev["rdap"] = {"error": str(exc)[:150]}
            if s["page_check"]:
                ev["page"] = page_check(dom, list(names), fetch)
                to = (ev["page"] or {}).get("redirects_to") or ""
                if to and registered_part(to) in own:
                    ev["redirects_to_you"] = True
            return dom, ev
        with ThreadPoolExecutor(max_workers=s["workers"]) as ex:
            checked = list(ex.map(check, alive.items()))
        for dom, ev in checked:
            tech = cands[dom]
            sim = similarity(dom, w["domain"])
            f = {"domain": dom, "watched": w["domain"], "technique": tech, "similarity": sim,
                 "score": score(tech, sim, ev), "evidence": ev}
            if f["score"] < s["min_score"]:
                continue
            if bstore.upsert(f):
                out["new"] += 1
                if kstore is not None:
                    try:
                        e = kstore.upsert_entity("domain", dom, confidence=f["score"], tags=[f"lookalike:{w['domain']}"])
                        kstore.add_tags(e["id"], [f"lookalike:{w['domain']}"])
                    except ValueError:
                        pass
            out["findings"].append({"domain": dom, "technique": tech, "score": f["score"]})
        bstore.mark_gone(w["domain"], set(alive))
    bstore.add_run(out)
    return out


def due(cfg, bstore: BrandStore) -> bool:
    s = settings(cfg)
    if not s["watch"] or s["interval_minutes"] <= 0:
        return False
    last = bstore.last_run().get("finished") or ""
    if not last:
        return True
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() >= s["interval_minutes"] * 60
    except ValueError:
        return True
