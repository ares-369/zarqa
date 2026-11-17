"""Collect intel from the internet, from other platforms, and from what people add.

Sources are listed in ``config.yaml``::

    sources:
      - name: gov-advisories
        kind: feed                 # RSS or Atom; each new item's article is fetched (fetch_articles)
        url: "https://example.org/advisories.xml"
        interval_minutes: 60       # 0 = only when pulled by hand
        keywords: []               # keep only items that mention one of these (optional)
        max_items: 20
      - name: vendor-research
        kind: page                 # one page, stored again when its text changes
        url: "https://example.org/research/"
      - name: blocklist
        kind: list                 # indicator list: text (one per line), csv, json or stix
        url: "https://example.org/ips.txt"
        format: text
        type: ipv4                 # optional; otherwise each value's type is detected
        value_field: ""            # csv column / json field
        list_key: ""               # json: dot path to the list
        headers_env: {}            # header -> name of a .env variable, e.g. {X-API-Key: FEED_KEY}
      - name: platform
        kind: connector            # call a connector tool; STIX in the result is imported, other text is a document
        connector: sharing-server
        tool: get_objects
        arguments: {collection: "c1"}

Every web request goes through the safe fetcher (http(s) only, private addresses refused on every
redirect hop, size cap). Feed items are remembered by link, so each article is stored once.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import xml.etree.ElementTree as ET
from typing import Any

from ..intel.extract import extract, guess_type
from ..intel.store import KnowledgeStore
from .fetch import FetchError, fetch_url, html_to_text, read_file

KINDS = ("feed", "page", "list", "connector")
FORMATS = ("text", "csv", "json", "stix")
_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
_NS = {"atom": "http://www.w3.org/2005/Atom"}


def validate_source(s: dict) -> dict:
    if not isinstance(s, dict):
        raise ValueError("each source must be a mapping")
    name = str(s.get("name", ""))
    if not _NAME.fullmatch(name):
        raise ValueError(f"source name {name!r} must be lowercase letters, digits, _ or - (max 40)")
    kind = s.get("kind", "feed")
    if kind not in KINDS:
        raise ValueError(f"source {name}: kind must be one of {KINDS}")
    if kind == "connector":
        if not s.get("connector") or not s.get("tool"):
            raise ValueError(f"source {name}: a connector source needs connector and tool")
        if not isinstance(s.get("arguments", {}) or {}, dict):
            raise ValueError(f"source {name}: arguments must be a mapping")
    elif not str(s.get("url", "")).startswith(("https://", "http://")):
        raise ValueError(f"source {name}: url must be http(s)")
    if kind == "list" and s.get("format", "text") not in FORMATS:
        raise ValueError(f"source {name}: format must be one of {FORMATS}")
    for k in ("interval_minutes", "max_items", "confidence"):
        if k in s and not isinstance(s[k], int):
            raise ValueError(f"source {name}: {k} must be a whole number")
    if "reliability" in s:
        from ..intel.credibility import valid_letter
        if not valid_letter(s["reliability"]):
            raise ValueError(f"source {name}: reliability must be a letter A-F (Admiralty scale)")
    if not isinstance(s.get("headers_env", {}) or {}, dict):
        raise ValueError(f"source {name}: headers_env must be a mapping of header to .env variable")
    return s


def sources_from(cfg) -> list[dict]:
    items = list(((cfg.raw or {}).get("sources") or []) if cfg is not None else [])
    out = [validate_source(dict(s)) for s in items]
    names = [s["name"] for s in out]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ValueError(f"duplicate source names: {dupes}")
    return out


def parse_feed(xml_text: str) -> list[dict]:
    """Items from an RSS 2.0 or Atom document: [{title, link, summary, published}]."""
    head = xml_text if isinstance(xml_text, str) else xml_text.decode("utf-8", "replace")
    if "<!ENTITY" in head.upper() or "<!DOCTYPE" in head.upper():
        raise FetchError("feed declares a DOCTYPE or XML entities; refused")
    # Safe: DOCTYPE/entities refused above, and ElementTree never fetches external resources.
    root = ET.fromstring(head.encode())  # nosec B314
    items = []
    for it in root.iter("item"):
        items.append({"title": (it.findtext("title") or "").strip(), "link": (it.findtext("link") or "").strip(),
                      "summary": (it.findtext("description") or "").strip(),
                      "published": (it.findtext("pubDate") or "").strip()})
    for it in root.iter("{http://www.w3.org/2005/Atom}entry"):
        link = ""
        for ln in it.findall("atom:link", _NS):
            if ln.get("rel", "alternate") == "alternate":
                link = ln.get("href", "")
                break
        items.append({"title": (it.findtext("atom:title", default="", namespaces=_NS) or "").strip(), "link": link,
                      "summary": (it.findtext("atom:summary", default="", namespaces=_NS)
                                  or it.findtext("atom:content", default="", namespaces=_NS) or "").strip(),
                      "published": (it.findtext("atom:published", default="", namespaces=_NS)
                                    or it.findtext("atom:updated", default="", namespaces=_NS) or "").strip()})
    return items


def _dig(obj: Any, path: str) -> Any:
    for part in [p for p in (path or "").split(".") if p]:
        obj = obj.get(part) if isinstance(obj, dict) else None
    return obj


def parse_list(content: str, fmt: str, *, value_field: str = "", list_key: str = "") -> list[str]:
    """Values from an indicator list (text, csv or json)."""
    if fmt == "text":
        return [ln.strip().split()[0] for ln in content.splitlines()
                if ln.strip() and not ln.lstrip().startswith(("#", ";", "//"))]
    if fmt == "csv":
        rows = [r for r in csv.reader(io.StringIO(content)) if r and not r[0].lstrip().startswith("#")]
        if not rows:
            return []
        head = [h.strip() for h in rows[0]]
        if value_field and value_field in head:
            i, body = head.index(value_field), rows[1:]
        else:
            i = 0
            body = rows[1:] if guess_type(rows[0][0].strip()) is None else rows
        return [r[i].strip() for r in body if len(r) > i and r[i].strip()]
    data = json.loads(content)
    items = _dig(data, list_key) if list_key else data
    if not isinstance(items, list):
        raise ValueError("list_key does not point at a JSON list")
    vals = []
    for it in items:
        v = _dig(it, value_field) if value_field and isinstance(it, dict) else it
        if isinstance(v, (str, int)):
            vals.append(str(v))
    return vals


class Collector:
    def __init__(self, cfg, store: KnowledgeStore, *, fetch=None, hub=None):
        self.cfg = cfg
        self.store = store
        c = ((cfg.raw or {}).get("collect") or {}) if cfg is not None else {}
        self.allow_private = bool(c.get("allow_private_urls", False))
        self.fetch_articles = bool(c.get("fetch_articles", True))
        self.max_chars = int(c.get("max_document_chars", 200_000))
        self.default_reliability = str(c.get("default_reliability", "F")).upper()
        self.manual_reliability = str(c.get("manual_reliability", "F")).upper()
        self._fetch = fetch or fetch_url
        self._hub = hub

    def _get(self, url: str, **kw) -> dict:
        return self._fetch(url, allow_private=self.allow_private, **kw)

    # ---- configured sources ----
    def pull(self, src: dict, *, actor: str = "scheduler") -> dict:
        src = validate_source(src)
        out: dict[str, Any] = {"source": src["name"], "new_documents": [], "values": 0, "skipped": 0, "errors": []}
        try:
            getattr(self, "_" + src.get("kind", "feed"))(src, out, actor)
            self.store.record_pull(src["name"], ok=True, documents=len(out["new_documents"]))
        except (FetchError, ET.ParseError, OSError, ValueError, KeyError) as exc:
            out["errors"].append(str(exc)[:300])
            self.store.record_pull(src["name"], ok=False, error=str(exc))
        return out

    def _wanted(self, src: dict, text: str) -> bool:
        kws = [k.lower() for k in src.get("keywords") or []]
        return not kws or any(k in text.lower() for k in kws)

    def _doc(self, src: dict, *, kind: str, text: str, url: str, title: str, published: str = "",
             actor: str = "") -> dict:
        return self.store.add_document(source=src["name"], kind=kind, text=text, url=url, title=title,
                                       published=published, tags=list(src.get("tags") or []), added_by=actor,
                                       max_chars=self.max_chars,
                                       reliability=str(src.get("reliability", self.default_reliability)))

    def _feed(self, src: dict, out: dict, actor: str) -> None:
        doc = self._get(src["url"])
        items = parse_feed(doc.get("raw") or doc["text"])
        for it in items[: int(src.get("max_items", 20))]:
            key = f"{src['name']}|{it['link'] or hashlib.sha256((it['title'] + it['summary']).encode()).hexdigest()}"
            if self.store.seen(key):
                continue
            text = html_to_text(it["summary"])[1] if "<" in it["summary"] else it["summary"]
            if it["link"] and src.get("fetch_articles", self.fetch_articles):
                try:
                    art = self._get(it["link"])
                    text = f"{text}\n\n{art['text']}".strip()
                except FetchError as exc:
                    out["errors"].append(f"{it['link']}: {exc}"[:300])
            if not text.strip() or not self._wanted(src, f"{it['title']}\n{text}"):
                self.store.mark_seen(key, src["name"], None)
                out["skipped"] += 1
                continue
            r = self._doc(src, kind="feed", text=f"{it['title']}\n\n{text}", url=it["link"], title=it["title"],
                          published=it.get("published", ""), actor=actor)
            self.store.mark_seen(key, src["name"], r["id"])
            if r["new"]:
                out["new_documents"].append(r["id"])

    def _page(self, src: dict, out: dict, actor: str) -> None:
        doc = self._get(src["url"])
        if not self._wanted(src, doc["text"]):
            out["skipped"] += 1
            return
        r = self._doc(src, kind="page", text=doc["text"], url=src["url"], title=doc.get("title") or src["name"],
                      actor=actor)
        if r["new"]:
            out["new_documents"].append(r["id"])

    def _headers(self, src: dict) -> dict:
        return {str(h): os.getenv(str(v), "") for h, v in (src.get("headers_env") or {}).items()}

    def _list(self, src: dict, out: dict, actor: str) -> None:
        doc = self._get(src["url"], want_raw=True, headers=self._headers(src))
        raw = doc.get("raw") or doc["text"]
        fmt = src.get("format", "text")
        if fmt == "stix":
            from .stix_in import import_bundle
            r = import_bundle(self.store, raw, source=src["name"], url=src["url"],
                              confidence=int(src.get("confidence", 60)), tags=list(src.get("tags") or []),
                              added_by=actor, reliability=str(src.get("reliability", self.default_reliability)))
            out["values"] += r["indicators"] + r["entities"]
            out["new_documents"] += r["reports"]
            return
        vals = parse_list(raw, fmt, value_field=str(src.get("value_field", "")), list_key=str(src.get("list_key", "")))
        vals = vals[: int(src.get("max_items", 100_000))]
        self._import_values(src, vals, out, actor, url=src["url"])

    def _import_values(self, src: dict, vals: list[str], out: dict, actor: str, *, url: str = "") -> None:
        text = f"Indicator list {src['name']} ({len(vals)} values)\n" + "\n".join(vals[:5000])
        d = self._doc(src, kind="list", text=text, url=url, title=f"{src['name']}: {len(vals)} values", actor=actor)
        self.store.update_document(d["id"], status="extracted", method="list")
        kind = src.get("type")
        for v in vals:
            k = kind or guess_type(v)
            if not k or k == "technique":
                out["skipped"] += 1
                continue
            try:
                e = self.store.upsert_entity(k, v, confidence=int(src.get("confidence", 50)),
                                             tags=list(src.get("tags") or []))
            except ValueError:
                out["skipped"] += 1
                continue
            self.store.add_mention(e["id"], d["id"], method="feed", context=str(src.get("context", "malicious")))
            out["values"] += 1
        from ..intel.credibility import refresh_document
        refresh_document(self.store, d["id"])

    def _connector(self, src: dict, out: dict, actor: str) -> None:
        from ..connectors import get_hub
        hub = self._hub or get_hub(self.cfg)
        res = hub.call(src["connector"], src["tool"], dict(src.get("arguments") or {}),
                       actor=f"source:{src['name']}", ref=f"source:{src['name']}", max_bytes=2_000_000)
        if res.get("is_error"):
            raise ValueError(f"{src['connector']}/{src['tool']} returned an error: {res['content'][:200]}")
        body = _unwrap(res["content"])
        try:
            data = json.loads(body)
        except ValueError:
            data = None
        if data is not None:
            from .stix_in import load
            try:
                objs = load(data)
            except ValueError:
                objs = []
            if objs and any(str(o.get("type", "")) in ("indicator", "report", "malware", "intrusion-set",
                                                        "threat-actor", "campaign", "relationship") for o in objs):
                from .stix_in import import_bundle
                r = import_bundle(self.store, {"objects": objs}, source=src["name"], method="connector",
                                  confidence=int(src.get("confidence", 60)), tags=list(src.get("tags") or []),
                                  added_by=actor, reliability=str(src.get("reliability", self.default_reliability)))
                out["values"] += r["indicators"] + r["entities"]
                out["new_documents"] += r["reports"]
                return
        r = self._doc(src, kind="connector", text=body, url="", title=f"{src['name']}: {src['tool']}", actor=actor)
        if r["new"]:
            out["new_documents"].append(r["id"])

    # ---- added by people ----
    def add_text(self, text: str, *, title: str = "", url: str = "", actor: str = "", tags: list[str] | None = None) -> dict:
        return self.store.add_document(source="manual", kind="text", text=text, url=url, title=title or text[:80],
                                       tags=tags, added_by=actor, max_chars=self.max_chars, reliability=self.manual_reliability)

    def add_url(self, url: str, *, actor: str = "", tags: list[str] | None = None) -> dict:
        doc = self._get(url)
        return self.store.add_document(source="manual", kind="url", text=doc["text"], url=doc.get("url", url),
                                       title=doc.get("title") or url, tags=tags, added_by=actor,
                                       max_chars=self.max_chars, reliability=self.manual_reliability)

    def add_file(self, path: str, *, actor: str = "", tags: list[str] | None = None) -> dict:
        if path.lower().endswith(".json"):
            raw = open(path, encoding="utf-8", errors="replace").read()  # noqa: SIM115
            try:
                from .stix_in import import_bundle
                r = import_bundle(self.store, raw, source="manual", tags=tags, method="manual", added_by=actor,
                                  reliability=self.manual_reliability)
                return {"id": r["document_id"], "new": True, "stix": r}
            except ValueError:
                pass
        doc = read_file(path)
        return self.store.add_document(source="manual", kind="file", text=doc["text"], title=doc.get("title", path),
                                       tags=tags, added_by=actor, max_chars=self.max_chars, reliability=self.manual_reliability)

    def add_values(self, values: list[str], *, actor: str = "", context: str = "malicious", tags: list[str] | None = None,
                   confidence: int = 60) -> dict:
        out = {"new_documents": [], "values": 0, "skipped": 0, "errors": []}
        found = [v for vals in extract("\n".join(values)).values() for v in vals]
        src = {"name": "manual", "context": context, "confidence": confidence, "tags": tags or [],
               "reliability": self.manual_reliability}
        self._import_values(src, found, out, actor)
        return out


_WRAP = re.compile(r"^<<UNTRUSTED-DATA [^>]*>>\n|\n<<END-UNTRUSTED-DATA [^>]*>>$")


def _unwrap(content: str) -> str:
    return _WRAP.sub("", content or "")
