"""How much does a document matter to this organization? A score from 0 to 100, with the reasons.

Rules first (no model, always):

* your products, brands and domains named in the document;
* your sectors and regions named, or targeted (from extraction: sector and country entities);
* CVEs in the document that are known exploited (tagged ``kev`` by a list source) or in the top 10% by
  EPSS (tagged ``epss-top10``);
* your intelligence requirements (``requirements:``): a requirement matches when one of its terms is in
  the document; the document is tagged ``pir:<name>``;
* malicious indicators to act on.

Then, if ``relevance.model: true`` and the rules found anything, the analyst model reads the profile and the
document and gives its own score and one-sentence reason. Its score replaces the rules score; the reasons from
both are kept. Documents that match nothing at all are never sent to the model.

Without an organization profile and requirements nothing is scored (the score stays empty), because a
number with nothing behind it would mislead.
"""

from __future__ import annotations

import re
from typing import Any

from ..connectors.untrusted import SYSTEM_RULE
from .store import INDICATOR_TYPES, KnowledgeStore

WEIGHTS = {"product": 35, "brand": 40, "domain": 45, "sector": 15, "region": 10, "targeted": 15, "kev": 20,
           "epss": 10, "requirement": 25, "indicators": 5}

SYSTEM = f"""You rate how relevant one threat intelligence document is to ONE organization.
High (70-100): it names a product, brand or domain the organization uses, or a threat actively targeting its
sector and region, with something the organization can act on. Medium (30-69): related sector, region or
technology, or a threat worth knowing about. Low (0-29): general news, other sectors, nothing to act on.
Reply with ONE JSON object only: {{"score": 0-100, "why": "one sentence naming what matters to this organization",
"requirements": ["names of the listed intelligence requirements this document answers"]}}
{SYSTEM_RULE}"""


def _list(v) -> list[str]:
    if isinstance(v, str):
        v = [v]
    return [str(x).strip() for x in (v or []) if str(x).strip()]


def profile(cfg) -> dict:
    raw = (cfg.raw or {}) if cfg is not None else {}
    org = raw.get("organization") or {}
    reqs = []
    for r in raw.get("requirements") or []:
        if isinstance(r, dict) and r.get("name"):
            reqs.append({"name": str(r["name"])[:60], "question": str(r.get("question", ""))[:300],
                         "terms": _list(r.get("terms"))})
    return {"name": str(org.get("name", "")), "products": _list(org.get("products")), "brands": _list(org.get("brands")),
            "domains": _list(org.get("domains")), "sectors": _list(org.get("sectors")),
            "regions": _list(org.get("regions")), "notes": _list(org.get("notes")), "requirements": reqs}


def validate(raw: dict) -> None:
    names = []
    for r in raw.get("requirements") or []:
        if not isinstance(r, dict) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,39}", str(r.get("name", ""))):
            raise ValueError("requirements: each needs a name (lowercase letters, digits, _ or -), a question and terms")
        if not _list(r.get("terms")):
            raise ValueError(f"requirement {r['name']}: list at least one term")
        names.append(r["name"])
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ValueError(f"requirements: duplicate names {dupes}")
    org = raw.get("organization") or {}
    if not isinstance(org, dict):
        return                          # the config loader reports a non-mapping organization with its own message
    for k in ("products", "brands", "domains", "sectors", "regions", "notes"):
        v = org.get(k)
        if v is not None and not isinstance(v, (list, str)):
            raise ValueError(f"organization.{k}: a list of names")


ORG_FIELDS = ("name", "sectors", "regions", "products", "brands", "domains", "notes")


def clean_profile(body: dict) -> tuple[dict, list[dict]]:
    """An organization profile and requirements from the UI or API, tidied: lists of short unique strings."""
    def lst(v, n=200, size=120):
        items = v.splitlines() if isinstance(v, str) else (v or [])
        out = []
        for x in items:
            for part in (str(x).split(",") if not isinstance(v, str) else [str(x)]):
                t = part.strip()[:size]
                if t and t.lower() not in {o.lower() for o in out}:
                    out.append(t)
        return out[:n]
    org_in = body.get("organization") or {}
    org = {"name": str(org_in.get("name", "")).strip()[:120]}
    for k in ORG_FIELDS[1:]:
        org[k] = lst(org_in.get(k), size=300 if k == "notes" else 120)
    org["domains"] = [d.lower().strip(".") for d in org["domains"]]
    reqs = []
    for r in body.get("requirements") or []:
        if not isinstance(r, dict):
            continue
        name = re.sub(r"[^a-z0-9_-]+", "-", str(r.get("name", "")).strip().lower()).strip("-")[:40]
        terms = lst(r.get("terms"), n=50, size=80)
        if name or terms:
            reqs.append({"name": name, "question": str(r.get("question", "")).strip()[:300], "terms": terms})
    return {k: v for k, v in org.items() if v}, reqs


def has_profile(p: dict) -> bool:
    return any(p[k] for k in ("products", "brands", "domains", "sectors", "regions", "requirements"))


def _hits(text: str, terms: list[str]) -> list[str]:
    low = text.lower()
    out = []
    for t in terms:
        if len(t) >= 2 and re.search(r"(?<![a-z0-9])" + re.escape(t.lower()) + r"(?![a-z0-9])", low):
            out.append(t)
    return out


def rules_score(p: dict, doc: dict, mentions: list[dict], entities: dict[int, dict]) -> dict[str, Any]:
    text = f"{doc.get('title', '')}\n{doc.get('text', '')}"[:300_000]
    reasons: list[str] = []
    score = 0
    for key, label in (("products", "product"), ("brands", "brand"), ("domains", "domain")):
        h = _hits(text, p[key])
        if h:
            score += WEIGHTS[label]
            reasons.append(f"names your {label}{'s' if len(h) > 1 else ''} {', '.join(h[:5])}")
    targeted = {m["display"].lower() for m in mentions if m["type"] in ("sector", "country")}
    for key, label in (("sectors", "sector"), ("regions", "region")):
        h = _hits(text, p[key])
        if h:
            score += WEIGHTS[label]
            hit_t = [x for x in h if x.lower() in targeted]
            if hit_t:
                score += WEIGHTS["targeted"]
                reasons.append(f"targets your {label} {', '.join(hit_t[:3])}")
            else:
                reasons.append(f"mentions your {label} {', '.join(h[:3])}")
    cves = [entities[m["entity_id"]] for m in mentions if m["type"] == "cve" and m["entity_id"] in entities]
    kev = sorted({c["display"] for c in cves if "kev" in c.get("tags", [])})
    if kev:
        score += WEIGHTS["kev"]
        reasons.append(f"known exploited: {', '.join(kev[:5])}")
    hot = sorted({c["display"] for c in cves if "epss-top10" in c.get("tags", [])} - set(kev))
    if hot:
        score += WEIGHTS["epss"]
        reasons.append(f"likely to be exploited (EPSS top 10%): {', '.join(hot[:5])}")
    pirs = []
    for r in p["requirements"]:
        h = _hits(text, r["terms"])
        if h:
            pirs.append(r["name"])
            reasons.append(f"requirement {r['name']}: {', '.join(h[:3])}")
    if pirs:
        score += WEIGHTS["requirement"]
    bad = {m["entity_id"] for m in mentions if m["type"] in INDICATOR_TYPES and m["context"] == "malicious"}
    if bad and score:
        score += WEIGHTS["indicators"]
        reasons.append(f"{len(bad)} malicious indicator{'s' if len(bad) > 1 else ''} to check")
    return {"score": min(100, score), "reasons": reasons, "requirements": pirs}


def _context(p: dict) -> str:
    parts = [f"Organization: {p['name']}" if p["name"] else "Organization (name not given)"]
    for k in ("sectors", "regions", "products", "brands", "domains", "notes"):
        if p[k]:
            parts.append(f"{k}: {', '.join(p[k][:40])}")
    if p["requirements"]:
        parts.append("Intelligence requirements:\n" + "\n".join(
            f"- {r['name']}: {r['question'] or ', '.join(r['terms'])}" for r in p["requirements"]))
    return "\n".join(parts)


def score_document(cfg, store: KnowledgeStore, doc_id: int, *, llm=None) -> dict[str, Any]:
    p = profile(cfg)
    doc = store.document(doc_id)
    if not doc:
        raise ValueError(f"no document {doc_id}")
    why = ("no organization profile or requirements set" if not has_profile(p)
           else "an indicator list or STIX bundle record, not a report" if doc.get("kind") in ("list", "stix") else "")
    if why:
        if doc.get("relevance") is not None:
            store.update_document(doc_id, relevance=None, relevance_reason="")
        return {"score": None, "reasons": [why], "method": "none"}
    mentions = store.mentions(document_id=doc_id, limit=2000)
    entities = {m["entity_id"]: store.entity(m["entity_id"]) for m in mentions if m["type"] == "cve"}
    r = rules_score(p, doc, mentions, {k: v for k, v in entities.items() if v})
    r["method"] = "rules"
    use_model = bool(((cfg.raw or {}).get("relevance") or {}).get("model", False)) if cfg is not None else False
    if use_model and llm is not None and r["score"] > 0:
        from ..jsonparse import first_object
        user = (f"{_context(p)}\n\nWhat fixed rules found: {'; '.join(r['reasons']) or 'nothing'}\n\n"
                f"Document (untrusted):\n<<UNTRUSTED-DATA document>>\nTitle: {doc.get('title', '')}\n"
                f"Summary: {doc.get('summary', '')}\n{(doc.get('text') or '')[:6000]}\n<<END-UNTRUSTED-DATA document>>")
        res = llm.for_role("analyst").chat([{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                                           max_tokens=400)
        obj = first_object(res.text or "") if not res.error else None
        if isinstance(obj, dict) and "score" in obj:
            try:
                ms = max(0, min(100, int(obj["score"])))
            except (TypeError, ValueError):
                ms = None
            if ms is not None:
                known = {x["name"] for x in p["requirements"]}
                extra = [str(x) for x in obj.get("requirements") or [] if str(x) in known and str(x) not in r["requirements"]]
                r.update(score=ms, method="rules+model", requirements=r["requirements"] + extra)
                if obj.get("why"):
                    r["reasons"] = [f"model: {str(obj['why'])[:300]}", *r["reasons"]]
        else:
            r["reasons"].append(f"model check failed: {(res.error or 'no JSON')[:100]}")
    tags = [t for t in doc.get("tags", []) if not t.startswith("pir:")] + [f"pir:{n}" for n in r["requirements"]]
    store.update_document(doc_id, relevance=r["score"], relevance_reason="; ".join(r["reasons"])[:1000], tags=tags)
    return r
