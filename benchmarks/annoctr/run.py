"""Extraction benchmark on AnnoCTR (test split): how well does Zarqa find malware, groups, tools and ATT&CK
techniques in real threat reports?

Data: https://github.com/boschresearch/anno-ctr-lrec-coling-2024 (CC-BY-SA 4.0; not copied into this repository).
Download it, then:

    python benchmarks/annoctr/run.py --data <path>/AnnoCTR --out results.json            # rules and ATT&CK names only
    python benchmarks/annoctr/run.py --data <path>/AnnoCTR --model ollama:qwen2.5-coder:7b \
        --base-url http://localhost:11434 --out results-7b.json                         # plus a model

Scoring is per document, on sets, summed over documents (micro):

* names: the gold MALWARE, GROUP and TOOL entities (their linked titles). A prediction (actor, malware, tool or
  campaign) matches a gold entity when the normalised names are equal, when it equals any way the document wrote
  that entity, or when both resolve to the same MITRE ATT&CK entry (aliases).
* techniques: gold technique IDs from the linked ATT&CK URLs, scored exactly and at the parent level
  (T1566.001 counts as T1566).
* grounding (with a model): how many items the model returned, how many the checks kept, and why the rest were
  dropped (the share dropped as "ungrounded" is the measured hallucination rate).

``--aliases`` scores alias resolution instead, with no model: every annotated mention (all splits) that the
annotators linked to an ATT&CK group or software entry is resolved with Zarqa's ATT&CK data, and counted as right
(same entry), wrong (another entry) or unresolved.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

NAME_TYPES = ("MALWARE", "GROUP", "TOOL")


def gold(data: Path, split: str = "test") -> dict[str, dict]:
    docs: dict[str, dict] = defaultdict(lambda: {"names": {}, "tech": set()})
    for line in (data / "linking_mitre_only" / f"{split}.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        d = docs[r["document"]]
        if r["entity_type"] in NAME_TYPES:
            d["names"].setdefault(r["label_title"], set()).add(r["mention"])
        elif r["entity_type"] == "TECHNIQUE":
            m = re.search(r"/techniques/(T\d{4})(?:/(\d{3}))?", r["label_link"])
            if m:
                tid = m.group(1) + (f".{m.group(2)}" if m.group(2) else "")
                from zarqa.intel import attack
                cur = attack.technique(tid)            # gold uses older ATT&CK: map retired IDs to current ones
                d["tech"].add(cur["id"] if cur else tid)
    return dict(docs)


def aliases(data: Path) -> dict:
    import glob
    from collections import Counter

    from zarqa.intel import attack
    pairs = []
    for f in sorted(glob.glob(str(data / "linking_mitre_only" / "*.jsonl"))):
        if "_w_" in f:
            continue
        for line in Path(f).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            m = re.search(r"attack\.mitre\.org/(groups|software|campaigns)/([GSC]\d{4})", r["label_link"])
            if m:
                pairs.append((r["mention"], m.group(2), r["label_title"], m.group(1)))
    out = Counter()
    wrong, unresolved = Counter(), Counter()
    by_kind = Counter()
    for mention, gid, title, kind in pairs:
        hit = attack.lookup(mention)
        short = len(mention.split()) <= 4
        key = "right" if hit and hit["id"] == gid else ("wrong" if hit else "unresolved")
        out[key] += 1
        out[f"{key}_short"] += short
        by_kind[(kind, key)] += 1
        if key == "wrong":
            wrong[f"{mention} -> {hit['name']} (gold {title})"] += 1
        elif key == "unresolved":
            unresolved[f"{mention} (gold {title})"] += 1
    n = len(pairs)
    short = out["right_short"] + out["wrong_short"] + out["unresolved_short"]
    return {"mentions": n, "right": out["right"], "wrong": out["wrong"], "unresolved": out["unresolved"],
            "accuracy": round(out["right"] / n, 3) if n else 0,
            "short_mentions": short, "accuracy_short": round(out["right_short"] / short, 3) if short else 0,
            "by_kind": {f"{k}:{v}": c for (k, v), c in sorted(by_kind.items())},
            "wrong_examples": wrong.most_common(15), "unresolved_examples": unresolved.most_common(25)}


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def name_matches(pred: str, title: str, mentions: set[str]) -> bool:
    from zarqa.intel import attack
    p = norm(pred)
    if p == norm(title) or p in {norm(m) for m in mentions}:
        return True
    a, b = attack.lookup(pred), attack.lookup(title)
    return bool(a and b and a["id"] == b["id"])


def score_names(pred: set[str], g: dict[str, set[str]]) -> tuple[int, int, int]:
    matched_gold, tp_pred = set(), 0
    for p in pred:
        hit = next((t for t, ms in g.items() if name_matches(p, t, ms)), None)
        if hit:
            tp_pred += 1
            matched_gold.add(hit)
    return len(matched_gold), len(pred) - tp_pred, len(g) - len(matched_gold)


def score_tech(pred: set[str], g: set[str], parent: bool) -> tuple[int, int, int]:
    if parent:
        pred, g = {t.split(".")[0] for t in pred}, {t.split(".")[0] for t in g}
    return len(pred & g), len(pred - g), len(g - pred)


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="the AnnoCTR folder (with text/ and linking_mitre_only/)")
    ap.add_argument("--model", default="", help="provider:model for the extractor role, e.g. ollama:qwen2.5-coder:7b")
    ap.add_argument("--base-url", default="")
    ap.add_argument("--split", default="test", choices=["test", "dev", "train"],
                    help="which AnnoCTR split (the phrase list was tuned on test; dev and train are unseen)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N documents")
    ap.add_argument("--start", type=int, default=0, help="skip the first N documents (to finish an interrupted run)")
    ap.add_argument("--out", default="")
    ap.add_argument("--aliases", action="store_true", help="score alias resolution only (no model, all splits)")
    a = ap.parse_args()
    data = Path(a.data)
    if a.aliases:
        res = aliases(data)
        print(json.dumps(res, indent=2))
        if a.out:
            Path(a.out).write_text(json.dumps(res, indent=2))
        return 0
    g = gold(data, a.split)
    names = sorted(g)[a.start:][: a.limit or None]
    home = Path(tempfile.mkdtemp(prefix="zarqa-bench-"))
    import yaml
    cfg = {"zarqa": {"data_dir": str(home / "data")}, "auth": {"mode": "none"}, "privacy": {"mask_for": []},
           "extract": {"model": bool(a.model), "chunk_chars": 12000, "max_chunks": 3, "strict_links": False},
           "llm": {"roles": {}, "providers": {}}}
    if a.model:
        prov, model = a.model.split(":", 1)
        cfg["llm"]["roles"]["extractor"] = {"provider": prov, "model": model}
        cfg["llm"]["providers"][prov] = {"default_model": model, **({"base_url": a.base_url} if a.base_url else {}),
                                         "num_ctx": 12288, "timeout_sec": 600}
    (home / "config.yaml").write_text(yaml.safe_dump(cfg))
    import os
    os.environ["ZARQA_HOME"] = str(home)
    os.environ["ZARQA_CONFIG"] = str(home / "config.yaml")
    from zarqa import config
    from zarqa.intel.service import process_documents
    from zarqa.intel.store import store_for
    c = config.get_config(reload=True)
    st = store_for(c)
    tot = {"names": [0, 0, 0], "tech": [0, 0, 0], "tech_parent": [0, 0, 0]}
    per_doc, t0, model_errors, calls = [], time.monotonic(), 0, 0
    from collections import Counter
    returned = kept = 0
    drop_reasons: Counter = Counter()
    for i, doc in enumerate(names, 1):
        text = (data / "text" / a.split / f"{doc}.txt").read_text(encoding="utf-8", errors="replace")
        d = st.add_document(source="annoctr", kind="text", text=text, title=doc)
        r = process_documents(c, [d["id"]], store=st)[0]
        m = r.get("model") or {}
        calls += m.get("calls", 0)
        model_errors += bool(m.get("errors"))
        model_drops = [x for x in r.get("dropped") or [] if x.get("why") != "rules"]
        kept += m.get("items", 0) + m.get("relations", 0) + m.get("labels", 0)
        returned += m.get("items", 0) + m.get("relations", 0) + m.get("labels", 0) + len(model_drops)
        for x in model_drops:
            drop_reasons[re.sub(r"\(.*\)|: .*| [0-9A-Z][^ ]*$", "", x["why"]).strip()[:60]] += 1
        ms = st.mentions(document_id=d["id"], limit=5000)
        pred_names = {x["display"] for x in ms if x["type"] in ("actor", "malware", "tool", "campaign")}
        pred_tech = {x["value"] for x in ms if x["type"] == "technique"}
        s = {"names": score_names(pred_names, g[doc]["names"]), "tech": score_tech(pred_tech, g[doc]["tech"], False),
             "tech_parent": score_tech(pred_tech, g[doc]["tech"], True)}
        for k, v in s.items():
            tot[k] = [x + y for x, y in zip(tot[k], v, strict=True)]
        per_doc.append({"document": doc, "pred_names": sorted(pred_names), "gold_names": sorted(g[doc]["names"]),
                        "pred_tech": sorted(pred_tech), "gold_tech": sorted(g[doc]["tech"]), "model_errors": m.get("errors")})
        print(f"[{i}/{len(names)}] {doc[:60]:60} names tp/fp/fn {s['names']}  tech {s['tech_parent']}", flush=True)
    res = {"dataset": f"AnnoCTR {a.split}", "documents": len(names), "config": {"model": a.model or "none (rules and ATT&CK names)"},
           "names": prf(*tot["names"]), "techniques_exact": prf(*tot["tech"]), "techniques_parent": prf(*tot["tech_parent"]),
           "model_calls": calls, "documents_with_model_errors": model_errors,
           "grounding": {"returned": returned, "kept": kept, "dropped": returned - kept,
                         "dropped_share": round((returned - kept) / returned, 3) if returned else None,
                         "reasons": dict(drop_reasons.most_common())},
           "seconds": round(time.monotonic() - t0), "per_document": per_doc}
    print(json.dumps({k: v for k, v in res.items() if k != "per_document"}, indent=2))
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=2))
    shutil.rmtree(home, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
