"""Build zarqa/intel/attack_data.json from the ATT&CK Enterprise STIX bundle.

Usage: python scripts/build_attack_data.py enterprise-attack.json
Source: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json)

Keeps what Zarqa needs to recognise and link names: techniques (name, tactics), retired technique IDs
and what replaced them, groups, software and campaigns with their aliases, and which techniques and
software each group, campaign and piece of software is known to use.
"""
import json
import sys
from pathlib import Path


def ext_id(o):
    return next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), "")


def main(src: str) -> None:
    bundle = json.loads(Path(src).read_text(encoding="utf-8"))
    objs = bundle["objects"]
    version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), "")
    live = {o["id"]: o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")}
    techs, retired, groups, software, campaigns = {}, {}, {}, {}, {}
    for o in objs:
        t, eid = o.get("type"), ext_id(o)
        if not eid:
            continue
        if t == "attack-pattern":
            if o["id"] not in live:
                retired[eid] = {"n": o.get("name", ""), "by": "", "_id": o["id"]}
                continue
            tactics = sorted({p["phase_name"] for p in o.get("kill_chain_phases", [])
                              if p.get("kill_chain_name") == "mitre-attack"})
            techs[eid] = {"n": o["name"], "t": tactics}
        elif o["id"] not in live:
            continue
        elif t == "intrusion-set":
            groups[eid] = {"n": o["name"], "a": sorted(set(o.get("aliases", [])) - {o["name"]}), "tech": [], "sw": []}
        elif t in ("malware", "tool"):
            software[eid] = {"n": o["name"], "k": t, "a": sorted(set(o.get("x_mitre_aliases", [])) - {o["name"]}),
                             "tech": []}
        elif t == "campaign":
            campaigns[eid] = {"n": o["name"], "a": sorted(set(o.get("aliases", [])) - {o["name"]}), "tech": [],
                              "sw": [], "g": []}
    by_stix = {o["id"]: ext_id(o) for o in objs}
    for o in objs:
        if o.get("type") != "relationship" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        rt, s, d = o.get("relationship_type"), by_stix.get(o.get("source_ref", "")), by_stix.get(o.get("target_ref", ""))
        if not s or not d:
            continue
        if rt == "revoked-by" and s in retired:
            retired[s]["by"] = d
        elif rt == "uses":
            holder = groups.get(s) or software.get(s) or campaigns.get(s)
            if holder is None:
                continue
            if d in techs:
                holder["tech"].append(d)
            elif d in software and "sw" in holder:
                holder["sw"].append(d)
        elif rt == "attributed-to" and s in campaigns and d in groups:
            campaigns[s]["g"].append(d)
    for r in retired.values():
        r.pop("_id", None)
    for table in (groups, software, campaigns):
        for v in table.values():
            for k in ("tech", "sw", "g"):
                if k in v:
                    v[k] = sorted(set(v[k]))
    out = {"source": "MITRE ATT&CK Enterprise", "version": version, "techniques": techs, "retired": retired,
           "groups": groups, "software": software, "campaigns": campaigns}
    dest = Path(__file__).resolve().parent.parent / "zarqa" / "intel" / "attack_data.json"
    dest.write_text(json.dumps(out, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    print(f"ATT&CK {version}: {len(techs)} techniques, {len(retired)} retired, {len(groups)} groups, "
          f"{len(software)} software, {len(campaigns)} campaigns -> {dest} ({dest.stat().st_size} bytes)")


if __name__ == "__main__":
    main(sys.argv[1])
