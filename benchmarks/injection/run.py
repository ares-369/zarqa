"""Score Zarqa's prompt-injection scan on the hand-written adversarial set (cases.yaml).

    python benchmarks/injection/run.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from zarqa.intel.injection import scan


def main() -> int:
    cases = yaml.safe_load((Path(__file__).with_name("cases.yaml")).read_text())["cases"]
    tp = fn = fp = tn = 0
    for c in cases:
        hits = scan(c["text"])
        flagged = bool(hits)
        want = c["expect"] == "flag"
        tp += flagged and want
        fn += (not flagged) and want
        fp += flagged and not want
        tn += (not flagged) and not want
        mark = "ok  " if flagged == want else "MISS"
        print(f"{mark} {c['id']:30} expect {c['expect']:5} got {'flag' if flagged else 'clean':5} "
              f"{', '.join(h['pattern'] for h in hits)[:70]}")
    print(f"\nattacks flagged {tp}/{tp + fn}, clean flagged {fp}/{fp + tn}")
    return 0 if fn == 0 and fp == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
