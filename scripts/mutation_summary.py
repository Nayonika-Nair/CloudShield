"""Print the mutation-testing results recorded by scripts/run_mutation.py as a table."""
import json
from pathlib import Path

d = Path(__file__).resolve().parents[1] / "docs" / "testing" / "mutation"
rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json")) if p.name != "summary.json"]
print(f"{'module':<34}{'mutants':>8}{'done':>7}{'killed':>8}{'survived':>9}{'score':>8}")
tot = [0, 0, 0, 0]
for r in rows:
    print(f"{r['module']:<34}{r["total"]:>8}{r["complete"]:>7}{r['killed']:>8}{r['survived']:>9}{r['score_pct']:>7}%")
    for i, k in enumerate(("total", "complete", "killed", "survived")):
        tot[i] += r[k]
print("-" * 73)
print(f"{'ALL MODULES':<34}{tot[0]:>8}{tot[1]:>7}{tot[2]:>8}{tot[3]:>9}{(round(tot[2] / tot[1] * 100, 1) if tot[1] else 0):>7}%")
