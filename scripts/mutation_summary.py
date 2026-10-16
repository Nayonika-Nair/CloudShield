"""Print the mutation-testing results recorded by scripts/run_mutation.py as a table."""
import json
from pathlib import Path

d = Path(__file__).resolve().parents[1] / "docs" / "testing" / "mutation"
rows = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json")) if p.name != "summary.json"]
for r in rows:
    r.setdefault("complete", r["killed"] + r["survived"] + r["incompetent"])
    r.setdefault("round1", {"score_pct": r["score_pct"]})
head = f"{'module':<32}{'generated':>10}{'annot.':>8}{'tested':>8}{'killed':>8}{'survived':>9}{'incomp.':>8}{'round1':>8}{'final':>8}"
print(head)
print("-" * len(head))
tot = dict(generated=0, annotation_excluded=0, complete=0, killed_with_failing_test_output=0, survived=0, incompetent=0)
tot_r1 = [0, 0]
for r in rows:
    print(f"{r['module']:<32}{r['generated']:>10}{r['annotation_excluded']:>8}{r['complete']:>8}{r['killed_with_failing_test_output']:>8}"
          f"{r['survived']:>9}{r['incompetent']:>8}{str(r['round1']['score_pct']) + '%':>8}{str(r['score_pct']) + '%':>8}")
    for k in tot:
        tot[k] += r[k]
    tot_r1[0] += r["round1"].get("killed", 0)
    tot_r1[1] += r["round1"].get("survived", 0)
den = tot["killed_with_failing_test_output"] + tot["survived"]
print("-" * len(head))
print(f"{'ALL MODULES':<32}{tot['generated']:>10}{tot['annotation_excluded']:>8}{tot['complete']:>8}{tot['killed_with_failing_test_output']:>8}"
      f"{tot['survived']:>9}{tot['incompetent']:>8}{str(round(tot_r1[0] / (sum(tot_r1) or 1) * 100, 1)) + '%':>8}{(str(round(tot['killed_with_failing_test_output'] / den * 100, 1)) if den else 'n/a') + '%':>8}")
print("\nround1 = targeted tests only; final = after hardening tests were added and the survivors re-run (round 2).\nscore = killed / (killed + survived); incompetent mutants (could not be tested) are excluded.")
print("mutants are a seeded random sample (seed 2026) of those generated, annotation-only mutants excluded.")
