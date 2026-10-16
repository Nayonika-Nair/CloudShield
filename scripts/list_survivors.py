"""Compact list of surviving mutants from a Cosmic Ray session: line, operator and the changed source line."""
import re
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
rows = db.execute("select s.start_pos_row, s.operator_name, r.diff from work_results r join mutation_specs s using(job_id) "
                  "where r.test_outcome='SURVIVED' order by 1").fetchall()
for row, op, diff in rows:
    minus = [l[1:].strip() for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
    plus = [l[1:].strip() for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
    # show only the part of the line that differs
    a, b = (minus or [""])[0], (plus or [""])[0]
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    print(f"{row:>4} {op.replace('core/', ''):<42} ...{a[max(0, i - 25):i + 40]!r} -> {b[max(0, i - 5):i + 40]!r}")
print(len(rows), "survivors")
