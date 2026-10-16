"""Run Cosmic Ray mutation testing on selected CloudShield modules.

Each module is mutated in its own *copy* of backend/ so several runs can execute in parallel
without one run's mutants leaking into another run's test results.

Usage:
    python scripts/run_mutation.py --jobs 4 billing cost security iam config network optimization remediation
Results (raw report, survivors, score) are written to docs/testing/mutation/.
"""

import argparse
import ast
import json
import random
import sqlite3
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV_BIN = ROOT / ".venv" / "Scripts"
PYTHON = (VENV_BIN / "python.exe").as_posix()   # absolute: a bare "python" resolved to another interpreter without the dependencies
OUT = ROOT / "docs" / "testing" / "mutation"
WORK = ROOT / ".tmp" / "mut"

TARGETS = {
    "billing": ("app/simulator/billing.py", "tests/test_cost_time.py", "Cost calculation (simulated pricing arithmetic)"),
    "cost": ("app/engines/cost.py", "tests/test_cost_time.py", "Cost run-rate, history and anomaly detection"),
    "security": ("app/engines/security.py", "tests/test_security_rules.py", "Security detection rules and severity logic"),
    "iam": ("app/engines/iam.py", "tests/test_network_iam.py tests/test_security_rules.py", "IAM evaluation, trust and escalation"),
    "network": ("app/engines/network.py", "tests/test_network_iam.py", "Network reachability analysis"),
    "config": ("app/simulator/config.py", "tests/test_generator_config.py", "Configuration validation logic"),
    "optimization": ("app/engines/optimization.py", "tests/test_cost_time.py tests/test_whatif_drift.py", "Cost recommendation rules"),
    "remediation": ("app/engines/remediation.py", "tests/test_whatif_drift.py", "Remediation execution and plan hashing"),
}


def sh(cmd, cwd, env, timeout=None):
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, shell=True, timeout=timeout)


def annotation_spans(source: str) -> list[tuple[int, int, int, int]]:
    """(start_row, start_col, end_row, end_col) of every type annotation. Mutating an annotation either crashes at import
    (a trivially 'killed' mutant) or has no runtime effect, so these mutants carry no information and are excluded."""
    spans = []
    for node in ast.walk(ast.parse(source)):
        anns = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            anns += [a.annotation for a in node.args.args + node.args.kwonlyargs + node.args.posonlyargs if a.annotation]
            anns += [a for a in (node.args.vararg and node.args.vararg.annotation, node.args.kwarg and node.args.kwarg.annotation, node.returns) if a]
        elif isinstance(node, ast.AnnAssign):
            anns.append(node.annotation)
        spans += [(a.lineno, a.col_offset, a.end_lineno, a.end_col_offset) for a in anns]
    return spans


def prune_session(session: Path, module_file: Path, sample: int | None, seed: int) -> dict:
    spans = annotation_spans(module_file.read_text(encoding="utf-8"))
    db = sqlite3.connect(session)
    rows = db.execute("select job_id, start_pos_row, start_pos_col from mutation_specs").fetchall()
    generated = len(rows)
    in_ann = lambda r, c: any((r, c) >= (a, b) and (r, c) <= (e, f) for a, b, e, f in spans)  # noqa: E731
    keep = [j for j, r, c in rows if not in_ann(r, c)]
    excluded = generated - len(keep)
    if sample and len(keep) > sample:
        random.Random(seed).shuffle(keep)
        keep = keep[:sample]
    kept = set(keep)
    for j, _, _ in rows:
        if j not in kept:
            db.execute("delete from mutation_specs where job_id=?", (j,))
            db.execute("delete from work_items where job_id=?", (j,))
    db.commit()
    db.close()
    return {"generated": generated, "annotation_excluded": excluded, "sampled": len(kept)}


def run_one(name: str, sample: int | None = None, seed: int = 2026) -> dict:
    module, tests, label = TARGETS[name]
    work = WORK / name
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(ROOT / "backend", work / "backend", ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.db"))
    (ROOT / "frontend").exists()
    shutil.copytree(ROOT / "frontend", work / "frontend", ignore=shutil.ignore_patterns("node_modules"))
    backend = work / "backend"
    shutil.copy(ROOT / "scripts" / "cr_test.py", backend / "cr_test.py")
    toml = backend / "cosmic-ray.toml"
    toml.write_text(
        f'[cosmic-ray]\nmodule-path = "{module}"\ntimeout = 90.0\nexcluded-modules = []\n'
        f'test-command = "python -m pytest -x -q -p no:cacheprovider {tests}"\n\n[cosmic-ray.distributor]\nname = "local"\n',
        encoding="utf-8")
    env = dict(os.environ, PATH=f"{VENV_BIN};{os.environ['PATH']}")
    session = backend / "session.sqlite"
    start = time.time()
    init = sh("cosmic-ray init cosmic-ray.toml session.sqlite", backend, env)
    if init.returncode != 0:
        return {"name": name, "error": init.stderr[-500:]}
    # Baseline: the unmutated tests must pass with exactly the command Cosmic Ray will run, otherwise every mutant would look 'killed'.
    import shlex
    base = subprocess.run(shlex.split(f"{PYTHON} cr_test.py {tests}"), cwd=backend, capture_output=True,
                          env=dict(env, PYTHONDONTWRITEBYTECODE="1"))
    if base.returncode != 0:
        return {"name": name, "error": "baseline failed: " + base.stdout.decode()[-300:] + base.stderr.decode()[-300:]}
    pruned = prune_session(session, backend / module, sample, seed)
    execp = sh("cosmic-ray exec cosmic-ray.toml session.sqlite", backend, env)
    report = sh("cr-report session.sqlite --show-pending", backend, env).stdout
    survivors = sh("cr-report session.sqlite --surviving-only --show-diff", backend, env).stdout
    db = sqlite3.connect(session)
    counts = dict(db.execute("select test_outcome, count(*) from work_results group by 1").fetchall())
    genuine = db.execute("select count(*) from work_results where test_outcome='KILLED' and (output like '%FAILED %' or output like '%Error%' or output='timeout')").fetchone()[0]
    db.close()
    killed, survived, incompetent = counts.get("KILLED", 0), counts.get("SURVIVED", 0), counts.get("INCOMPETENT", 0)
    total = int(re.search(r"total jobs: (\d+)", report).group(1))
    complete = killed + survived + incompetent
    surv = survived
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{name}.survivors.txt").write_text(survivors, encoding="utf-8")
    result = {
        "name": name, "label": label, "module": module, "tests": tests, "total": total, "complete": complete, **pruned, "seed": seed,
        "survived": surv, "killed": killed, "killed_with_failing_test_output": genuine, "incompetent": incompetent, "baseline_passed": True,
        "score_pct": round(genuine / (genuine + surv) * 100, 1) if (genuine + surv) else None,
        "seconds": round(time.time() - start), "exec_returncode": execp.returncode,
    }
    (OUT / f"{name}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result), flush=True)
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+", choices=sorted(TARGETS))
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--sample", type=int, default=None, help="random sample of N mutants per module (seeded)")
    args = ap.parse_args()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda n: run_one(n, args.sample), args.targets))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    sys.exit(0)
