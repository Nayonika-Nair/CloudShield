"""System-building verification without Docker: start the real stack from a clean database, check health,
authenticate, generate an environment, restart the server process and prove the data persisted.

Usage: python scripts/verify_system.py --pg postgresql://postgres:@127.0.0.1:PORT/postgres
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import psycopg2

ROOT = Path(__file__).resolve().parents[1]
PORT = 8011
BASE = f"http://127.0.0.1:{PORT}"


def call(path, method="GET", body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def start(env):
    log = open(ROOT / ".tmp" / "verify_server.log", "ab")
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
                            cwd=ROOT / "backend", env=env, stdout=log, stderr=subprocess.STDOUT)
    for _ in range(60):
        try:
            return proc, call("/health")
        except Exception:
            time.sleep(0.5)
    raise SystemExit("server did not become healthy")


def main(pg):
    admin_db = pg
    dbname = "cloudshield_verify"
    conn = psycopg2.connect(admin_db)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("select version()")
    print("PostgreSQL:", cur.fetchone()[0].split(",")[0])
    cur.execute("select pg_terminate_backend(pid) from pg_stat_activity where datname=%s", (dbname,))
    cur.execute(f"drop database if exists {dbname}")
    cur.execute(f"create database {dbname}")
    print(f"created empty database {dbname}")
    url = re.sub(r"/[^/]*$", f"/{dbname}", pg)
    env = dict(os.environ, DATABASE_URL=url, JWT_SECRET_KEY="verify-secret-" + str(time.time()), ADMIN_EMAIL="admin@cloudshield.example.com",
               ADMIN_PASSWORD="Verify-Admin-2026", SEED_DEMO_ENVIRONMENT="false", SERVE_FRONTEND="true")
    print("\n--- start 1 (fresh database) ---")
    proc, health = start(env)
    print("GET /health ->", health)
    tok = call("/api/auth/login", "POST", {"email": env["ADMIN_EMAIL"], "password": env["ADMIN_PASSWORD"]})["access_token"]
    print("login OK, role:", call("/api/auth/me", token=tok)["role"])
    gen = call("/api/sim/environments", "POST", {"preset": "typical", "config": {"seed": 77}}, tok)
    e1 = gen["environment"]
    call("/api/sim/time/advance", "POST", {"days": 3}, tok)
    call("/api/sim/scans", "POST", token=tok)
    before = call("/api/sim/environment", token=tok)
    scans1 = call("/api/sim/scans", token=tok)["total"]
    dash1 = call("/api/sim/dashboard", token=tok)
    print(f"generated environment #{e1['id']} seed 77, advanced 3 days -> sim time {before['sim_time']}")
    print(f"scans stored: {scans1}; open findings: {dash1['security']['open_findings']}; run-rate ${dash1['cost']['monthly_run_rate']:.2f}")
    print("UI served by the same process: GET / ->", urllib.request.urlopen(BASE + "/").status)
    tables = None
    c2 = psycopg2.connect(re.sub(r"/[^/]*$", f"/{dbname}", pg))
    cc = c2.cursor()
    cc.execute("select count(*) from information_schema.tables where table_schema='public'")
    tables = cc.fetchone()[0]
    cc.execute("select count(*) from sim_resources")
    rows = cc.fetchone()[0]
    c2.close()
    print(f"database now has {tables} tables and {rows} sim_resources rows")
    proc.terminate()
    proc.wait(timeout=20)
    print("\n--- server stopped; start 2 (same database) ---")
    proc2, health2 = start(env)
    print("GET /health ->", health2)
    tok2 = call("/api/auth/login", "POST", {"email": env["ADMIN_EMAIL"], "password": env["ADMIN_PASSWORD"]})["access_token"]
    after = call("/api/sim/environment", token=tok2)
    scans2 = call("/api/sim/scans", token=tok2)["total"]
    dash2 = call("/api/sim/dashboard", token=tok2)
    print(f"environment #{after['id']} sim time {after['sim_time']} fingerprint {after['fingerprint'][:16]}")
    ok = (after["fingerprint"] == before["fingerprint"] and after["sim_time"] == before["sim_time"] and scans2 == scans1
          and dash2["security"]["open_findings"] == dash1["security"]["open_findings"])
    print(f"scans stored: {scans2}; open findings: {dash2['security']['open_findings']}")
    print("PERSISTENCE AFTER RESTART:", "PASS - identical environment, clock, scans and findings" if ok else "FAIL")
    proc2.terminate()
    proc2.wait(timeout=20)
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pg", required=True)
    sys.exit(main(ap.parse_args().pg))
