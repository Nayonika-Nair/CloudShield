"""Start a throw-away PostgreSQL server (pgserver package) for local verification without Docker.

Usage:  python scripts/run_postgres.py [datadir]   -> prints the DATABASE_URL and keeps running until Ctrl+C
"""

import sys
import time
from pathlib import Path

import pgserver

data = Path(sys.argv[1] if len(sys.argv) > 1 else ".tmp/pgdata").resolve()
server = pgserver.get_server(data, cleanup_mode=None)
print("DATABASE_URL=" + server.get_uri().replace("postgresql://", "postgresql+psycopg2://", 1).replace("+psycopg2", ""), flush=True)
print("PostgreSQL:", server.psql("select version();").strip().splitlines()[-2:], flush=True)
try:
    while True:
        time.sleep(3600)
except KeyboardInterrupt:
    server.cleanup()
