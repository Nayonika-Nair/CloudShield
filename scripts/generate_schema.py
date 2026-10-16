"""Write database/schema.sql (PostgreSQL DDL) from the SQLAlchemy models.

Usage:  python scripts/generate_schema.py
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DATABASE_URL", "postgresql://cloudshield:cloudshield@localhost:5432/cloudshield")

from sqlalchemy.dialects import postgresql  # noqa: E402
from sqlalchemy.schema import CreateIndex, CreateTable  # noqa: E402

from app import models  # noqa: E402,F401
from app.database import Base  # noqa: E402

lines = [
    "-- CloudShield PostgreSQL schema (generated from the SQLAlchemy models by scripts/generate_schema.py).",
    "-- The API creates any missing tables at start-up, so this file is for reference and manual set-up.",
    "",
]
dialect = postgresql.dialect()
for table in Base.metadata.sorted_tables:
    lines.append(str(CreateTable(table, if_not_exists=True).compile(dialect=dialect)).strip() + ";")
    for index in sorted(table.indexes, key=lambda i: i.name or ""):
        lines.append(str(CreateIndex(index, if_not_exists=True).compile(dialect=dialect)).strip() + ";")
    lines.append("")
(ROOT / "database" / "schema.sql").write_text("\n".join(lines), encoding="utf-8")
print(f"wrote {ROOT / 'database' / 'schema.sql'} ({len(Base.metadata.sorted_tables)} tables)")
