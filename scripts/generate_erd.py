"""Generate Mermaid ER diagrams from the real SQLAlchemy models (never hand-drawn).

Writes docs/diagrams/source/erd-simulator.mmd and erd-core.mmd.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DATABASE_URL", "postgresql://cloudshield:cloudshield@localhost:5432/cloudshield")

from app import models  # noqa: E402,F401
from app.database import Base  # noqa: E402

TYPE_MAP = {"INTEGER": "int", "VARCHAR": "string", "STRING": "string", "DATETIME": "datetime", "TEXT": "text", "JSON": "json",
            "FLOAT": "float", "BOOLEAN": "boolean", "DATE": "date", "NUMERIC": "decimal", "JSONB": "json"}


def col_type(col) -> str:
    name = type(col.type).__name__.upper()
    if name == "VARIANT":
        name = type(col.type.impl).__name__.upper()
    return TYPE_MAP.get(name, name.lower())


def build(tables, title) -> str:
    names = {t.name for t in tables}
    lines = ["erDiagram"]
    for t in tables:
        lines.append(f"  {t.name} {{")
        for c in t.columns:
            flags = []
            if c.primary_key:
                flags.append("PK")
            if c.foreign_keys:
                flags.append("FK")
            if c.unique and not c.primary_key:
                flags.append("UK")
            lines.append(f"    {col_type(c)} {c.name}" + (f" {','.join(flags)}" if flags else ""))
        lines.append("  }")
    for t in tables:
        for c in t.columns:
            for fk in c.foreign_keys:
                parent = fk.column.table.name
                if parent in names:
                    lines.append(f'  {parent} ||--o{{ {t.name} : "{c.name}"')
    return "\n".join(lines) + "\n"


tables = Base.metadata.sorted_tables
sim = [t for t in tables if t.name.startswith("sim_")]
core = [t for t in tables if not t.name.startswith("sim_")]
out = ROOT / "docs" / "diagrams" / "source"
out.mkdir(parents=True, exist_ok=True)
(out / "erd-simulator.mmd").write_text(build(sim, "Simulator"), encoding="utf-8")
(out / "erd-core.mmd").write_text(build(core, "Core"), encoding="utf-8")
print(f"simulator tables: {len(sim)}, core tables: {len(core)}")
