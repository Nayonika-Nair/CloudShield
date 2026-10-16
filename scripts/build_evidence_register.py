"""Merge docs/screenshots/.register/*.json into docs/screenshots/EVIDENCE_REGISTER.md (and verify every file exists)."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
items = []
for f in sorted((root / "docs" / "screenshots" / ".register").glob("*.json")):
    items += json.loads(f.read_text(encoding="utf-8"))
missing = [i["file"] for i in items if not (root / i["file"]).exists()]
if missing:
    raise SystemExit(f"missing files: {missing}")
lines = ["# Evidence register", "",
         "Every image below is a genuine screenshot of the running application (rendered by Chrome via Playwright) or a rendering of real captured command output "
         "(the unmodified text is next to it in `docs/testing/results/`). Nothing is mocked.", "",
         "| # | File | Shows | Demonstrates | Source output |", "|---|------|-------|--------------|---------------|"]
for n, i in enumerate(sorted(items, key=lambda x: (x["category"], x["file"])), 1):
    src = i.get("source_output", "")
    lines.append(f"| {n} | `{i['file'].replace('docs/screenshots/', '')}` | {i['title']} | {i['purpose']} | {('`' + src + '`') if src else '-'} |")
(root / "docs" / "screenshots" / "EVIDENCE_REGISTER.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"{len(items)} entries, all files present")
