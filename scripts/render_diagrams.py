"""Render every Mermaid source in docs/diagrams/source/*.mmd to SVG + PNG (offline, via headless Chrome).

mermaid.min.js is read from a local npm install (see docs/diagrams/README.md):
    cd .tmp/mermaid && npm install mermaid@10.9.1
Usage: python scripts/render_diagrams.py [name ...]
"""

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "diagrams" / "source"
OUT = ROOT / "docs" / "diagrams" / "rendered"
MERMAID = ROOT / ".tmp" / "mermaid" / "node_modules" / "mermaid" / "dist" / "mermaid.min.js"

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<style>body{margin:0;background:#fff;font-family:Inter,Segoe UI,Arial,sans-serif}#host{display:inline-block;padding:24px;background:#fff}</style>
<script src="%s"></script></head><body><div id="host"></div></body></html>"""


def render(names: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    tmp = ROOT / ".tmp" / "diagram_page.html"
    tmp.parent.mkdir(exist_ok=True)
    tmp.write_text(PAGE % MERMAID.as_uri(), encoding="utf-8")
    sources = sorted(SRC.glob("*.mmd"))
    if names:
        sources = [s for s in sources if s.stem in names]
    failures = 0
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        ctx = browser.new_context(viewport={"width": 2600, "height": 2000}, device_scale_factor=2)
        page = ctx.new_page()
        page.goto(tmp.as_uri())
        page.evaluate("""() => mermaid.initialize({startOnLoad: false, securityLevel: 'loose', theme: 'neutral',
            flowchart: {htmlLabels: true, useMaxWidth: false, curve: 'basis'},
            sequence: {useMaxWidth: false, wrap: true, mirrorActors: false}, er: {useMaxWidth: false},
            class: {useMaxWidth: false}, state: {useMaxWidth: false}, fontFamily: 'Inter, Segoe UI, Arial, sans-serif'})""")
        for src in sources:
            code = src.read_text(encoding="utf-8")
            try:
                svg = page.evaluate("""async ([id, code]) => {
                    const host = document.getElementById('host');
                    const { svg } = await mermaid.render('g' + id, code);
                    host.innerHTML = svg;
                    return svg;
                }""", [src.stem.replace("-", "_"), code])
            except Exception as exc:  # noqa: BLE001
                print(f"FAILED {src.name}: {str(exc)[:300]}")
                failures += 1
                continue
            (OUT / f"{src.stem}.svg").write_text(svg, encoding="utf-8")
            page.locator("#host").screenshot(path=str(OUT / f"{src.stem}.png"))
            print("rendered", src.stem)
        browser.close()
    return failures


if __name__ == "__main__":
    sys.exit(1 if render(sys.argv[1:]) else 0)
