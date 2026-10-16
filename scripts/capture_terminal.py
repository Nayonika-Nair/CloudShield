"""Run real commands and capture their real output as (a) a text file and (b) a terminal-style PNG.

The PNG is a rendering of the captured stdout/stderr (a terminal screenshot is not available to a script);
the text file next to it is the unmodified output, so every image can be checked against its source.

Usage:  python scripts/capture_terminal.py <plan.json>
plan.json: [{"id", "category", "title", "purpose", "cmd", "cwd", "env": {}, "max_lines": 60, "head": 8, "expect_rc": 0}]
"""

import html
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "docs" / "screenshots"
RESULTS = ROOT / "docs" / "testing" / "results"

PAGE = """<!doctype html><meta charset="utf-8"><style>
body{margin:0;background:#e9edf3;font-family:Consolas,'Cascadia Mono','Courier New',monospace}
.win{width:1180px;margin:0;background:#fff;border:1px solid #b4c0d0}
.bar{background:#1f2f45;color:#dbe6f5;padding:8px 14px;font:600 13px 'Segoe UI',Arial,sans-serif;display:flex;justify-content:space-between}
.cmd{background:#f3f6fa;border-bottom:1px solid #d8dfe9;padding:8px 14px;font-size:13px;color:#14304f;white-space:pre-wrap;word-break:break-all}
pre{margin:0;padding:12px 14px;font-size:12.5px;line-height:1.38;color:#1a2838;white-space:pre-wrap;word-break:break-word}
.foot{padding:6px 14px;border-top:1px solid #d8dfe9;font:12px 'Segoe UI',Arial,sans-serif;color:#3f5166;background:#f8fafc}
.ok{color:#1d6b35;font-weight:700}.bad{color:#9f1218;font-weight:700}
</style><body><div class="win"><div class="bar"><span>%(title)s</span><span>%(stamp)s</span></div>
<div class="cmd">$ %(cmd)s</div><pre>%(body)s</pre><div class="foot">exit code <span class="%(cls)s">%(rc)s</span> &middot; %(secs).1fs &middot; working directory %(cwd)s</div></div></body>"""


def run_item(item: dict, page) -> dict:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", **{k: str(v) for k, v in item.get("env", {}).items()})
    env["PATH"] = str(ROOT / ".venv" / "Scripts") + os.pathsep + env["PATH"]
    cwd = ROOT / item.get("cwd", ".")
    t0 = time.time()
    proc = subprocess.run(item["cmd"], cwd=cwd, env=env, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr.strip() else "")
    secs = time.time() - t0
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"{item['id']}.txt").write_text(f"$ {item['cmd']}\n(cwd: {item.get('cwd', '.')})\n\n{out}\n[exit code {proc.returncode}, {secs:.1f}s]\n", encoding="utf-8")
    lines = out.splitlines()
    mx, head = item.get("max_lines", 60), item.get("head", 6)
    if len(lines) > mx:
        keep = lines[:head] + [f"... ({len(lines) - mx} lines omitted in this image; full output in docs/testing/results/{item['id']}.txt) ..."] + lines[-(mx - head):]
    else:
        keep = lines
    expect = item.get("expect_rc", 0)
    body = html.escape("\n".join(keep))
    page.set_content(PAGE % {"title": html.escape(item["title"]), "stamp": time.strftime("%Y-%m-%d %H:%M"), "cmd": html.escape(item["cmd"]),
                             "body": body, "cls": "ok" if proc.returncode == expect else "bad", "rc": proc.returncode, "secs": secs,
                             "cwd": html.escape(str(item.get("cwd", ".")))})
    folder = SHOTS / item["category"]
    folder.mkdir(parents=True, exist_ok=True)
    png = folder / f"{item['id']}.png"
    page.locator(".win").screenshot(path=str(png))
    print(f"{item['id']}: rc={proc.returncode} ({secs:.0f}s) -> {png.relative_to(ROOT).as_posix()}")
    return {"file": png.relative_to(ROOT).as_posix(), "category": item["category"], "title": item["title"], "purpose": item["purpose"],
            "source_output": (RESULTS / f"{item['id']}.txt").relative_to(ROOT).as_posix(), "rc": proc.returncode, "expected_rc": expect}


def main(plan_path: str) -> int:
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    entries = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_page(viewport={"width": 1200, "height": 900}, device_scale_factor=1.5)
        for item in plan:
            entries.append(run_item(item, page))
        browser.close()
    reg = SHOTS / ".register"
    reg.mkdir(parents=True, exist_ok=True)
    name = Path(plan_path).stem
    (reg / f"{name}.json").write_text(json.dumps(entries, indent=2), encoding="utf-8")
    bad = [e for e in entries if e["rc"] != e["expected_rc"]]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
