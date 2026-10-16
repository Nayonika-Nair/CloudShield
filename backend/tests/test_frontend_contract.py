"""Frontend <-> backend integration checks that need no browser.

* every API path the JavaScript calls exists in the backend's OpenAPI document with that HTTP method;
* every data-action / data-change / data-input / data-form in the UI has a registered handler
  (no buttons that look functional but do nothing);
* the shell references only files that exist and contains no hard-coded sample data tables.
"""

import re
from pathlib import Path

import pytest

from app.main import app

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
JS_FILES = sorted((FRONTEND / "js").rglob("*.js"))
SOURCES = {p: p.read_text(encoding="utf-8") for p in JS_FILES}
HTML = (FRONTEND / "index.html").read_text(encoding="utf-8")


def _openapi_routes():
    spec = app.openapi()
    routes = []
    for path, methods in spec["paths"].items():
        regex = "^" + re.sub(r"\{[^}]+\}", "[^/]+", re.escape(path).replace(r"\{", "{").replace(r"\}", "}")) + "$"
        routes.append((re.compile(regex), {m.upper() for m in methods}))
    return routes


def _api_calls():
    """(method, path-with-placeholders, file) for get/post/patch/download calls with literal paths."""
    calls = []
    pattern = re.compile(r"\b(get|post|patch|download)\(\s*(['\"`])(/api/[^'\"`]*)\2(\s*\+\s*[^,)]+)?")
    for path, src in SOURCES.items():
        for m in pattern.finditer(src):
            verb, literal, concat = m.group(1), m.group(3), m.group(4)
            template = re.sub(r"\$\{[^}]*\}", "x", literal)
            if concat or template.endswith("/"):
                template = template.rstrip("/") + "/x"
            template = template.split("?")[0]
            calls.append(({"get": "GET", "post": "POST", "patch": "PATCH", "download": "GET"}[verb], template, path.name))
    return calls


def test_frontend_makes_a_meaningful_number_of_api_calls():
    assert len(_api_calls()) >= 40


@pytest.mark.parametrize("method,template,source", sorted(set(_api_calls())))
def test_every_api_call_in_the_ui_exists_in_the_backend(method, template, source):
    matches = [(rx, methods) for rx, methods in _openapi_routes() if rx.match(template)]
    assert matches, f"{source} calls {method} {template} but no such route exists"
    assert any(method in methods for _, methods in matches), f"{source}: {template} does not allow {method}"


def _registered_names():
    names = set()
    for src in SOURCES.values():
        if "registerActions(" not in src and "registerForms(" not in src:
            continue
        # handler properties are written at 4-space indentation inside init(): name: (el) => ... / 'kebab-name': async (el) => ...
        names |= set(re.findall(r"^ {4}['\"]?([\w-]+)['\"]?\s*:\s*(?:async\s*)?(?:\(|[A-Za-z_]+\s*=>)", src, re.M))
        for line in re.findall(r"registerActions\(\{([^\n]*)\}\);", src):   # one-line registrations (main.js)
            names |= set(re.findall(r"['\"]([\w-]+)['\"]\s*:", line))
    return names


def _used_names(attr):
    pattern = re.compile(attr + r'="([\w-]+)"')
    used = set(pattern.findall(HTML))
    for src in SOURCES.values():
        used |= set(pattern.findall(src))
    return used


@pytest.mark.parametrize("attr", ["data-action", "data-change", "data-input", "data-form"])
def test_every_ui_hook_has_a_handler(attr):
    registered = _registered_names()
    missing = sorted(n for n in _used_names(attr) if n not in registered)
    assert missing == [], f"{attr} used without a handler: {missing}"


def test_index_html_references_existing_assets_only():
    refs = re.findall(r'(?:href|src)="((?:css|js)/[^"]+)"', HTML)
    assert refs and all((FRONTEND / r).exists() for r in refs), refs


def test_ui_has_no_hardcoded_sample_data_tables():
    """The prototype used inline arrays of fake findings/costs; the integrated UI must not."""
    banned = ["customer-data-backup", "svc-deploy-bot", "i-0af23bcd991", "prod-db-cluster", "$4,215", "78 / 100"]
    corpus = HTML + "\n".join(SOURCES.values())
    assert [b for b in banned if b in corpus] == []


def test_all_untrusted_values_go_through_the_escaping_template():
    """Raw innerHTML assignments must only use html``/raw() output or escaped strings."""
    offenders = []
    for path, src in SOURCES.items():
        for m in re.finditer(r"\.innerHTML\s*=\s*([^;]+);", src):
            expr = m.group(1).strip()
            if not (expr == "String(content)"  # the generic mount() sink: callers pass html`` output
                    or expr.startswith("String(html`") or expr.startswith("''") or "esc(" in expr or expr.startswith("`<option")
                    or ".map(" in expr and "esc(" in expr):
                offenders.append((path.name, expr[:80]))
    assert offenders == []
