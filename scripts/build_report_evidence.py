"""Build docs/reports/CloudShield_Digital_Assignment_3_Evidence.pdf from real artefacts only."""

import json
import subprocess
from datetime import date
from pathlib import Path

from report_lib import (
    BODY, CELL, REPO, ROOT, PageBreak, Report, Spacer, TITLE, SUB, SMALL, bullets, code, coverage_total, fig, h1, h2, h3, junit_cases,
    load_register, mutation_rows, p, table, toc,
)

OUT = ROOT / "docs" / "reports" / "CloudShield_Digital_Assignment_3_Evidence.pdf"
REG = {e["file"]: e for e in load_register()}


def cap(rel: str) -> str:
    e = REG[rel]
    return f"<b>{e['title']}.</b> {e['purpose']}"


def shot(doc, rel, **kw):
    return fig(doc, ROOT / rel, cap(rel), **kw)


def git(*args) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8").stdout.strip()


def main():
    doc = Report(OUT, "CloudShield - Digital Assignment 3 Evidence", "Digital Assignment 3 / Review 3 - Evidence Pack")
    cases = junit_cases(ROOT / "docs/testing/results/junit-sqlite.xml")
    pg_cases = junit_cases(ROOT / "docs/testing/results/junit-postgres.xml")
    cov, _ = coverage_total(ROOT / "docs/testing/results/full-suite-coverage.txt")
    mut = mutation_rows()
    by_module: dict[str, list] = {}
    for c in cases:
        by_module.setdefault(c["module"], []).append(c)
    passed = sum(c["status"] == "passed" for c in cases)
    pg_passed = sum(c["status"] == "passed" for c in pg_cases)
    commits = git("rev-list", "--count", "develop")
    s: list = []

    # ---------------------------------------------------------------- cover
    s += [Spacer(1, 30), p("Digital Assignment 3 &mdash; Review 3", SUB), p("CloudShield", TITLE),
          p("Intelligent Cloud Cost &amp; Security Optimization Platform with a configurable Fake AWS simulator", SUB), Spacer(1, 16)]
    s += table(doc, ["Item", "Value"], [
        ["Submission", "Single PDF: integration / regression / mutation testing, version management and system building evidence, "
                       "screenshots of the developed functionality, tools and technologies"],
        ["GitHub repository", REPO],
        ["Branch evidenced", f"develop (integration branch), feature branches merged with --no-ff; {commits} commits on develop"],
        ["Generated on", date.today().isoformat()],
        ["Evidence policy", "Every screenshot was taken from the running application or from real command output captured in this "
                            "repository (docs/testing/results/*.txt). Nothing is mocked. Limitations are stated where they apply."],
    ], [40, 130], bold_first=True)
    s += [Spacer(1, 14), p("<b>How to find each required item</b>")]
    s += table(doc, ["Required by the assignment", "Section"], [
        ["Integration / regression / mutation testing (screenshots)", "2, 3 and 4"],
        ["Version management and system building (screenshots)", "5 and 6"],
        ["Screenshots of developed functionalities", "7"],
        ["Tools / technologies used", "8"],
        ["Demo of the project", "7.1 (scripted walkthrough) and README demo script"],
        ["Project report (problem statement, user stories, architecture, tests, appendix: SRS, DFD, ERD, UML, code / GitHub)", "Separate PDF: CloudShield_Project_Report.pdf"],
    ], [120, 50], zebra=True)
    s += [PageBreak(), p("<b>Contents</b>", BODY), toc(), PageBreak()]

    # ---------------------------------------------------------------- 1 overview
    s += [h1("1. Project overview")]
    s += [p("CloudShield helps a team understand a cloud estate, find security weaknesses and wasted spend, simulate fixes, apply them after explicit "
            "confirmation and verify that the problem is really gone. Because real AWS accounts are not required, the platform runs on a configurable, "
            "stateful <b>Fake AWS simulator</b>: seeded and reproducible, with VPCs, subnets, route tables, internet gateways, network interfaces, "
            "security groups, EC2, EBS, snapshots, Elastic IPs, load balancers, RDS, S3 and IAM, plus a controlled simulated clock, daily metrics and billing.")]
    s += [p("The core workflow demonstrated in this evidence pack is <b>Configure &rarr; Provision &rarr; Observe &rarr; Analyze &rarr; Detect &rarr; "
            "Simulate &rarr; Remediate &rarr; Verify &rarr; Compare &rarr; Report</b>. Security findings are <i>derived from simulated state</i> (network reachability, "
            "IAM policy graph, metrics, billing) by 20 documented rules; scenarios only change state. A finding is resolved only when a re-scan no longer "
            "detects the condition.")]
    s += [fig(doc, "docs/diagrams/rendered/12-simulator-workflow.png", "<b>Simulator workflow.</b> The ten stages and the modules that implement them.", width_mm=172)]

    # ---------------------------------------------------------------- 2 integration
    s += [PageBreak(), h1("2. Integration testing evidence")]
    ig = by_module.get("test_integration_db", []) + by_module.get("test_e2e_workflow", [])
    s += [p(f"Integration tests exercise the real database and the real HTTP stack together. They cover simulator &harr; database round trips "
            f"(resources, relationships, metrics and costs reload to an identical fingerprint), append-only history, optimistic locking against concurrent writers, "
            f"transactional rollback of a failed mutation (the rejected attempt is still audited), scan reconciliation (idempotent scans, findings that resolve only "
            f"when the condition disappears), archived environments keeping their rows, and an end-to-end API workflow that follows the demo script. "
            f"<b>{len(ig)} tests ran: {sum(c['status'] == 'passed' for c in ig)} passed.</b> API-level integration is covered by a further "
            f"{len(by_module.get('test_api', []))} tests (Section 9).")]
    s += [shot(doc, "docs/screenshots/testing/integration-tests.png", max_h_mm=235)]
    s += [p("Integration evidence also includes the same suite against real PostgreSQL 16 (Section 9) and the frontend contract tests: every API call made by the "
            "browser code and every <font name='Courier'>data-action</font> hook is checked against the backend's OpenAPI document and handler registry.")]
    s += [shot(doc, "docs/screenshots/testing/frontend-contract-tests.png", max_h_mm=120)]

    # ---------------------------------------------------------------- 3 regression
    s += [PageBreak(), h1("3. Regression testing evidence")]
    rg = by_module.get("test_regression_legacy", [])
    s += [p(f"The original CloudShield code (registration/login, the mock cloud provider, the label-based security, cost and recommendation engines, the original "
            f"<font name='Courier'>/api/*</font> routes and their persistence) was kept and is pinned by regression tests that assert its previously observable behaviour: "
            f"the 15-resource mock inventory, the baseline scan (score 96, two findings, $1,120 monthly cost, $192 potential saving), route contracts, transactional "
            f"persistence, and that a legacy scan never touches simulator history. A database created before role-based access control (no <font name='Courier'>users.role</font> column) "
            f"is upgraded in place at start-up. <b>{len(rg)} regression tests ran: {sum(c['status'] == 'passed' for c in rg)} passed.</b>")]
    s += [shot(doc, "docs/screenshots/testing/regression-tests.png", max_h_mm=235)]

    # ---------------------------------------------------------------- 4 mutation
    s += [PageBreak(), h1("4. Mutation testing evidence")]
    if mut:
        tot_c = sum(m["complete"] for m in mut)
        tot_k = sum(m["killed"] for m in mut)
        s += [p("Tool: <b>Cosmic Ray 8.4.1</b> (Python mutation testing). Each target module is mutated in its own copy of the backend so runs cannot contaminate each other; "
                "every mutant is tested with the module's targeted pytest files using <font name='Courier'>pytest -x</font>. Two honest adjustments were made: "
                "(1) a <b>seeded random sample</b> of mutants per module was run (seed 2026) because exhaustive runs cost about 15 s per mutant on the development machine, and "
                "(2) mutants that fall inside <b>type annotations</b> were excluded, because they either crash at import (a trivially 'killed' mutant) or have no runtime effect.")]
        rows = [[m["module"], m["label"], m["generated"], m["annotation_excluded"], m["complete"], m["killed"], m["survived"], f"{m['score_pct']}%"] for m in mut]
        rows.append(["<b>All</b>", "", sum(m["generated"] for m in mut), sum(m["annotation_excluded"] for m in mut), tot_c, tot_k, sum(m["survived"] for m in mut),
                     f"{round(tot_k / tot_c * 100, 1)}%" if tot_c else "n/a"])
        s += table(doc, ["Module", "Covers", "Generated", "Annotation (excluded)", "Tested", "Killed", "Survived", "Score"], rows, [38, 52, 15, 18, 13, 12, 12, 12],
                   caption="Mutation testing results exactly as recorded by scripts/run_mutation.py (docs/testing/mutation/*.json).")
        surv = [m for m in mut if m["survived"]]
        s += [p("<b>Surviving mutants.</b> " + (
            "; ".join(f"{m['module']}: {m['survived']}" for m in surv) + ". Their diffs are stored in docs/testing/mutation/&lt;module&gt;.survivors.txt and discussed in the project report."
            if surv else "None of the tested mutants survived."))]
        s += [shot(doc, "docs/screenshots/testing/mutation-summary.png", max_h_mm=120)]
        s += [p("<b>Interpretation and limits.</b> The score applies only to the sampled mutants of the listed modules, not to the whole code base. A killed mutant means at least one "
                "test failed; it does not by itself prove that the failure is meaningful. Lifecycle validation (lifecycle.py) is covered by unit tests but was not mutation-tested "
                "because of its size.", SMALL)]
    else:
        s += [p("Mutation testing results were not available when this report was built.")]

    # ---------------------------------------------------------------- 5 version mgmt
    s += [PageBreak(), h1("5. Version management evidence")]
    s += [p(f"Repository: <font name='Courier'>{REPO}</font>. Work followed the project's GitHub-Flow with a <font name='Courier'>develop</font> integration branch: "
            "feature branches (<font name='Courier'>feature/simulator-core</font>, <font name='Courier'>feature/frontend-integration</font>, <font name='Courier'>feature/documentation-evidence</font>) "
            "are merged with <font name='Courier'>--no-ff</font>, commits are small and describe what changed, and the commits made for this work carry the co-author trailer. "
            "The pre-existing branches (<font name='Courier'>main</font>, <font name='Courier'>feature/authentication</font>) and the user's earlier history were left untouched; "
            "the tool never pushes - publishing the branches to GitHub is left to the repository owner.")]
    s += [shot(doc, "docs/screenshots/version-management/git-branches.png", max_h_mm=100)]
    s += [shot(doc, "docs/screenshots/version-management/git-graph.png", max_h_mm=200)]
    s += [shot(doc, "docs/screenshots/version-management/git-status-remote.png", max_h_mm=100)]

    # ---------------------------------------------------------------- 6 system building
    s += [PageBreak(), h1("6. System building evidence")]
    s += [h2("6.1 Container set-up (written; image build not executed)")]
    s += [p("The repository provides <font name='Courier'>docker-compose.yml</font> (PostgreSQL 16 with a named volume and <font name='Courier'>pg_isready</font> health check, "
            "the FastAPI backend with a health check and non-root user, and an nginx frontend that serves the static UI and proxies <font name='Courier'>/api</font>), "
            "two Dockerfiles, <font name='Courier'>.env.example</font> and a generated <font name='Courier'>database/schema.sql</font>. "
            "<b>Docker is not installed on the machine used for development, so <font name='Courier'>docker compose up --build</font> was NOT run and no successful container "
            "build is claimed.</b> What was done instead is shown below: a record of the missing tool, static validation of the compose file and Dockerfiles, and a native run of the "
            "identical stack.")]
    s += [shot(doc, "docs/screenshots/docker/docker-availability.png", max_h_mm=60)]
    s += [shot(doc, "docs/screenshots/docker/compose-static-validation.png", max_h_mm=110)]
    s += [h2("6.2 Native clean start, health check and persistence")]
    s += [p("FastAPI/uvicorn was started against a freshly created, empty PostgreSQL 16 database. Tables were created automatically, the health endpoint reported "
            "<font name='Courier'>database: ok</font>, an environment was generated and scanned, the server process was stopped and started again, and the clock, fingerprint, "
            "scan history and findings were identical afterwards.")]
    s += [shot(doc, "docs/screenshots/docker/native-startup-persistence.png", max_h_mm=160)]
    s += [h2("6.3 Test execution on PostgreSQL")]
    s += [shot(doc, "docs/screenshots/testing/full-suite-postgres.png", max_h_mm=110)]

    # ---------------------------------------------------------------- 7 screenshots
    s += [PageBreak(), h1("7. Screenshots of the developed functionality")]
    s += [h2("7.1 Demonstration walkthrough")]
    s += [p("All screenshots in this section were produced by <font name='Courier'>scripts/ui_walkthrough.py</font>, which drives the real application in Chrome with Playwright against the "
            "FastAPI + PostgreSQL stack, asserts what it sees (for example that a world-open rule exists before remediation and is gone afterwards) and fails if the browser logs any error. "
            "The sequence follows the demo script: sign in, configure and generate, inspect, trigger a scenario, scan, explain a finding, preview, apply and verify a remediation, "
            "cost anomaly and recommendation, what-if, audit, drift and report.")]
    groups = [
        ("Authentication and dashboard", ["application/01-login", "application/02-login-rejected", "application/03-dashboard", "application/07-viewer-readonly"]),
        ("Simulator configuration and generation", ["simulator/01-configuration", "simulator/02-configuration-security-rates", "simulator/03-generate-confirm",
                                                    "simulator/04-environment-generated", "simulator/05-environments-history"]),
        ("Inventory, topology and IAM", ["simulator/06-inventory", "simulator/07-resource-detail", "simulator/08-network-topology-clean", "simulator/09-iam-analysis"]),
        ("Simulated time and scenarios", ["simulator/10-time-and-scenarios", "simulator/11-scenario-triggered"]),
        ("Detection with evidence (before)", ["security/01-findings-clean", "security/02-sg-before-remediation", "security/03-findings-after-scan",
                                              "security/04-finding-evidence", "simulator/12-topology-exposed"]),
        ("Remediation: preview, apply, verify, and the resource after the fix", ["security/05-remediation-preview", "security/06-remediation-verified",
                                                                                 "security/07-sg-after-remediation", "security/08-findings-resolved",
                                                                                 "security/09-finding-resolution-detail", "security/10-remediation-history",
                                                                                 "security/11-scan-comparison", "security/12-detection-rules"]),
        ("IAM privilege escalation", ["security/13-iam-escalation"]),
        ("Cost analysis and optimization", ["cost/01-cost-anomaly", "cost/02-cost-by-service", "application/04-dashboard-after-scenarios", "cost/03-optimization",
                                            "cost/04-recommendation-evidence", "cost/05-recommendation-whatif", "cost/06-recommendation-verified",
                                            "cost/07-recommendation-status-verified"]),
        ("What-if, audit and drift", ["simulator/13-whatif-result", "simulator/14-audit-log", "simulator/15-audit-event-detail", "simulator/16-configuration-drift"]),
        ("Reports and API documentation", ["application/05-report-generated", "application/06-api-docs"]),
    ]
    for title, names in groups:
        s += [h3(title)]
        for n in names:
            rel = f"docs/screenshots/{n}.png"
            if rel in REG:
                tall = n.startswith(("security/04", "security/05", "security/06", "security/09", "simulator/07", "simulator/15", "cost/05", "cost/06"))
                s += [shot(doc, rel, width_mm=150 if tall else 170, max_h_mm=215 if tall else 190)]
    # ---------------------------------------------------------------- 8 tools
    s += [PageBreak(), h1("8. Tools and technologies used")]
    s += table(doc, ["Area", "Technology", "Used for"], [
        ["Backend", "Python 3.11, FastAPI 0.115, Uvicorn, Pydantic 2", "REST API, validation, OpenAPI documentation"],
        ["Persistence", "PostgreSQL 16, SQLAlchemy 2, psycopg2", "Users and all simulator state / history (JSONB columns)"],
        ["Security", "bcrypt (passlib), python-jose (JWT)", "Password hashing, bearer tokens, role-based access"],
        ["Simulator", "Pure-Python domain model (dataclass-free dicts)", "Deterministic generation, lifecycle, time, billing, scenarios"],
        ["Frontend", "Vanilla HTML / CSS / ES modules, inline SVG charts", "11 views, topology and IAM graphs, no framework"],
        ["Reports", "ReportLab", "Server-side PDF export; CSV and JSON exports"],
        ["Testing", "pytest 8, pytest-cov, httpx / Starlette TestClient", f"{len(cases)} automated tests, {cov} line coverage"],
        ["Mutation testing", "Cosmic Ray 8.4", "Mutation score of rules, cost and validation code"],
        ["UI automation", "Playwright + Chrome", "Real-browser walkthrough and screenshots"],
        ["Containers", "Docker Compose, nginx", "Written; not executed on the development machine"],
        ["Version control", "Git, GitHub Flow", "Feature branches merged into develop"],
        ["Diagrams", "Mermaid 10.9 (rendered offline in Chrome)", "Architecture, DFD, ERD, UML, workflows"],
        ["Local database", "pgserver (embedded PostgreSQL 16.2)", "Native PostgreSQL where Docker was unavailable"],
    ], [26, 62, 82], caption="Tools and technologies.")

    # ---------------------------------------------------------------- 9 test summary
    s += [h1("9. Test execution summary")]
    rows = []
    descr = {
        "test_generator_config": "Unit - configuration validation, deterministic generation, referential integrity",
        "test_lifecycle": "Unit - validated lifecycle operations and prerequisites",
        "test_network_iam": "Unit - network reachability, IAM evaluation, trust, escalation",
        "test_security_rules": "Unit - every detection rule, severity logic, scenarios",
        "test_cost_time": "Unit - billing, simulated time, anomalies, recommendations",
        "test_whatif_drift": "Unit - what-if isolation, remediation, drift, compliance, scenario revert",
        "test_integration_db": "Integration - simulator and database",
        "test_api": "API - auth, validation, purity of GET, audit, remediation, what-if, reports",
        "test_regression_legacy": "Regression - original CloudShield behaviour",
        "test_e2e_workflow": "End-to-end - full workflow over HTTP",
        "test_frontend_contract": "Frontend contract - UI to API wiring",
    }
    for mod, cs in sorted(by_module.items()):
        ok = sum(c["status"] == "passed" for c in cs)
        rows.append([f"{mod}.py", descr.get(mod, ""), len(cs), ok, len(cs) - ok, f"{sum(c['time'] for c in cs):.1f}s"])
    rows.append(["<b>Total</b>", "SQLite run", len(cases), passed, len(cases) - passed, f"{sum(c['time'] for c in cases):.1f}s"])
    rows.append(["<b>Total</b>", "Same suite on PostgreSQL 16", len(pg_cases), pg_passed, len(pg_cases) - pg_passed, f"{sum(c['time'] for c in pg_cases):.1f}s"])
    s += table(doc, ["Test file", "Level", "Tests", "Passed", "Failed", "Time"], rows, [38, 80, 13, 14, 12, 13],
               caption=f"Actual results from the JUnit reports (docs/testing/results/junit-*.xml). Line coverage of app/: {cov}.")
    s += [shot(doc, "docs/screenshots/testing/full-suite-coverage.png", max_h_mm=230)]
    s += [shot(doc, "docs/screenshots/testing/unit-tests.png", max_h_mm=120)]
    s += [shot(doc, "docs/screenshots/testing/api-tests.png", max_h_mm=235)]
    s += [h2("Defects found and fixed while testing")]
    s += bullets([
        "<b>IAM trust evaluation</b>: a role trusting the account root returned early and hid a later wildcard or explicit principal; fixed to prefer the most permissive entry.",
        "<b>Snapshot billing</b>: steady-state history showed an artificial ramp because policy snapshots started with one copy; now the full retention window is generated and "
        "policy snapshots are billed incrementally.",
        "<b>Recommendation after resize</b>: metrics recorded before a resize described the old size and could trigger a second recommendation; the rules now ignore pre-resize metrics.",
        "<b>Evidence overwrite</b>: a finding's evidence lost the rule object because a text summary shared the key; renamed.",
        "<b>Live configuration patch</b>: unknown fields were silently ignored and nested price changes replaced the whole price table; now rejected (422) or deep-merged.",
        "<b>Topology highlighting</b>: ordinary HTTP/HTTPS world-open rules were flagged as exposure; only sensitive-port or all-port rules are flagged now.",
    ])

    # ---------------------------------------------------------------- 10 conclusion
    s += [h1("10. Conclusion")]
    s += [p(f"The CloudShield prototype was turned into a working, tested platform: a seeded Fake AWS simulator with persistent state, 20 state-derived detection rules, a cost model with "
            f"anomaly detection and recommendations, a preview-confirm-apply-verify remediation workflow, isolated what-if analysis, an append-only audit trail with drift detection, "
            f"role-based access and downloadable reports. {len(cases)} automated tests pass on SQLite and {pg_passed} of {len(pg_cases)} on PostgreSQL 16 with {cov} line coverage; the real UI walkthrough "
            f"completes without browser errors. Limits that matter for an evaluator: Docker images were written but not built here, mutation testing used a seeded sample of mutants, and all prices, "
            f"metrics and 'AWS' resources are simulated.")]

    # ---------------------------------------------------------------- appendix
    s += [PageBreak(), h1("Appendix A. Evidence register")]
    rows = [[e["file"].replace("docs/screenshots/", ""), e["title"], e["purpose"]] for e in sorted(REG.values(), key=lambda e: e["file"])]
    s += table(doc, ["File (docs/screenshots/)", "Shows", "Demonstrates"], rows, [44, 46, 80], caption="Every screenshot used in this report with its purpose.")
    doc.multiBuild(s)
    print("wrote", OUT, OUT.stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main()
