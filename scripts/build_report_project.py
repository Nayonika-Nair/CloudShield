"""Build docs/reports/CloudShield_Project_Report.pdf from the repository, test results and screenshots."""

import re
import subprocess
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from report_lib import (  # noqa: E402
    BODY, CELL, REPO, ROOT, PageBreak, Report, SMALL, SUB, TITLE, Spacer, bullets, code, coverage_total, esc, excerpt, fig, h1, h2, h3,
    junit_cases, load_register, mutation_rows, p, table, toc,
)

OUT = ROOT / "docs" / "reports" / "CloudShield_Project_Report.pdf"
REG = {e["file"]: e for e in load_register()}


def shot(doc, rel, caption=None, **kw):
    e = REG.get(rel)
    return fig(doc, ROOT / rel, caption or (f"<b>{e['title']}.</b> {e['purpose']}" if e else rel), **kw)


def diagram(doc, name, caption, **kw):
    return fig(doc, ROOT / "docs" / "diagrams" / "rendered" / f"{name}.png", caption, **kw)


def main():
    from app.engines.security import RULES
    from app.simulator.lifecycle import OPS
    from app.simulator.scenarios import SCENARIOS

    doc = Report(OUT, "CloudShield - Project Report", "Project Report - CloudShield")
    cases = junit_cases(ROOT / "docs/testing/results/junit-sqlite.xml")
    pg_cases = junit_cases(ROOT / "docs/testing/results/junit-postgres.xml")
    cov, _ = coverage_total(ROOT / "docs/testing/results/full-suite-coverage.txt")
    mut = mutation_rows()
    by_module: dict[str, list] = {}
    for c in cases:
        by_module.setdefault(c["module"], []).append(c)
    s: list = []

    # ---------------------------------------------------------------- cover + toc
    s += [Spacer(1, 40), p("Project Report", SUB), p("CloudShield", TITLE),
          p("Intelligent Cloud Cost &amp; Security Optimization Platform", SUB), Spacer(1, 10),
          p("with a configurable, stateful Fake AWS simulator", SUB), Spacer(1, 26)]
    s += table(doc, ["Item", "Value"], [
        ["GitHub repository", REPO], ["Technology", "FastAPI, SQLAlchemy, PostgreSQL 16, vanilla HTML/CSS/JS, Docker Compose"],
        ["Report date", date.today().isoformat()],
        ["Companion document", "CloudShield_Digital_Assignment_3_Evidence.pdf (testing, version-management and system-building evidence)"],
        ["Scope note", "All cloud resources, prices and metrics are simulated. No real AWS account or credential is used."],
    ], [38, 132], bold_first=True)
    s += [PageBreak(), p("<b>Contents</b>"), toc(), PageBreak()]

    # ---------------------------------------------------------------- 1
    s += [h1("1. Introduction and problem statement")]
    s += [h2("1.1 Background")]
    s += [p("Organisations that run workloads on public cloud platforms accumulate hundreds of resources: virtual networks, servers, disks, buckets, databases and identities. "
            "Each resource can be misconfigured (an SSH port open to the whole internet, a public storage bucket, an administrator without multi-factor authentication) or can quietly "
            "waste money (an idle server, an unattached disk, an old snapshot). Security and cost are usually reviewed by different people with different tools, which makes it hard "
            "to see a single picture of risk and spend, and even harder to know whether a change that was made really solved the problem.")]
    s += [h2("1.2 Problem statement")]
    s += [p("Cloud administrators and analysts need one console that (a) shows what exists and how it is connected, (b) detects security weaknesses and cost waste with evidence they can trust, "
            "(c) lets them <i>simulate</i> a fix before touching anything, (d) applies a fix only after explicit confirmation, and (e) <i>verifies</i> that the underlying condition is gone. "
            "The earlier CloudShield prototype only displayed hard-coded sample data and its backend decided findings from text labels such as \"Open SSH\", so it could not demonstrate "
            "detection, remediation or verification honestly.")]
    s += [h2("1.3 Motivation")]
    s += [p("A real AWS environment is expensive, risky to experiment on and impossible to reproduce for assessment. A <b>configurable Fake AWS simulator</b> that behaves like a simplified cloud "
            "(related resources, state transitions, time, billing) removes those obstacles and lets every claim of the platform be demonstrated, tested and repeated with a seed.")]
    s += [h2("1.4 Objectives")]
    s += bullets([
        "Model a realistic, reproducible AWS-like account with consistent relationships, validated lifecycle operations, quotas and persistent state.",
        "Derive findings from state (network reachability, IAM policy graph, metrics, billing) - never from labels or injected results.",
        "Provide a controlled workflow: propose &rarr; preview &rarr; confirm &rarr; apply &rarr; re-scan &rarr; verify, with every change audited.",
        "Offer isolated what-if analysis and configuration-drift detection; keep history across regeneration.",
        "Integrate everything with the existing FastAPI/PostgreSQL/vanilla-JS code base, with authentication, roles and tests at every level.",
    ])
    s += [h2("1.5 Scope and limitations")]
    s += [p("<b>In scope:</b> the simulator and its persistence, 20 detection rules, cost model and recommendations, remediation, what-if, audit, drift, reports, the 11-view UI and the tests. "
            "<b>Out of scope / limitations:</b> no real AWS integration (the provider factory still refuses to enable AWS); prices are simulated and a month is 30 days; no partial-day billing; "
            "one region per environment; no NAT gateways or Lambda; detection covers the documented rules only; encryption of EBS/RDS is modelled in place; Docker images were written but "
            "not built on the development machine (Docker is not installed there); mutation testing used a seeded sample of mutants.")]

    # ---------------------------------------------------------------- 2
    s += [PageBreak(), h1("2. Requirements and user stories")]
    s += [h2("2.1 Stakeholders")]
    s += table(doc, ["Stakeholder", "Role in CloudShield", "Main interest"], [
        ["Cloud administrator", "<b>admin</b> role", "Configure and generate environments, change state, advance time, run scenarios"],
        ["Security / cost analyst", "<b>analyst</b> role", "Scan, explain findings, preview/apply remediation, what-if, reports"],
        ["IT manager / viewer", "<b>viewer</b> role", "Read dashboards, findings, costs, audit; download reports"],
        ["Developer / maintainer", "Repository user", "Run locally or with Docker, extend rules and the simulator"],
        ["Evaluator", "Reviewer", "Reproduce results from a seed; check evidence and limitations"],
    ], [38, 40, 92], caption="Stakeholders.")
    s += [h2("2.2 Functional requirements")]
    frs = [
        ("FR-01", "Authenticate users with e-mail and password (bcrypt hashes, JWT) and enforce admin / analyst / viewer roles on every state-changing endpoint.", "Auth, RBAC, 401/403 tests"),
        ("FR-02", "Configure the simulator: seed, account, region, counts, naming, tags, utilization mix, misconfiguration rates, IAM, quotas, thresholds, pricing, time and scenario probabilities; validate input.", "Config tests, UI form"),
        ("FR-03", "Generate a reproducible environment: same seed and configuration give identical identifiers and properties.", "Reproducibility tests"),
        ("FR-04", "Model EC2, EBS, snapshots, S3, RDS, IAM, security groups, VPCs, subnets, route tables, internet gateways, ENIs, Elastic IPs and load balancers with consistent relationships.", "Referential-integrity tests"),
        ("FR-05", "Support validated lifecycle operations (create, start, stop, resize, terminate, attach, encrypt, configure backups, change rules, routes, IAM, tags) and reject impossible transitions, duplicates and quota violations.", f"{len(OPS)} operations; lifecycle tests"),
        ("FR-06", "Keep simulated time under explicit control; time-driven metrics, billing, aging, backups; GET requests never advance time or mutate state.", "Time-engine and purity tests"),
        ("FR-07", "Persist configuration, resources, relationships, metrics, costs, scans, findings, recommendations, remediations, audit events, scenarios, what-ifs and reports in PostgreSQL; never erase history on regeneration.", "Integration tests"),
        ("FR-08", "Derive network reachability from VPC, subnet, route, gateway, address and security-group state and explain why a resource is or is not exposed; visualise topology.", "Network tests, topology view"),
        ("FR-09", "Model IAM (users, roles, policies, allow/deny, trust, role assumption, MFA, key age) and detect wildcard admin, missing MFA, stale keys, risky trust, escalation paths, excess admins.", "IAM tests"),
        ("FR-10", "Detect security issues with transparent rules; each finding carries id, severity (with reason), category, resource, evidence, explanation, impact, remediation, rule logic, first/last seen and status.", f"{len(RULES)} rules; rule tests"),
        ("FR-11", "Compute costs from simulated state, usage and a configurable (simulated) price list; keep daily history; detect anomalies; recommend savings with evidence, assumptions and risk.", "Cost and optimisation tests"),
        ("FR-12", "Trigger, enable and revert scenarios that change state; the same rules evaluate them.", f"{len(SCENARIOS)} scenarios"),
        ("FR-13", "Remediate with preview on an isolated copy, explicit confirmation, atomic execution, audit, re-scan and verification; resolve a finding only when the condition is gone.", "Remediation API tests"),
        ("FR-14", "What-if: evaluate hypothetical changes on a copy and show cost, security, availability, compliance and configuration differences without altering the baseline.", "What-if tests"),
        ("FR-15", "Append-only audit log with actor, target, outcome and before/after; configuration drift against a baseline kept separate from findings.", "Audit and drift tests"),
        ("FR-16", "Generate reports (PDF, CSV, JSON) from persisted state, separating estimated, simulated and verified values and stating assumptions.", "Report tests"),
        ("FR-17", "Provide a UI for dashboard, simulator, inventory, topology, IAM, findings, cost, optimization, what-if, audit/drift and reports with loading, empty, error and success states.", "UI walkthrough, contract tests"),
    ]
    s += table(doc, ["ID", "Requirement", "Verified by"], [[a, b, c] for a, b, c in frs], [14, 114, 42], caption="Functional requirements.")
    s += [h2("2.3 Non-functional requirements")]
    s += table(doc, ["ID", "Requirement", "How it is met"], [
        ["NFR-01 Security", "No hard-coded secrets; hashed passwords; least-privilege roles; no real cloud access", "Environment variables, bcrypt, role dependencies, DEMO_MODE guard in provider factory"],
        ["NFR-02 Reproducibility", "Same seed + state gives same results", "Hash-based stateless randomness; fingerprint comparisons in tests"],
        ["NFR-03 Integrity", "No invalid relationships; atomic multi-step changes", "Validation in lifecycle; run_operations rollback; optimistic locking on state_version"],
        ["NFR-04 Auditability", "Every state change recorded and not editable", "Append-only sim_audit_events; no update/delete routes"],
        ["NFR-05 Usability", "Formal light UI, accessible contrast, keyboard operation, clear states", "Design tokens, focus styles, ARIA roles, text + colour badges"],
        ["NFR-06 Performance", "Interactive response for ~200 resources", "Typical API calls 20-100 ms (measured locally); bulk inserts; no N+1 queries"],
        ["NFR-07 Maintainability", "Layered code, tests, documentation", "routers / services / engines / simulator split; 340+ tests; diagrams"],
        ["NFR-08 Portability", "Run with Docker or natively; configurable API base", "Compose files, .env.example, same-origin or configurable API base"],
        ["NFR-09 Honesty", "State limitations and never present estimates as results", "Estimated / simulated / verified labels; limitations in UI and reports"],
    ], [34, 62, 74], caption="Non-functional requirements.")
    s += [h2("2.4 User stories")]
    s += [p("The original project defined 25 user stories in docs/reports/User-Stories.md (authentication, dashboard, security findings, cost optimization, inventory, reports, deployment). "
            "They are retained and extended with simulator-specific stories.")]
    stories = [
        ("US-01..03", "Cloud Administrator", "log in / log out securely and have my authentication validated", "only authorised users can use CloudShield", "Implemented (JWT, roles)"),
        ("US-04..07", "Cloud Administrator", "see a dashboard of key metrics and navigate between modules", "I understand my estate quickly", "Implemented; live data"),
        ("US-08..11", "Security Analyst", "view, filter and track security findings by severity and status", "I can prioritise remediation", "Implemented with evidence"),
        ("US-12..15", "DevOps Engineer", "see spend, recommendations, underutilised resources and monthly estimates", "I can reduce cost", "Implemented; simulated prices"),
        ("US-16..19", "Cloud Administrator", "browse, search, filter and inspect resources", "I know what is deployed", "Implemented"),
        ("US-20..22", "IT Manager", "generate reports covering findings and cost recommendations", "I can share them", "Implemented (PDF/CSV/JSON)"),
        ("US-23..25", "Developer", "run with Docker, set up quickly, and prepare for AWS later", "contributors start fast", "Compose written; provider interface kept"),
        ("US-26", "Administrator", "generate a reproducible fake AWS environment from a seed and configuration", "demonstrations and tests are repeatable", "Implemented"),
        ("US-27", "Administrator", "advance simulated time manually", "I can observe metrics, billing and aging", "Implemented"),
        ("US-28", "Security Analyst", "trigger a scenario and see the rules detect it", "I can prove detection works", "Implemented (10 scenarios)"),
        ("US-29", "Security Analyst", "preview, confirm and verify a remediation", "I do not break things or mark issues fixed by mistake", "Implemented"),
        ("US-30", "Security Analyst", "run a what-if without changing the baseline", "I can compare options safely", "Implemented"),
        ("US-31", "IT Manager", "see an append-only audit trail and configuration drift", "I can trace what changed", "Implemented"),
        ("US-32", "Viewer", "read everything but not change anything", "safe access for stakeholders", "Implemented (403 on writes)"),
    ]
    s += table(doc, ["ID", "As a...", "I want to...", "So that...", "Status"], [list(x) for x in stories], [16, 26, 62, 42, 24], caption="User stories (original and new).")
    s += [h2("2.5 Acceptance criteria")]
    s += table(doc, ["Story", "Acceptance criterion (Given / When / Then)", "Automated check"], [
        ["US-26", "Given the same config and seed, when an environment is generated twice, then identifiers and properties are identical", "test_same_seed_and_config_reproduce_identical_environment"],
        ["US-27", "Given an environment, when 5 days are advanced in one step or in five steps, then the resulting state is identical; a GET never moves time", "test_advancing_in_one_step_or_many..., test_get_requests_never_change_state..."],
        ["US-28", "Given a clean environment, when 'open SSH' is triggered, then no finding exists until a scan, after which NET-001 appears for the instance", "test_scenario_changes_state_first_and_findings_only_appear_after_a_scan"],
        ["US-29", "Given a finding, when the plan hash is wrong or confirmation is missing, then apply is refused; when applied, the finding is RESOLVED only if the re-scan no longer detects it", "test_remediation_requires_preview_hash..., ..._not_resolved"],
        ["US-30", "Given a baseline, when a what-if is run and discarded, then the environment fingerprint and version are unchanged", "test_whatif_through_api_leaves_baseline_untouched..."],
        ["US-31", "Given any rejected or successful change, then an audit event exists and cannot be deleted through the API", "test_audit_log_is_append_only..."],
        ["US-32", "Given a viewer token, when a write endpoint is called, then HTTP 403 is returned", "test_roles_control_who_can_change_state"],
    ], [14, 100, 56], caption="Selected acceptance criteria and the tests that check them.")

    # ---------------------------------------------------------------- 3
    s += [PageBreak(), h1("3. System architecture and design")]
    s += [h2("3.1 Architecture")]
    s += [diagram(doc, "01-system-architecture", "<b>System architecture.</b> Browser, delivery layer, FastAPI layers and PostgreSQL. The simulator is a library used by the services; nothing connects to AWS.", width_mm=172)]
    s += [p("<b>Frontend</b> (vanilla ES modules) renders every number from API responses, keeps no business logic, and uses one delegated event system so that every control is declared and testable. "
            "<b>Backend</b> routers validate input (Pydantic) and authorise by role; <b>services</b> own transactions, auditing and persistence; <b>engines</b> are pure functions over an in-memory "
            "<i>Environment</i> (network, IAM, security, cost, optimisation, what-if, remediation, drift, compliance); the <b>simulator</b> generates and mutates that Environment through validated operations. "
            "<b>PostgreSQL</b> stores users and all simulator state and history.")]
    s += [diagram(doc, "07-component-diagram", "<b>Component diagram.</b> Responsibilities of frontend, interface, application, domain, simulator and legacy components.", width_mm=150, max_h_mm=210)]
    s += [h2("3.2 Fake AWS simulator design")]
    s += [p("An <i>Environment</i> is a plain-data object (resources by type, daily metrics, daily costs, id counters, baseline). Identifiers come from a counter hashed with the seed, so they are "
            "stable and collision-free. Daily metrics and costs are pure functions of (seed, resource, day), so advancing time in one step or many steps gives identical results. "
            "<b>Generation</b> builds network, IAM, compute, storage and data resources, then applies configured misconfiguration rates and optional scenario probabilities; <b>history</b> is back-filled for "
            "the configured number of days; a baseline snapshot is stored for drift. <b>Lifecycle</b> operations validate prerequisites (for example a volume must be unattached to be deleted; an instance must be "
            "stopped to resize; an ACL cannot be public while Block Public Access is on). <b>Billing</b> uses a configurable price list: EC2 hourly, EBS/S3/RDS storage, snapshots (policy snapshots incremental), "
            "idle Elastic IPs, load balancers and data transfer.")]
    s += [diagram(doc, "11-fake-aws-topology", "<b>Simulated network topology.</b> VPCs with public and private subnets, internet gateway, instances, RDS, S3, security groups and IAM relationships.", width_mm=150, max_h_mm=200)]
    s += [diagram(doc, "12-simulator-workflow", "<b>Simulator workflow</b> from configuration to report and the modules involved.", width_mm=172)]
    s += [h2("3.3 Data flow")]
    s += [diagram(doc, "02-dfd-level-0", "<b>DFD level 0.</b> CloudShield and its external actors.", width_mm=160, max_h_mm=100)]
    s += [diagram(doc, "03-dfd-level-1", "<b>DFD level 1.</b> Seven processes and seven data stores (tables of the implemented schema).", width_mm=172, max_h_mm=215)]
    s += [h2("3.4 Security detection and remediation workflows")]
    s += [diagram(doc, "13-detection-remediation-workflow", "<b>Detection and remediation workflow.</b> State &rarr; derived analysis &rarr; rules &rarr; findings &rarr; plan &rarr; preview &rarr; confirmation &rarr; execution &rarr; re-scan.", width_mm=172, max_h_mm=140)]
    s += [diagram(doc, "14-whatif-workflow", "<b>What-if workflow.</b> The simulation runs on an isolated copy and proves that the baseline fingerprint is unchanged.", width_mm=150, max_h_mm=210)]
    s += [h2("3.5 Database design")]
    s += [p("Tables are defined with SQLAlchemy (models.py for users and the original tables, sim_models.py for the simulator) and created idempotently at start-up; "
            "<font name='Courier'>database/schema.sql</font> is generated from the models. JSON columns hold resource documents, configuration, evidence and plans (JSONB on PostgreSQL). "
            "The original tables are kept unchanged; the simulator tables are prefixed <font name='Courier'>sim_</font> so a legacy scan cannot truncate simulator history.")]
    s += [diagram(doc, "erd-simulator", "<b>Entity-relationship diagram of the simulator schema</b> (generated from the SQLAlchemy models by scripts/generate_erd.py).", width_mm=172, max_h_mm=210)]
    s += [diagram(doc, "erd-core", "<b>Entity-relationship diagram of the original tables</b> (users and the legacy scan snapshot tables).", width_mm=160, max_h_mm=120)]
    s += [h2("3.6 API design")]
    api_rows = [
        ["POST /api/auth/register, /login; GET /api/auth/me", "any / authenticated", "Sign-up (viewer), JWT login, current user and role"],
        ["GET /api/sim/presets, /environment, /environments, /configs", "any user", "Presets, active environment, history, saved configs"],
        ["POST /api/sim/environments; /environment/reset; PATCH /environment/config; POST /configs", "admin", "Generate / regenerate; live pricing and thresholds; save config"],
        ["GET /api/sim/time; POST /time/advance", "any / admin", "Read or explicitly advance simulated time (1-90 days)"],
        ["GET /api/sim/resources, /resources/{id}, /actions; POST /resources/actions", "any / admin", "Inventory (filters, pagination), details, operation catalog, run an operation"],
        ["GET /api/sim/network/topology, /exposures, /reachability/{id}, /issues", "any user", "Derived topology and step-by-step reachability"],
        ["GET /api/sim/iam/analysis, /iam/evaluate", "any user", "Principals, graph, escalation paths, policy evaluation"],
        ["GET /api/sim/metrics, /costs/summary, /costs/history, /costs/anomalies, /costs/breakdown", "any user", "Metrics and billing views"],
        ["POST /api/sim/scans; GET /scans, /scans/{id}, /scans/compare, /findings, /findings/{id}, /recommendations, /rules", "analyst / any", "Scan, history, comparison, findings with timeline"],
        ["GET /api/sim/scenarios; POST /scenarios/{name}/trigger, /scenarios/executions/{id}/revert", "any / admin", "Scenario catalog, trigger and revert"],
        ["POST /api/sim/remediation/preview, /remediation/apply; GET /remediation", "analyst / any", "Preview (what-if), confirmed apply with plan hash, history"],
        ["POST /api/sim/whatif, /whatif/{id}/apply; GET /whatif, /whatif/{id}", "analyst / any", "Simulate, apply (confirmed), history"],
        ["GET /api/sim/audit, /drift, /compliance, /dashboard; POST /drift/baseline", "any / admin", "Governance views"],
        ["POST /api/sim/reports; GET /reports, /reports/{id}, /reports/{id}/download?format=pdf|csv|json", "analyst / any", "Report generation and export"],
        ["GET /health, /api/health", "public", "Liveness and database check"],
    ]
    s += table(doc, ["Endpoint(s)", "Role", "Purpose"], api_rows, [84, 24, 62], caption="API overview (full OpenAPI documentation at /docs).")
    s += [p("All errors use one shape, <font name='Courier'>{\"detail\", \"error\": {\"code\", \"message\"}}</font>, with correct status codes (401, 403, 404, 409 for state conflicts, 422 for validation). "
            "Lists are paginated; mutating operations run in a transaction with optimistic locking on <font name='Courier'>state_version</font>.")]

    # ---------------------------------------------------------------- 4
    s += [PageBreak(), h1("4. Implementation")]
    s += [h2("4.1 Modules and responsibilities")]
    s += table(doc, ["Module", "Responsibility"], [
        ["simulator/config.py", "Pydantic configuration with presets, quotas, pricing, thresholds, scenario probabilities and cross-field validation"],
        ["simulator/generator.py, builders.py", "Deterministic generation of network, IAM, compute, storage, data; misconfiguration injection; history back-fill"],
        ["simulator/lifecycle.py", f"{len(OPS)} validated operations registered in OPS with parameter specs and risk (feeds the UI catalog)"],
        ["simulator/timeengine.py, billing.py", "Manual simulated time; per-day metrics, costs, backup schedules, key usage, storage growth; price arithmetic"],
        ["simulator/scenarios.py", f"{len(SCENARIOS)} state-changing scenarios with diff-based revert"],
        ["engines/network.py", "Route/gateway/address/security-group reachability with step explanations; egress; topology graph"],
        ["engines/iam.py", "Policy evaluation (deny > allow > implicit deny), trust rules, escalation BFS (sts:AssumeRole, PassRole+RunInstances, IAM write)"],
        ["engines/security.py", f"{len(RULES)} detection rules producing evidence-rich findings and remediation plans; scoring"],
        ["engines/cost.py, optimization.py", "Run-rate, history, z-score anomalies; nine recommendation rules with assumptions and risk"],
        ["engines/whatif.py, remediation.py", "Isolated simulation and atomic operation execution; plan hashing"],
        ["engines/drift.py, compliance.py", "Baseline comparison (not findings) and posture checks"],
        ["services/*", "Transactions, optimistic locking, audit, scan reconciliation, reports, inventory"],
        ["routers/sim.py, main.py, auth.py", "REST API, error handling, health, CORS, JWT and roles"],
        ["frontend/js/*", "api.js, state.js (event delegation), navigation.js, views/*.js, remediation.js, topology_graph.js"],
    ], [52, 118], caption="Module responsibilities.")
    s += [h2("4.2 Simulator generation and lifecycle")]
    s += [p("Generation order is network &rarr; IAM &rarr; compute &rarr; load balancers &rarr; RDS &rarr; S3 &rarr; misconfiguration &rarr; optional scenarios &rarr; history. "
            "The following excerpt shows how a lifecycle operation validates prerequisites before it changes state; the same pattern is used by every operation.")]
    ops_src = (ROOT / "backend/app/simulator/lifecycle.py").read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(ops_src) if l.startswith('@op("ec2.change_type"')) + 1
    s += [code(excerpt("backend/app/simulator/lifecycle.py", start, start + 14))]
    s += [h2("4.3 Security detection")]
    s += [p("Reachability is evaluated hop by hop and the result becomes the finding's evidence. A resource is reachable from the internet only if a security-group rule allows 0.0.0.0/0, the resource is running, "
            "it has a public address and its subnet routes to an <i>attached</i> internet gateway of the same VPC. If a world-open rule exists on an unreachable resource it is reported as a low-severity latent finding.")]
    net_src = (ROOT / "backend/app/engines/network.py").read_text(encoding="utf-8").splitlines()
    st = next(i for i, l in enumerate(net_src) if l.startswith("def _exposure(")) + 1
    s += [code(excerpt("backend/app/engines/network.py", st, st + 22))]
    s += [p("<b>Severity</b> is rule-based and explained in every finding: each rule has a base severity; resources tagged environment=prod, databases and confidential data raise it by one level; the reason is stored "
            "with the finding. The score is 100 minus 8/4/2/1 per critical/high/medium/low finding.")]
    s += [shot(doc, "docs/screenshots/security/04-finding-evidence.png", width_mm=120, max_h_mm=210)]
    s += [h2("4.4 Cost calculation and optimisation")]
    s += [p("Monthly run-rate is the sum of each resource's configured daily charge times 30, plus data transfer implied by its current traffic and egress state. Billed history is accrued day by day from the same functions, "
            "so what-if results match applying the change. Anomalies use the trailing 14-day mean and standard deviation per service and in total, with an absolute floor to ignore noise. "
            "Recommendations never claim realised savings: they are <b>estimated</b>, become <b>simulated</b> when previewed and <b>verified</b> only when the run-rate measured after applying the plan is lower.")]
    s += [shot(doc, "docs/screenshots/cost/01-cost-anomaly.png", width_mm=165, max_h_mm=210)]
    s += [h2("4.5 Recommendations, remediation and verification")]
    rem_src = (ROOT / "backend/app/engines/remediation.py").read_text(encoding="utf-8").splitlines()
    st = next(i for i, l in enumerate(rem_src) if l.startswith("def run_operations")) + 1
    s += [code(excerpt("backend/app/engines/remediation.py", st, st + 17))]
    s += [p("<font name='Courier'>apply_remediation</font> re-runs the analysis, refuses a changed plan (hash mismatch, HTTP 409), executes the operations atomically, saves with optimistic locking, writes the audit "
            "events, runs a verification scan and sets the result to VERIFIED or NOT_RESOLVED. Findings are resolved by the scan reconciliation, not by the click.")]
    s += [diagram(doc, "08-sequence-remediation", "<b>Sequence diagram</b> of preview, apply and verification.", width_mm=165, max_h_mm=215)]
    s += [shot(doc, "docs/screenshots/security/05-remediation-preview.png", width_mm=120, max_h_mm=215)]
    s += [shot(doc, "docs/screenshots/security/06-remediation-verified.png", width_mm=120, max_h_mm=130)]
    s += [h2("4.6 What-if simulation")]
    s += [p("<font name='Courier'>whatif.simulate</font> takes a fingerprint of the baseline, analyses it, copies it, runs the changes on the copy, analyses the copy, and returns differences in cost, security (resolved and "
            "introduced findings, exposure), availability (steps that stop or resize, with dependent resources), compliance percentages and configuration. It then verifies that the baseline fingerprint is unchanged.")]
    s += [shot(doc, "docs/screenshots/simulator/13-whatif-result.png", width_mm=150, max_h_mm=215)]
    s += [h2("4.7 Audit logging and drift")]
    s += [p("Events are inserted by <font name='Courier'>services/audit.py</font> only; no route can update or delete them. Rejected operations are audited with the error. Drift compares current resources with the baseline, "
            "ignoring telemetry (bucket growth, last-used timestamps) and policy-managed snapshots, and marks security-relevant fields. It is deliberately separate from findings.")]
    s += [shot(doc, "docs/screenshots/simulator/14-audit-log.png", width_mm=150, max_h_mm=180)]
    s += [h2("4.8 Frontend")]
    s += [p("The original prototype's navigation and layout were preserved (sidebar sections, topbar, cards, tables) but restyled as a light, formal theme through design tokens. The monolithic inline script was replaced by "
            "ES modules. Dynamic values are escaped by a tagged-template helper, and a contract test checks that no hook is unwired. Tall dialogs and drawers are screenshot-tested in the walkthrough.")]
    s += [shot(doc, "docs/screenshots/application/03-dashboard.png", width_mm=160, max_h_mm=190)]

    # ---------------------------------------------------------------- 5
    s += [PageBreak(), h1("5. Design of tests")]
    s += [h2("5.1 Strategy")]
    s += [p("Testing is layered so that each kind of fault is caught where it is cheapest to find: <b>unit</b> tests on pure engines with deterministic seeds; <b>integration</b> tests across simulator, engines and database; "
            "<b>API</b> tests for contracts, authorisation and state consistency; <b>regression</b> tests that pin the original behaviour; <b>frontend contract</b> tests; one <b>end-to-end</b> workflow; "
            "<b>mutation testing</b> to measure how sensitive the tests are; and a <b>real-browser walkthrough</b> for the UI. The suite runs on SQLite by default and on PostgreSQL via <font name='Courier'>TEST_DATABASE_URL</font>.")]
    descr = {
        "test_generator_config": ("Unit", "Seed reproducibility, validation of config, relationships, presets"),
        "test_lifecycle": ("Unit", "Every operation's prerequisites, duplicates, quotas, invalid references"),
        "test_network_iam": ("Unit", "Reachability chain, route/IGW/SG changes, egress, IAM allow/deny, trust, escalation"),
        "test_security_rules": ("Unit", "Each rule fires only from state; severity bumps; scenarios; pure evaluation"),
        "test_cost_time": ("Unit", "Billing arithmetic, time-step equivalence, metrics, anomalies, recommendations"),
        "test_whatif_drift": ("Unit", "What-if isolation and atomicity, remediation fixes findings, drift, compliance, scenario revert"),
        "test_integration_db": ("Integration", "DB round trip, history append-only, optimistic lock, rollback, scan reconciliation"),
        "test_api": ("API", "Auth/roles, validation, 404/409/422, GET purity, audit, remediation, what-if, reports"),
        "test_regression_legacy": ("Regression", "Original auth, provider, engines, routes, persistence, schema upgrade"),
        "test_e2e_workflow": ("End-to-end", "Full demo workflow over HTTP"),
        "test_frontend_contract": ("Frontend contract", "UI API calls exist in OpenAPI; all hooks have handlers"),
    }
    rows = []
    for mod, cs in sorted(by_module.items()):
        ok = sum(c["status"] == "passed" for c in cs)
        lvl, what = descr.get(mod, ("", ""))
        rows.append([f"{mod}.py", lvl, what, len(cs), ok])
    rows.append(["<b>Total (SQLite)</b>", "", f"Line coverage of app/: {cov}", len(cases), sum(c["status"] == "passed" for c in cases)])
    rows.append(["<b>Total (PostgreSQL 16)</b>", "", "Same tests, real PostgreSQL", len(pg_cases), sum(c["status"] == "passed" for c in pg_cases)])
    s += table(doc, ["File", "Level", "What it checks", "Tests", "Passed"], rows, [38, 22, 78, 16, 16], caption="Test suite composition and actual results.")
    s += [h2("5.2 Representative test cases")]
    tcs = [
        ["TC-01", "Generate twice with the same seed", "Identical fingerprints", "Passed", "test_same_seed_and_config_reproduce_identical_environment"],
        ["TC-02", "Stop an already stopped instance", "409 invalid_state; state unchanged; audited as REJECTED", "Passed", "test_invalid_and_duplicate_operations_are_rejected..."],
        ["TC-03", "SSH rule on a public instance, then remove the default route", "Reachable, then blocked at the routing step", "Passed", "test_removing_the_default_route_blocks..."],
        ["TC-04", "Wildcard trust on a role", "Any user can assume it; IAM-004 raised CRITICAL", "Passed", "test_wildcard_trust_lets_anyone_assume; test_risky_trust_severity..."],
        ["TC-05", "Advance 5 days in one step vs five steps", "Identical state", "Passed", "test_advancing_in_one_step_or_many_gives_identical_state"],
        ["TC-06", "Trigger cost-spike scenario, advance 2 days", "Total anomaly with contributors", "Passed", "test_cost_spike_is_flagged_with_contributors_and_baseline"],
        ["TC-07", "What-if stop idle instance", "Cost falls, baseline fingerprint unchanged", "Passed", "test_whatif_never_mutates_the_baseline; ..._cost_matches_actually_applying"],
        ["TC-08", "Apply remediation with wrong plan hash / no confirm", "409 / 422, state untouched", "Passed", "test_remediation_requires_preview_hash_and_explicit_confirmation"],
        ["TC-09", "Apply remediation correctly", "State changed, finding RESOLVED, verification VERIFIED, audit events", "Passed", "test_remediation_changes_state_rescans_and_resolves..."],
        ["TC-10", "Verification fails (condition persists)", "NOT_RESOLVED; finding stays OPEN", "Passed", "test_remediation_that_does_not_fix_the_condition..."],
        ["TC-11", "Two writers save the same version", "Second gets 409 conflict", "Passed", "test_optimistic_locking_rejects_a_stale_writer"],
        ["TC-12", "Viewer calls a write endpoint", "403", "Passed", "test_roles_control_who_can_change_state"],
        ["TC-13", "Regenerate environment", "Old environment archived; scans/findings/audit remain", "Passed", "test_regenerating_archives_the_old_environment_and_keeps_history"],
        ["TC-14", "Legacy dashboard route", "Same 15 resources, score 96, $1,120", "Passed", "test_dashboard_values_match_scan_baseline"],
    ]
    s += table(doc, ["ID", "Input / action", "Expected outcome", "Actual", "Automated test"], tcs, [12, 46, 52, 14, 46], caption="Representative test cases with expected and actual outcomes (all executed; the full list is in Appendix F).")
    s += [h2("5.3 Mutation testing")]
    if mut:
        tot_c = sum(m["complete"] for m in mut)
        tot_k = sum(m["killed"] for m in mut)
        rows = [[m["module"], m["label"], m["complete"], m["killed"], m["survived"], f"{m['score_pct']}%"] for m in mut]
        rows.append(["<b>All</b>", "", tot_c, tot_k, sum(m["survived"] for m in mut), f"{round(tot_k / tot_c * 100, 1)}%"])
        s += [p("Cosmic Ray 8.4.1 was run on eight modules that hold the security rules, cost calculation, IAM logic, network reachability, configuration validation, recommendations and remediation. "
                "A seeded random sample of up to 120 mutants per module was tested (annotation-only mutants excluded because they either crash at import or change nothing at runtime).")]
        s += table(doc, ["Module", "Covers", "Tested", "Killed", "Survived", "Score"], rows, [46, 62, 14, 14, 16, 18], caption="Mutation results (docs/testing/mutation).")
        surv = [m for m in mut if m["survived"]]
        s += [p(("Surviving mutants are listed with their diffs in docs/testing/mutation/*.survivors.txt. " if surv else "No sampled mutant survived. ") +
                "A killed mutant means the suite failed after the code was altered; it does not prove every behaviour is tested, and unsampled mutants were not run. Equivalent mutants (changes with no observable effect) would appear as survivors and are not hidden.")]
    s += [h2("5.4 API, end-to-end and system tests")]
    s += [p("API tests cover valid and invalid input, missing resources, unauthorised calls, unsupported transitions, duplicates, state consistency, read-only GETs, what-if isolation, audit creation and remediation verification. "
            "The end-to-end test follows the demo script (generate, authenticate, scan, scenario, remediate, what-if, audit, report). The Playwright walkthrough repeats the flow in a real browser and fails on any console error. "
            "System start-up and persistence across a restart were verified natively against PostgreSQL 16 (Docker was unavailable).")]
    s += [h2("5.5 Known limitations of the tests")]
    s += bullets([
        "Docker image builds and <font name='Courier'>docker compose up</font> were not executed (no Docker on the development machine); only static validation and a native run were done.",
        "Mutation testing used a sample, and lifecycle.py was not mutation-tested.",
        "The UI is verified by one scripted walkthrough, not by a full cross-browser matrix.",
        "Performance was observed (tens of milliseconds per request locally) but no load test was performed.",
    ])

    # ---------------------------------------------------------------- 6
    s += [PageBreak(), h1("6. Results and demonstration")]
    s += [h2("6.1 Implemented features")]
    s += table(doc, ["Feature", "Status", "Evidence"], [
        ["Configurable seeded Fake AWS environment (16 resource types, quotas, presets, saved configs)", "Implemented", "Simulator screenshots, config and generator tests"],
        ["Validated lifecycle operations (%d), controlled time, metrics, billing" % len(OPS), "Implemented", "Lifecycle and time tests"],
        ["Derived network reachability, topology view, IAM graph and escalation", "Implemented", "Topology and IAM screenshots"],
        ["%d detection rules and %d scenarios (revertible)" % (len(RULES), len(SCENARIOS)), "Implemented", "Security tests, scenario screenshots"],
        ["Cost run-rate, history, anomalies and 9 recommendation rules", "Implemented", "Cost screenshots, cost tests"],
        ["Preview / confirm / apply / verify remediation", "Implemented", "Remediation screenshots and API tests"],
        ["What-if without baseline change; audit; drift; reports (PDF/CSV/JSON)", "Implemented", "Screenshots, tests"],
        ["Roles (admin / analyst / viewer) and JWT authentication", "Implemented", "API tests, viewer screenshot"],
        ["Docker Compose stack", "Written, not built here", "Static validation, native equivalent run"],
        ["Real AWS integration", "Not implemented (by design)", "Provider factory still refuses AWS"],
    ], [92, 32, 46], caption="Feature status.")
    s += [h2("6.2 Example: security detection and remediation")]
    s += [p("On a clean environment (no critical or high findings) the <i>SSH open to the internet</i> scenario adds a security group allowing tcp/22 from 0.0.0.0/0 to a public Linux instance. "
            "Nothing changes in the findings until a scan runs; then rule NET-001 raises a HIGH finding whose evidence shows the four satisfied hops. After remediation the same security group has no world-open rule, "
            "the verification scan no longer detects the condition, the finding is RESOLVED (kept in history) and the security score rises.")]
    s += [shot(doc, "docs/screenshots/security/02-sg-before-remediation.png", width_mm=110, max_h_mm=200)]
    s += [shot(doc, "docs/screenshots/security/07-sg-after-remediation.png", width_mm=110, max_h_mm=200)]
    s += [shot(doc, "docs/screenshots/security/08-findings-resolved.png", width_mm=150, max_h_mm=150)]
    s += [h2("6.3 Example: cost optimisation")]
    s += [p("The <i>cost spike</i> scenario launches three large instances; after three simulated days the daily cost jumps and is flagged as an anomaly with the new instances as contributors. "
            "A recommendation shows its evidence (CPU averages, projected utilisation after right-sizing), assumptions and risk; previewing it simulates the saving, and applying it produces a verified saving "
            "measured from the run-rate before and after.")]
    s += [shot(doc, "docs/screenshots/cost/03-optimization.png", width_mm=150, max_h_mm=210)]
    s += [shot(doc, "docs/screenshots/cost/06-recommendation-verified.png", width_mm=125, max_h_mm=120)]
    s += [h2("6.4 Demo workflow")]
    s += bullets([
        "Sign in &rarr; Dashboard.", "Simulator: choose the <i>Clean</i> preset, 16 instances, seed 2026, Generate.", "Inventory and Topology: nothing exposed.",
        "Trigger <i>SSH open to the internet</i>; observe the stale-scan chip; run a scan.", "Open the finding and read the evidence; see the red node in the topology.",
        "Preview remediation (what-if, baseline unchanged), confirm, apply; read VERIFIED.", "Re-open the security group (before/after) and the resolved finding.",
        "Trigger <i>cost spike</i> (+3 days); Cost anomaly; Optimization; apply a recommendation.", "What-If: stop an instance; confirm the baseline is unchanged.",
        "Audit log and Drift; generate and download the report.",
    ])
    s += [shot(doc, "docs/screenshots/application/05-report-generated.png", width_mm=150, max_h_mm=200)]

    # ---------------------------------------------------------------- 7
    s += [h1("7. Conclusion and future enhancements")]
    s += [p("CloudShield now demonstrates the complete loop from configuration to verified remediation on a reproducible simulated cloud, with evidence-based findings, honest cost estimates, isolated what-if analysis "
            "and an auditable history. The most useful design decision was to derive every finding from simulated state: it makes scenarios, remediation and verification genuine, and it exposed real defects during testing.")]
    s += [p("<b>Future enhancements:</b> Alembic migrations; a real AWS provider behind the existing provider interface (read-only first); NAT gateways, Lambda and multi-region; a rule-pack format with per-rule enable/disable; "
            "exhaustive mutation testing in CI; a container-based CI pipeline that builds the images and runs the suite on PostgreSQL; role administration in the UI; and websocket-driven live updates for auto-advancing time.")]

    # ---------------------------------------------------------------- 8 appendix
    s += [PageBreak(), h1("8. Appendix")]
    s += [h2("Appendix A. Software Requirements Specification (summary)")]
    s += [p("<b>Purpose.</b> This SRS summarises the requirements of CloudShield v2.0 following the structure of IEEE 830. "
            "<b>Product perspective.</b> A web application (single-page UI + REST API + PostgreSQL) that analyses a simulated AWS account. "
            "<b>User classes.</b> Administrator, analyst and viewer. <b>Operating environment.</b> Python 3.11+, PostgreSQL 16 (or SQLite for development), any modern browser. "
            "<b>Constraints.</b> No real AWS credentials or API calls; simulated prices; JWT authentication; UTF-8 JSON API. <b>Assumptions.</b> Simulated time is advanced only explicitly. "
            "Functional and non-functional requirements are listed in Section 2 (Tables 2-3); interfaces: HTTPS/JSON REST API documented by OpenAPI, SQLAlchemy persistence, static web UI.")]
    s += [h2("Appendix B. DFD level 0 and level 1")]
    s += [p("See Figures in Section 3.3 (DFD level 0 and DFD level 1).")]
    s += [h2("Appendix C. Entity-relationship diagrams")]
    s += [p("See Section 3.5. The ER diagrams are generated from the models, so they cannot drift from the implementation.")]
    s += [h2("Appendix D. UML diagrams")]
    s += [diagram(doc, "05-use-case", "<b>UML use-case diagram.</b>", width_mm=165, max_h_mm=210)]
    s += [diagram(doc, "06-class-diagram", "<b>UML class diagram</b> of the main domain classes, engine modules and persistence classes.", width_mm=172, max_h_mm=215)]
    s += [diagram(doc, "09-activity-remediation", "<b>UML activity diagram</b> of the remediation workflow.", width_mm=140, max_h_mm=215)]
    s += [diagram(doc, "10-state-lifecycles", "<b>UML state diagram</b> of finding, recommendation and EC2 instance lifecycles.", width_mm=172, max_h_mm=150)]
    s += [p("The component diagram (Figure in Section 3.1) and the sequence diagram (Figure in Section 4.5) complete the UML set; all sources are in docs/diagrams/source.")]
    s += [h2("Appendix E. Code listings and repository")]
    s += [p(f"Complete source: <font name='Courier'>{REPO}</font>. Key listings are in Sections 4.2, 4.3 and 4.5; the optimistic-locking save used by every state change is shown here:")]
    s += [code(excerpt("backend/app/services/env_store.py", next(i for i, l in enumerate((ROOT / "backend/app/services/env_store.py").read_text(encoding="utf-8").splitlines()) if l.startswith("def save")) + 1, 
                       next(i for i, l in enumerate((ROOT / "backend/app/services/env_store.py").read_text(encoding="utf-8").splitlines()) if l.startswith("def save")) + 16))]
    s += [h3("API documentation reference")]
    s += [p("Interactive: <font name='Courier'>/docs</font> (Swagger UI) and <font name='Courier'>/openapi.json</font> on the running API; screenshot in the evidence PDF.")]
    s += [h3("Installation and execution")]
    s += [code("# Docker (see README for details)\ncp .env.example .env   # set secrets\ndocker compose up --build   # UI :3000, API :8000/docs\n\n"
               "# Native\npython -m venv .venv && .venv\\Scripts\\activate\npip install -r backend/requirements-dev.txt\n"
               "set DATABASE_URL=postgresql://user:pass@localhost:5432/cloudshield\nset JWT_SECRET_KEY=change-me\nset ADMIN_EMAIL=admin@example.com & set ADMIN_PASSWORD=change-me-1234\n"
               "cd backend && uvicorn app.main:app --port 8000      # UI and API on http://localhost:8000\n\n"
               "# Tests\ncd backend && python -m pytest tests -q\nTEST_DATABASE_URL=postgresql://... python -m pytest tests -q")]
    s += [h2("Appendix F. Test-case table (all automated tests)")]
    rows = [[c["module"].replace("test_", ""), c["name"], c["status"], f"{c['time']:.2f}s"] for c in cases]
    s += table(doc, ["Module", "Test", "Result", "Time"], rows, [30, 112, 14, 14], caption="Every automated test with its result (JUnit report of the SQLite run).")
    s += [h2("Appendix G. Additional screenshots")]
    for rel in ["docs/screenshots/simulator/01-configuration.png", "docs/screenshots/simulator/06-inventory.png", "docs/screenshots/simulator/09-iam-analysis.png",
                "docs/screenshots/simulator/12-topology-exposed.png", "docs/screenshots/security/13-iam-escalation.png", "docs/screenshots/simulator/16-configuration-drift.png",
                "docs/screenshots/application/06-api-docs.png", "docs/screenshots/testing/api-tests.png"]:
        if rel in REG:
            s += [shot(doc, rel, width_mm=150, max_h_mm=190)]
    doc.multiBuild(s)
    print("wrote", OUT, OUT.stat().st_size // 1024, "KB")


if __name__ == "__main__":
    main()
