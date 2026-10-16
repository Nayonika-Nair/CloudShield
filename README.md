# CloudShield — Intelligent Cloud Cost & Security Optimization Platform

CloudShield helps a team **understand** a cloud estate, **find** security weaknesses and wasted spend, **simulate** fixes, **apply** them after explicit confirmation and **verify** that the problem is really gone.
It runs against a configurable, stateful **Fake AWS simulator**, so no AWS account or credentials are needed and no real infrastructure is ever touched.

> Repository: <https://github.com/Nayonika-Nair/CloudShield> · API docs (when running): `http://localhost:8000/docs`

```
Configure → Provision → Observe → Analyze → Detect → Simulate → Remediate → Verify → Compare → Report
```

## What is in the box

| Area | What it does |
|---|---|
| **Fake AWS simulator** | Seeded, reproducible account: VPCs, subnets, route tables, internet gateways, ENIs, security groups, EC2, EBS, snapshots, Elastic IPs, load balancers, RDS, S3, IAM users/roles/policies. Validated lifecycle operations, quotas, a manual simulated clock, daily metrics and billing, backup schedules and key-age aging. |
| **Detection** | 20 documented rules that read *state* (derived network reachability, IAM policy graph, metrics, billing) — findings are never injected. Severity logic is explained per finding. |
| **Scenarios** | 10 scenarios (public bucket, open SSH/RDP, over-permissive IAM, missing encryption/backup, suspicious outbound traffic, cost spike, excess admins, risky network). Each *changes state*; the normal rules then detect it. Scenarios can be reverted. |
| **Cost** | Simulated price list (configurable, clearly **not** AWS prices), run-rate, daily history, z-score anomaly detection, 9 recommendation rules with evidence, assumptions, risk and estimated saving. |
| **Remediation** | Preview on an isolated copy → explicit confirmation → atomic execution → full re-scan. A finding is resolved only if the condition is gone. *Estimated*, *simulated* and *verified* values are labelled separately. |
| **What-if** | Evaluate up to 20 changes on a copy; cost, score, exposure, downtime, compliance and config diff; proves the baseline fingerprint is unchanged. |
| **Governance** | Append-only audit log with before/after values, configuration drift against a baseline, PDF/CSV/JSON reports built from persisted state. |
| **Platform** | FastAPI + SQLAlchemy + PostgreSQL, JWT auth with `admin` / `analyst` / `viewer` roles, vanilla HTML/CSS/JS frontend (light theme), Docker Compose. |

## Architecture

```
Browser (vanilla ES modules) ── REST/JSON ──► FastAPI ─► services ─► engines ─► Fake AWS simulator
        ▲                                         │            └──────────────► PostgreSQL (users, sim_* tables)
        └──────────── nginx (static + /api proxy) ┘
```

```
backend/app/
  main.py            app wiring, health, CORS, consistent errors, start-up seeding
  auth.py            bcrypt + JWT, role dependencies
  routers/sim.py     /api/sim/* REST API          routes.py   original /api/* routes (kept)
  services/          sim_service, scan, env_store, audit, reporting, inventory
  engines/           network, iam, security, cost, optimization, whatif, remediation, drift, compliance, analysis
  simulator/         config, generator, builders, lifecycle, timeengine, billing, scenarios, catalog, env
  sim_models.py      simulator tables            models.py   users + original tables
  providers/, security_engine.py, cost_engine.py, recommendation_engine.py   original label-based engines (kept for regression)
frontend/            index.html, css/, js/ (api.js, state.js, navigation.js, views/*.js)
docs/                diagrams/ (source + rendered), screenshots/, testing/, reports/ (the two PDFs)
scripts/             schema, ERD, diagram, walkthrough, mutation and report tooling
```

Diagrams (Mermaid source in `docs/diagrams/source`, rendered in `docs/diagrams/rendered`): system architecture, DFD 0/1, ERDs generated from the models, use case, class, component, sequence, activity, state, Fake AWS topology and the simulator / detection / what-if workflows.

## Prerequisites

* Python 3.11+ and Git
* PostgreSQL 16 **or** Docker Desktop (Compose v2). For a quick look you can use SQLite (`DATABASE_URL=sqlite:///./cloudshield-dev.db`).
* Node.js is only needed to re-render diagrams.

## Configuration

Copy `.env.example` to `.env` and change every value. Nothing is hard-coded; `.env` is git-ignored.

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLAlchemy URL (PostgreSQL in Compose) |
| `JWT_SECRET_KEY` | token signing key (required in Compose) |
| `ADMIN_EMAIL/PASSWORD`, `ANALYST_*`, `VIEWER_*` | accounts created at start-up when set |
| `SEED_DEMO_ENVIRONMENT` | generate the default demo environment on an empty database |
| `SIM_AUTO_ADVANCE_SECONDS` | optional automatic clock advance (0 = manual only) |
| `SERVE_FRONTEND` / `FRONTEND_DIR` | let uvicorn also serve `frontend/` (default on when the folder exists) |
| `CORS_ORIGINS` | allowed browser origins when the UI is served elsewhere |

## Run with Docker (recommended)

```bash
cp .env.example .env            # edit the secrets
docker compose up --build
```

* UI: <http://localhost:3000> (nginx proxies `/api` to the backend)
* API + Swagger: <http://localhost:8000/docs> · health: <http://localhost:8000/health>
* PostgreSQL data persists in the `cloudshield-pgdata` volume; tables are created automatically at start-up.

## Run locally without Docker

```bash
python -m venv .venv && .venv\Scripts\activate          # Windows;  source .venv/bin/activate elsewhere
pip install -r backend/requirements-dev.txt
set DATABASE_URL=postgresql://user:pass@localhost:5432/cloudshield   # or sqlite:///./cloudshield-dev.db
set JWT_SECRET_KEY=change-me & set ADMIN_EMAIL=admin@example.com & set ADMIN_PASSWORD=change-me-1234
cd backend && uvicorn app.main:app --port 8000
```

Open <http://localhost:8000> (uvicorn serves the UI too) and sign in with the admin account you configured.
`python scripts/run_postgres.py` starts a throw-away PostgreSQL via the `pgserver` package when you have neither Docker nor a local server.

## Using the simulator

1. **Simulator → Configuration**: pick a preset (clean / typical / neglected), set the seed, region, counts, utilization, misconfiguration rates, quotas, pricing and scenario probabilities, then *Generate environment*. The previous environment is archived; its history is kept.
2. **Time & scenarios**: advance the clock manually; trigger a scenario (state changes), then **Security Findings → Run scan**.
3. Open a finding: evidence, explanation, step-by-step reachability proof, detection rule. **Preview and remediate** → tick confirmation → **Apply**; the verification result shows whether the condition is gone.
4. **Cost / Optimization**: anomalies, run-rate, recommendations; **What-If** to evaluate changes; **Audit & Drift** and **Reports** for governance.

Reading pages (every `GET`) never changes state or time.

## API

Interactive docs at `/docs` (OpenAPI at `/openapi.json`). Main groups under `/api/sim`: `environments`, `time`, `resources` (+`actions`), `network/*`, `iam/*`, `metrics`, `costs/*`, `scans`, `findings`, `recommendations`, `scenarios`, `remediation/{preview,apply}`, `whatif`, `audit`, `drift`, `compliance`, `reports`, `dashboard`. Errors share one shape: `{"detail": "...", "error": {"code": "...", "message": "..."}}`. Roles: viewers read; analysts also scan, remediate, run what-ifs and make reports; admins also configure, change state, advance time and run scenarios.

## Tests

```bash
cd backend
python -m pytest tests -q                           # 410+ tests (SQLite by default)
TEST_DATABASE_URL=postgresql://... python -m pytest tests -q    # same suite on PostgreSQL
python -m pytest tests --cov=app --cov-report=term
python ../scripts/run_mutation.py --jobs 4 security cost billing iam config   # Cosmic Ray mutation testing
python ../scripts/ui_walkthrough.py --admin EMAIL:PASS --viewer EMAIL:PASS    # drives the real UI, captures screenshots
```

Layers: unit (generator, lifecycle, network, IAM, rules, cost, time, optimisation, what-if, drift), integration (simulator ↔ database, optimistic locking, transactions), API (auth/roles, validation, purity of `GET`, audit), regression (original auth, mock provider, engines, routes, persistence), frontend contract (every API call and `data-action` in the UI is wired) and an end-to-end workflow.

## Demo script (≈10 minutes)

1. Sign in → Dashboard. 2. Simulator: *Clean* preset, 16 instances, generate. 3. Inventory & Topology: nothing exposed. 4. Time & scenarios → **SSH open to the internet** → note the "state changed" chip. 5. Run scan → new HIGH finding; open it and read the reachability steps. 6. Topology shows the instance outlined red. 7. Preview remediation (what-if, baseline unchanged) → confirm → VERIFIED. 8. Re-open the security group: the rule is gone; finding is RESOLVED with history. 9. Trigger **cost spike** with 3 days → Cost anomaly → Optimization recommendation → apply → verified saving. 10. What-If: stop an instance, show baseline unchanged. 11. Audit log, Drift, Report (PDF).

## Known limitations

* Everything is simulated: prices are not AWS prices, a month is 30 days, there is no partial-day billing, one region per environment, no NAT gateways.
* Detection covers the documented rule set only; it does not claim to find every real attack.
* Encrypting EBS/RDS is modelled in place (real AWS needs snapshot-copy/restore); scenario revert restores the touched resources' earlier copies.
* Alembic is not used (no migration system existed): tables are created idempotently at start-up and a startup check adds `users.role`; `database/schema.sql` is generated for reference.
* The Docker images were written and statically validated, but **Docker was not available on the machine used for development**, so `docker compose up` was not executed there. The same stack (FastAPI + PostgreSQL 16 + static UI) was run and tested natively; see the project report.
* The original label-based engines and mock provider are kept unchanged for regression; they under-detect compared with the state-derived rules.

## Version management

GitHub Flow with a `develop` integration branch: `feature/simulator-core`, `feature/frontend-integration`, … merged with `--no-ff`. See `git log --graph --oneline --all`.

License: see `LICENSE`.
