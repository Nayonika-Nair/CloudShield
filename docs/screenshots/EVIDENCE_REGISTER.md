# Evidence register

Every image below is a genuine screenshot of the running application (rendered by Chrome via Playwright) or a rendering of real captured command output (the unmodified text is next to it in `docs/testing/results/`). Nothing is mocked.

| # | File | Shows | Demonstrates | Source output |
|---|------|-------|--------------|---------------|
| 1 | `application/01-login.png` | Sign-in screen | Login view; credentials are validated by the API, not hard-coded in the page. | - |
| 2 | `application/02-login-rejected.png` | Rejected sign-in | A wrong password is refused with a generic message (HTTP 401). | - |
| 3 | `application/03-dashboard.png` | Dashboard (default environment) | KPIs, security posture, cost trend, cost by service and compliance derived from the persisted simulated environment. | - |
| 4 | `application/04-dashboard-after-scenarios.png` | Dashboard after scenarios and a rescan | Dashboard reflects the new findings, the cost anomaly and updated compliance posture. | - |
| 5 | `application/05-report-generated.png` | Generated report | Report built from persisted state: score, run-rate, estimated vs verified savings, remediation evidence, limitations. | - |
| 6 | `application/06-api-docs.png` | OpenAPI documentation | FastAPI /docs listing the simulator, analysis, remediation, what-if, audit and report endpoints. | - |
| 7 | `application/07-viewer-readonly.png` | Read-only viewer role | A viewer sees a notice and cannot generate environments or change state (also enforced by the API with HTTP 403). | - |
| 8 | `cost/01-cost-anomaly.png` | Cost analysis with a detected anomaly | Daily cost chart with the spike flagged (z-score above baseline), by-service breakdown and contributors. | - |
| 9 | `cost/02-cost-by-service.png` | Daily cost by service | Stacked daily cost per service from simulated billing. | - |
| 10 | `cost/03-optimization.png` | Optimization recommendations | Each recommendation shows evidence, estimated saving (labelled ESTIMATED), risk and the action to take. | - |
| 11 | `cost/04-recommendation-evidence.png` | Recommendation evidence and assumptions | Supporting metrics, assumptions, risk and the executable plan. | - |
| 12 | `cost/05-recommendation-whatif.png` | Recommendation what-if preview | Cost and security effect simulated before applying. | - |
| 13 | `cost/06-recommendation-verified.png` | Recommendation applied and verified | Run-rate before/after shows the verified (simulated) saving. | - |
| 14 | `cost/07-recommendation-status-verified.png` | Verified recommendation | Estimated and verified savings are shown separately. | - |
| 15 | `docker/compose-static-validation.png` | Static validation of docker-compose.yml and Dockerfiles | Compose file parses, defines db/backend/frontend with health checks, a named volume and dependency conditions (not a substitute for a real build). | `docs/testing/results/compose-static-validation.txt` |
| 16 | `docker/docker-availability.png` | Docker availability check on the development machine | Honest record: Docker is not installed here, so image build / compose up could not be executed. | `docs/testing/results/docker-availability.txt` |
| 17 | `docker/native-startup-persistence.png` | Clean start, health check and persistence across restart (native, PostgreSQL 16) | The same stack (FastAPI + PostgreSQL) started from an empty database, health-checked, restarted, with identical data afterwards. | `docs/testing/results/native-startup-persistence.txt` |
| 18 | `security/01-findings-clean.png` | Findings on the clean environment | Before any scenario: no critical or high findings are detected. | - |
| 19 | `security/02-sg-before-remediation.png` | Security group BEFORE remediation | The scenario's security group allows tcp/22 from 0.0.0.0/0 (resource state, before the fix). | - |
| 20 | `security/03-findings-after-scan.png` | Findings after the scenario and a scan | A new HIGH finding NET-001 appears, derived from the changed security group, public address and route. | - |
| 21 | `security/04-finding-evidence.png` | Finding with evidence | Explanation, impact, step-by-step reachability proof, detection rule, severity reason and timeline. | - |
| 22 | `security/05-remediation-preview.png` | Remediation preview (PROPOSED) | Plan, risk, and a what-if comparison computed on an isolated copy: score before/after, cost, availability, config diff. Nothing has changed yet. | - |
| 23 | `security/06-remediation-verified.png` | Remediation executed and verified | The change was applied to the simulated state, the analysis re-ran, and the condition is no longer detected (VERIFIED). | - |
| 24 | `security/07-sg-after-remediation.png` | Security group AFTER remediation | Same resource after remediation: the world-open SSH rule is gone (compare with the BEFORE screenshot). | - |
| 25 | `security/08-findings-resolved.png` | Resolved finding kept in history | The finding is RESOLVED because a re-scan no longer detects it; the record and its history remain. | - |
| 26 | `security/09-finding-resolution-detail.png` | Resolved finding detail | Timeline, resolving scan, remediation record and verification result. | - |
| 27 | `security/10-remediation-history.png` | Remediation and verification history | Proposed -> executed -> verified, with score and run-rate before/after. | - |
| 28 | `security/11-scan-comparison.png` | Scan history and comparison | Compare two scans: resolved/introduced findings and score change. | - |
| 29 | `security/12-detection-rules.png` | Detection rules catalogue | Each rule's logic and severity basis is documented and visible. | - |
| 30 | `security/13-iam-escalation.png` | IAM privilege escalation after a permissive role | AdministratorAccess on a workload role creates escalation paths from ordinary users; red edges show the chain. | - |
| 31 | `simulator/01-configuration.png` | Simulator configuration | Seed, region, resource counts, utilization, misconfiguration rates, quotas, time, pricing and scenario probabilities. | - |
| 32 | `simulator/02-configuration-security-rates.png` | Misconfiguration rates and scenario probabilities | Clean preset: misconfiguration rates are zero, so no flaw exists until a scenario creates it. | - |
| 33 | `simulator/03-generate-confirm.png` | Generate confirmation | Generation archives (does not delete) the previous environment and its history. | - |
| 34 | `simulator/04-environment-generated.png` | Environment generated | Active environment panel shows the seed, simulated clock, fingerprint and resulting resource counts (16 EC2 instances). | - |
| 35 | `simulator/05-environments-history.png` | Environment history | The earlier environment is ARCHIVED, not erased; scans and audit history remain. | - |
| 36 | `simulator/06-inventory.png` | Resource inventory | Paginated inventory of every simulated resource with state, key attributes, environment and monthly cost. | - |
| 37 | `simulator/07-resource-detail.png` | Resource detail drawer | Per-resource properties, tags, metrics, relationships, network reachability explanation and the validated operations available. | - |
| 38 | `simulator/08-network-topology-clean.png` | Network topology (no exposure) | VPCs, public/private subnets, internet gateways, instances, databases and security groups. Nothing is exposed on a sensitive port. | - |
| 39 | `simulator/09-iam-analysis.png` | IAM identity analysis | Principals, admin detection, MFA and access-key status, trust relationships and the escalation graph. | - |
| 40 | `simulator/10-time-and-scenarios.png` | Simulated time and scenarios | Manual clock controls and the ten scenarios; each changes state and names the rules expected to detect it. | - |
| 41 | `simulator/11-scenario-triggered.png` | Scenario applied | State changed (a world-open SSH rule was added); the 'state changed since last scan' chip appears because no finding exists until a scan runs. | - |
| 42 | `simulator/12-topology-exposed.png` | Network topology with an exposed instance | The instance is outlined red with 'EXPOSED 22' because the network model finds SSH reachable from the internet. | - |
| 43 | `simulator/13-whatif-result.png` | What-if comparison | Baseline vs hypothetical: cost, security score, availability, compliance and config diff; the baseline fingerprint is verified unchanged. | - |
| 44 | `simulator/14-audit-log.png` | Audit log | Append-only record of generation, scenarios, scans, remediation, what-if and time changes with actor, outcome and details. | - |
| 45 | `simulator/15-audit-event-detail.png` | Audit event with before/after | A remediation event stores the changed fields before and after. | - |
| 46 | `simulator/16-configuration-drift.png` | Configuration drift | Resources whose configuration differs from the saved baseline; security-relevant drift first. Drift is not a finding. | - |
| 47 | `testing/api-tests.png` | API tests: auth, roles, validation, GET purity, audit, remediation, what-if, reports | API-level evidence: valid and invalid input, unauthorised calls, missing resources, duplicate operations, read-only GETs, what-if isolation, audit creation. | `docs/testing/results/api-tests.txt` |
| 48 | `testing/frontend-contract-tests.png` | Frontend integration contract tests | Every API call made by the UI exists in the backend OpenAPI document; every button/handler is wired. | `docs/testing/results/frontend-contract-tests.txt` |
| 49 | `testing/full-suite-coverage.png` | Full suite on SQLite with coverage | Complete test run with line coverage of the application package. | `docs/testing/results/full-suite-coverage.txt` |
| 50 | `testing/full-suite-postgres.png` | Full suite on PostgreSQL 16 | The same suite executed against a real PostgreSQL 16 server (TEST_DATABASE_URL). | `docs/testing/results/full-suite-postgres.txt` |
| 51 | `testing/integration-tests.png` | Integration tests: simulator <-> database, engines <-> persisted history | Integration-testing evidence (simulator and database, optimistic locking, transactions, scan reconciliation). | `docs/testing/results/integration-tests.txt` |
| 52 | `testing/regression-tests.png` | Regression tests: original CloudShield behaviour | Regression evidence: original authentication, mock provider, label-based engines, original API routes and persistence still behave as before. | `docs/testing/results/regression-tests.txt` |
| 53 | `testing/unit-tests.png` | Unit tests: generator, lifecycle, network, IAM, rules, cost, time, what-if | Unit-test evidence: seed reproducibility, lifecycle validation, reachability, IAM evaluation, detection rules, cost arithmetic, anomaly detection, what-if isolation. | `docs/testing/results/unit-tests.txt` |
