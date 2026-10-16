"""API and integration tests: auth, validation, state consistency, audit, remediation, what-if, reports."""

import pytest

from tests.helpers import first


def hdr(h):
    return h


def state(c, h):
    env = c.get("/api/sim/environment", headers=h).json()
    return env["state_version"], env["fingerprint"], env["sim_time"]


def audit_total(c, h):
    return c.get("/api/sim/audit?page_size=1", headers=h).json()["total"]


def finding(c, h, rule, status="OPEN"):
    items = c.get(f"/api/sim/findings?status={status}&page_size=200", headers=h).json()["items"]
    return first(items, rule_id=rule)


# ----------------------------------------------------------------------- auth
def test_every_simulator_endpoint_requires_authentication(client):
    for path in ("/api/sim/dashboard", "/api/sim/resources", "/api/sim/findings", "/api/sim/audit", "/api/sim/presets"):
        assert client.get(path).status_code == 401
    assert client.post("/api/sim/environments", json={}).status_code == 401


def test_roles_control_who_can_change_state(client, admin, analyst, viewer):
    assert client.post("/api/sim/environments", headers=viewer, json={}).status_code == 403
    assert client.post("/api/sim/environments", headers=analyst, json={}).status_code == 403
    assert client.post("/api/sim/environments", headers=admin, json={"preset": "clean"}).status_code == 201
    assert client.post("/api/sim/scans", headers=viewer).status_code == 403
    assert client.post("/api/sim/scans", headers=analyst).status_code == 201
    assert client.post("/api/sim/time/advance", headers=analyst, json={"days": 1}).status_code == 403
    assert client.post("/api/sim/scenarios/open_ssh/trigger", headers=analyst, json={}).status_code == 403
    assert client.post("/api/sim/resources/actions", headers=viewer, json={"action": "eip.allocate"}).status_code == 403
    assert client.get("/api/sim/dashboard", headers=viewer).status_code == 200
    assert client.post("/api/sim/whatif", headers=viewer, json={"changes": [{"action": "eip.allocate"}]}).status_code == 403


def test_registration_creates_a_viewer_who_cannot_modify_the_simulator(client, admin):
    r = client.post("/api/auth/register", json={"email": "new.user@example.com", "password": "long-enough-1"})
    assert r.status_code == 201 and r.json()["role"] == "viewer" and "password" not in r.text
    token = client.post("/api/auth/login", json={"email": "new.user@example.com", "password": "long-enough-1"}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=h).json()["role"] == "viewer"
    assert client.post("/api/sim/environments", headers=h, json={}).status_code == 403


def test_tampered_or_garbage_token_is_rejected(client):
    assert client.get("/api/sim/dashboard", headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401


# ------------------------------------------------------------------ validation
def test_no_environment_gives_a_clear_404(client, admin):
    r = client.get("/api/sim/dashboard", headers=admin)
    assert r.status_code == 404 and r.json()["error"]["code"] == "no_environment"


def test_invalid_configuration_returns_422_with_readable_message(client, admin):
    r = client.post("/api/sim/environments", headers=admin, json={"config": {"region": "mars-1", "counts": {"vpcs": 0}}})
    assert r.status_code == 422
    body = r.json()
    assert body["error"]["code"] == "invalid_configuration" and "region" in body["detail"] and "counts.vpcs" in body["detail"]


def test_request_body_validation_uses_consistent_error_shape(sim):
    c, h = sim
    r = c.post("/api/sim/time/advance", headers=h, json={"days": 500})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error" and r.json()["error"]["fields"]
    assert c.post("/api/sim/remediation/apply", headers=h, json={"kind": "oops", "id": 1, "plan_hash": "x" * 8}).status_code == 422
    assert c.post("/api/sim/whatif", headers=h, json={"changes": []}).status_code == 422
    assert c.get("/api/sim/findings?severity=EXTREME", headers=h).status_code == 422
    assert c.get("/api/sim/resources?page_size=9999", headers=h).status_code == 422


def test_unknown_ids_return_404_not_500(sim):
    c, h = sim
    for path in ("/api/sim/resources/i-nope", "/api/sim/findings/99999", "/api/sim/scans/99999", "/api/sim/whatif/99999",
                 "/api/sim/reports/99999", "/api/sim/network/reachability/i-nope", "/api/sim/metrics?resource_id=i-nope"):
        r = c.get(path, headers=h)
        assert r.status_code == 404 and r.json()["error"]["code"] == "not_found", path


# ------------------------------------------------------------- state & purity
def test_get_requests_never_change_state_time_or_audit_log(sim):
    c, h = sim
    before = state(c, h), audit_total(c, h)
    paths = ["/api/sim/dashboard", "/api/sim/environment", "/api/sim/environments", "/api/sim/resources", "/api/sim/network/topology",
             "/api/sim/network/exposures", "/api/sim/iam/analysis", "/api/sim/costs/summary", "/api/sim/costs/history",
             "/api/sim/costs/anomalies", "/api/sim/costs/breakdown", "/api/sim/findings", "/api/sim/recommendations",
             "/api/sim/scans", "/api/sim/drift", "/api/sim/compliance", "/api/sim/scenarios", "/api/sim/whatif",
             "/api/sim/time", "/api/sim/actions", "/api/sim/rules", "/api/sim/reports", "/api/sim/remediation", "/api/sim/network/issues"]
    for p in paths:
        assert c.get(p, headers=h).status_code == 200, p
    inst = c.get("/api/sim/resources?type=ec2_instance", headers=h).json()["items"][0]["id"]
    for p in (f"/api/sim/resources/{inst}", f"/api/sim/network/reachability/{inst}", f"/api/sim/metrics?resource_id={inst}"):
        assert c.get(p, headers=h).status_code == 200
    assert (state(c, h), audit_total(c, h)) == before


def test_environment_generation_is_reproducible_across_api_calls(client, admin):
    cfg = {"config": {"seed": 7, "counts": {"ec2_instances": 6}}}
    a = client.post("/api/sim/environments", headers=admin, json=cfg).json()["environment"]
    b = client.post("/api/sim/environments", headers=admin, json=cfg).json()["environment"]
    assert a["id"] != b["id"] and a["fingerprint"] == b["fingerprint"] and a["counts"] == b["counts"]
    c = client.post("/api/sim/environments", headers=admin, json={"config": {"seed": 8, "counts": {"ec2_instances": 6}}}).json()["environment"]
    assert c["fingerprint"] != a["fingerprint"]


def test_regenerating_archives_the_old_environment_and_keeps_history(sim):
    c, h = sim
    old_id = c.get("/api/sim/environment", headers=h).json()["id"]
    scans_before = c.get("/api/sim/scans", headers=h).json()["total"]
    assert scans_before >= 1
    c.post("/api/sim/environment/reset", headers=h)
    envs = c.get("/api/sim/environments", headers=h).json()["items"]
    assert [e["status"] for e in envs] == ["ACTIVE", "ARCHIVED"] and envs[1]["id"] == old_id
    from app.database import SessionLocal
    from app.sim_models import SimAuditEvent, SimFinding, SimScan
    with SessionLocal() as db:
        assert db.query(SimScan).filter(SimScan.environment_id == old_id).count() == scans_before
        assert db.query(SimFinding).filter(SimFinding.environment_id == old_id).count() > 0
        assert db.query(SimAuditEvent).filter(SimAuditEvent.environment_id == old_id).count() > 0
    actions = [e["action"] for e in c.get("/api/sim/audit?page_size=200", headers=h).json()["items"]]
    assert "ENVIRONMENT_RESET" in actions and "ENVIRONMENT_GENERATED" in actions


def test_time_advance_updates_clock_metrics_and_costs_and_is_audited(sim):
    c, h = sim
    inst = c.get("/api/sim/resources?type=ec2_instance&state=running", headers=h).json()["items"][0]["id"]
    n_before = len(c.get(f"/api/sim/metrics?resource_id={inst}&metric=cpu&days=120", headers=h).json()["metrics"]["cpu"])
    hist_before = len(c.get("/api/sim/costs/history?days=120", headers=h).json()["items"])
    r = c.post("/api/sim/time/advance", headers=h, json={"days": 4})
    assert r.status_code == 200 and r.json()["advance"]["days"] == 4 and r.json()["sim_time"].startswith("2026-10-05")
    assert len(c.get(f"/api/sim/metrics?resource_id={inst}&metric=cpu&days=120", headers=h).json()["metrics"]["cpu"]) == n_before + 4
    assert len(c.get("/api/sim/costs/history?days=120", headers=h).json()["items"]) == hist_before + 4
    ev = c.get("/api/sim/audit?action=TIME_ADVANCED", headers=h).json()["items"][0]
    assert ev["details"]["days"] == 4 and ev["actor"] == "admin@example.com"


# --------------------------------------------------------------------- inventory
def test_inventory_pagination_filters_and_details(sim):
    c, h = sim
    page1 = c.get("/api/sim/resources?page=1&page_size=10", headers=h).json()
    page2 = c.get("/api/sim/resources?page=2&page_size=10", headers=h).json()
    assert page1["total"] == page2["total"] and len(page1["items"]) == 10
    assert {i["id"] for i in page1["items"]}.isdisjoint({i["id"] for i in page2["items"]})
    ec2 = c.get("/api/sim/resources?type=ec2_instance&page_size=200", headers=h).json()
    assert ec2["total"] == 14 and all(i["type"] == "ec2_instance" for i in ec2["items"])
    assert all("monthly_cost" in i for i in ec2["items"])
    stopped = c.get("/api/sim/resources?type=ec2_instance&state=stopped", headers=h).json()["items"]
    assert all(i["state"] == "stopped" for i in stopped)
    q = c.get("/api/sim/resources?q=prod-web", headers=h).json()
    assert q["total"] >= 1 and all("prod-web" in i["name"] for i in q["items"])
    detail = c.get(f"/api/sim/resources/{ec2['items'][0]['id']}", headers=h).json()
    assert detail["reachability"]["resource_id"] == ec2["items"][0]["id"]
    assert {"relationships_out", "relationships_in", "metrics", "actions", "monthly_cost"} <= set(detail)
    iam = c.get("/api/sim/resources/user:alice", headers=h)
    assert iam.status_code == 200 and iam.json()["type"] == "iam_user"


# --------------------------------------------------------- lifecycle through API
def test_lifecycle_action_changes_state_and_is_audited_with_before_after(sim):
    c, h = sim
    inst = c.get("/api/sim/resources?type=ec2_instance&state=running", headers=h).json()["items"][0]["id"]
    v0 = state(c, h)[0]
    r = c.post("/api/sim/resources/actions", headers=h, json={"action": "ec2.stop", "target_id": inst})
    assert r.status_code == 200 and r.json()["changes"]["modified"][inst]["state"] == {"before": "running", "after": "stopped"}
    assert state(c, h)[0] == v0 + 1
    assert c.get(f"/api/sim/resources/{inst}", headers=h).json()["resource"]["state"] == "stopped"
    ev = c.get(f"/api/sim/audit?target_id={inst}", headers=h).json()["items"][0]
    assert ev["action"] == "ACTION:ec2.stop" and ev["before"][inst]["state"] == "running" and ev["after"][inst]["state"] == "stopped"


def test_invalid_and_duplicate_operations_are_rejected_without_changing_state_but_are_audited(sim):
    c, h = sim
    inst = c.get("/api/sim/resources?type=ec2_instance&state=running", headers=h).json()["items"][0]["id"]
    assert c.post("/api/sim/resources/actions", headers=h, json={"action": "ec2.stop", "target_id": inst}).status_code == 200
    snapshot = state(c, h)
    r = c.post("/api/sim/resources/actions", headers=h, json={"action": "ec2.stop", "target_id": inst})
    assert r.status_code == 409 and r.json()["error"]["code"] == "invalid_state"
    assert c.post("/api/sim/resources/actions", headers=h, json={"action": "ec2.start", "target_id": "i-missing"}).status_code == 404
    assert c.post("/api/sim/resources/actions", headers=h, json={"action": "bogus"}).status_code == 422
    assert c.post("/api/sim/resources/actions", headers=h, json={"action": "ebs.create", "params": {"size_gb": -5, "az": "us-east-1a"}}).status_code == 422
    assert state(c, h) == snapshot
    rejected = c.get("/api/sim/audit?outcome=REJECTED", headers=h).json()
    assert rejected["total"] >= 4 and "error" in rejected["items"][0]["details"]


def test_duplicate_bucket_and_quota_conflicts_return_409(sim):
    c, h = sim
    assert c.post("/api/sim/resources/actions", headers=h, json={"action": "s3.create_bucket", "params": {"name": "acme-fresh-bucket"}}).status_code == 200
    r = c.post("/api/sim/resources/actions", headers=h, json={"action": "s3.create_bucket", "params": {"name": "acme-fresh-bucket"}})
    assert r.status_code == 409 and r.json()["error"]["code"] == "duplicate_id"


def test_pricing_can_be_changed_but_structural_config_cannot(sim):
    c, h = sim
    before = c.get("/api/sim/costs/summary", headers=h).json()["monthly_run_rate"]
    cfg = c.get("/api/sim/environment", headers=h).json()["config"]["pricing"]["ec2_hourly"]
    r = c.patch("/api/sim/environment/config", headers=h, json={"pricing": {"ec2_hourly": {k: v * 2 for k, v in cfg.items()}}})
    assert r.status_code == 200
    assert c.get("/api/sim/costs/summary", headers=h).json()["monthly_run_rate"] > before
    assert c.patch("/api/sim/environment/config", headers=h, json={"pricing": {"ec2_hourly": {"t3.micro": 1}}}).status_code == 422
    events = c.get("/api/sim/audit?action=CONFIG_CHANGED", headers=h).json()["items"]
    assert events and events[0]["before"] and events[0]["after"]


# ------------------------------------------------------------- scenarios & scans
def test_scenario_changes_state_first_and_findings_only_appear_after_a_scan(sim):
    c, h = sim
    c.post("/api/sim/environments", headers=h, json={"preset": "clean"})
    assert not [f for f in c.get("/api/sim/findings?status=OPEN&page_size=200", headers=h).json()["items"] if f["severity"] in ("HIGH", "CRITICAL")]
    t = c.post("/api/sim/scenarios/open_ssh/trigger", headers=h, json={})
    assert t.status_code == 201 and t.json()["targets"]
    inst, sg = t.json()["targets"]
    assert sg in c.get(f"/api/sim/resources/{inst}", headers=h).json()["resource"]["sg_ids"]  # underlying state changed
    assert not [f for f in c.get("/api/sim/findings?status=OPEN&page_size=200", headers=h).json()["items"] if f["rule_id"] == "NET-001"]
    dash = c.get("/api/sim/dashboard", headers=h).json()
    assert dash["stale"] is True  # state changed since the last scan
    scan = c.post("/api/sim/scans", headers=h).json()["scan"]
    assert scan["new_findings"] == 1
    f = finding(c, h, "NET-001")
    assert f["resource_id"] == inst and f["evidence"]["reachable"] is True
    assert c.get("/api/sim/dashboard", headers=h).json()["stale"] is False


def test_scenario_can_be_reverted_and_revert_is_audited(sim):
    c, h = sim
    c.post("/api/sim/environments", headers=h, json={"preset": "clean"})
    ex = c.post("/api/sim/scenarios/public_s3_bucket/trigger", headers=h, json={}).json()
    bucket = ex["targets"][0]
    assert c.get(f"/api/sim/resources/{bucket}", headers=h).json()["resource"]["acl"] == "public-read"
    r = c.post(f"/api/sim/scenarios/executions/{ex['execution_id']}/revert", headers=h)
    assert r.status_code == 200 and c.get(f"/api/sim/resources/{bucket}", headers=h).json()["resource"]["acl"] == "private"
    assert c.post(f"/api/sim/scenarios/executions/{ex['execution_id']}/revert", headers=h).status_code == 409
    assert c.post("/api/sim/scenarios/meteor/trigger", headers=h, json={}).status_code == 404
    assert [e for e in c.get("/api/sim/scenarios", headers=h).json()["executions"] if e["status"] == "REVERTED"]
    assert c.get("/api/sim/audit?action=SCENARIO", headers=h).json()["total"] >= 2


def test_time_dependent_scenario_surfaces_through_metrics_scan_and_cost_anomaly(sim):
    c, h = sim
    c.post("/api/sim/environments", headers=h, json={"preset": "clean"})
    c.post("/api/sim/scenarios/suspicious_outbound/trigger", headers=h, json={"advance_days": 3})
    c.post("/api/sim/scans", headers=h)
    f = finding(c, h, "NET-008")
    assert f["evidence"]["ratio"] >= 8 and f["resource_type"] == "ec2_instance"


def test_scan_history_comparison_and_finding_lifecycle(sim):
    c, h = sim
    c.post("/api/sim/environments", headers=h, json={"preset": "clean"})
    s1 = c.get("/api/sim/scans", headers=h).json()["items"][0]
    c.post("/api/sim/scenarios/public_s3_bucket/trigger", headers=h, json={})
    s2 = c.post("/api/sim/scans", headers=h).json()["scan"]
    cmp = c.get(f"/api/sim/scans/compare?a={s1['id']}&b={s2['id']}", headers=h).json()
    assert [x["finding_key"][:6] for x in cmp["introduced"]] == ["S3-001"] and cmp["score_delta"] < 0
    f = finding(c, h, "S3-001")
    c.post("/api/sim/resources/actions", headers=h, json={"action": "s3.make_private", "target_id": f["resource_id"]})
    s3 = c.post("/api/sim/scans", headers=h).json()["scan"]
    assert s3["resolved_findings"] == 1
    resolved = c.get(f"/api/sim/findings/{f['id']}", headers=h).json()
    assert resolved["finding"]["status"] == "RESOLVED" and resolved["finding"]["resolution"] == "NO_LONGER_DETECTED"
    c.post("/api/sim/scenarios/public_s3_bucket/trigger", headers=h, json={"params": {"target": f["resource_id"]}})
    c.post("/api/sim/scans", headers=h)
    history = c.get(f"/api/sim/findings/{f['id']}", headers=h).json()["history"]
    assert len(history) == 2 and {x["status"] for x in history} == {"RESOLVED", "OPEN"}  # old record kept, new one opened


# ----------------------------------------------------------------- remediation
def test_remediation_requires_preview_hash_and_explicit_confirmation(sim):
    c, h = sim
    f = finding(c, h, "NET-001")
    v0 = state(c, h)
    pv = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": f["id"]}).json()
    assert pv["status"] == "PROPOSED" and pv["preview"]["baseline_unchanged"] and state(c, h)[:2] == v0[:2]
    plan = pv["plan"]
    base = {"kind": "finding", "id": f["id"], "plan_hash": plan["plan_hash"]}
    assert c.post("/api/sim/remediation/apply", headers=h, json={**base}).status_code == 422          # no confirmation
    assert c.post("/api/sim/remediation/apply", headers=h, json={**base, "confirm": False}).status_code == 422
    r = c.post("/api/sim/remediation/apply", headers=h, json={**base, "plan_hash": "0" * 16, "confirm": True})
    assert r.status_code == 409 and r.json()["error"]["code"] == "plan_changed"
    assert state(c, h)[:2] == v0[:2]


def test_remediation_changes_state_rescans_and_resolves_only_when_condition_is_gone(sim):
    c, h = sim
    f = finding(c, h, "NET-001")
    inst, sg = f["resource_id"], f["evidence"]["security_group"]
    before_sg = c.get(f"/api/sim/resources/{sg}", headers=h).json()["resource"]["ingress"]
    pv = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": f["id"]}).json()
    r = c.post("/api/sim/remediation/apply", headers=h, json={"kind": "finding", "id": f["id"], "plan_hash": pv["plan"]["plan_hash"], "confirm": True})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "EXECUTED" and body["verification"] == "VERIFIED"
    after_sg = c.get(f"/api/sim/resources/{sg}", headers=h).json()["resource"]["ingress"]
    assert len(after_sg) == len(before_sg) - 1                                  # real state change
    fresh = c.get(f"/api/sim/findings/{f['id']}", headers=h).json()
    assert fresh["finding"]["status"] == "RESOLVED" and fresh["finding"]["resolution"] == "REMEDIATED"
    assert fresh["finding"]["remediation_id"] == body["remediation"]["id"] and fresh["remediations"][0]["verification"] == "VERIFIED"
    rem = body["remediation"]
    assert rem["score_after"] > rem["score_before"] and rem["before"] and rem["after"]
    actions = [e["action"] for e in c.get(f"/api/sim/audit?page_size=200", headers=h).json()["items"]]
    for expected in ("REMEDIATION_PREVIEWED", "REMEDIATION_APPLIED", "REMEDIATION_VERIFIED", "SCAN_COMPLETED"):
        assert expected in actions
    assert not any(x["finding_key"] == f["finding_key"] for x in c.get("/api/sim/findings?status=OPEN&page_size=200", headers=h).json()["items"])
    assert inst  # target instance still exists; only the exposure was removed
    again = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": f["id"]})
    assert again.status_code == 409                                              # already resolved


def test_remediation_that_does_not_fix_the_condition_is_reported_as_not_resolved(sim, monkeypatch):
    c, h = sim
    f = finding(c, h, "ENC-001")
    pv = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": f["id"]}).json()
    from app.engines import security
    original = security.evaluate

    def never_fixed(env, ctx=None):  # simulate a rule that still detects the issue after the change
        out = original(env, ctx)
        if not any(x["finding_key"] == f["finding_key"] for x in out):
            out.append(dict(f, remediation=f["remediation"], resource_id=f["resource_id"]))
        return out

    monkeypatch.setattr(security, "evaluate", never_fixed)
    r = c.post("/api/sim/remediation/apply", headers=h, json={"kind": "finding", "id": f["id"], "plan_hash": pv["plan"]["plan_hash"], "confirm": True})
    assert r.status_code == 200 and r.json()["verification"] == "NOT_RESOLVED"
    assert c.get(f"/api/sim/findings/{f['id']}", headers=h).json()["finding"]["status"] == "OPEN"   # not marked resolved by the click


def test_cost_recommendation_lifecycle_estimated_then_verified(sim):
    c, h = sim
    recs = c.get("/api/sim/recommendations?status=OPEN&page_size=200", headers=h).json()
    rec = first([r for r in recs["items"] if r["remediation"]["supported"]], rule_id="OPT-001")
    assert rec["savings_basis"] == "ESTIMATED" and rec["simulated"] is False and rec["realized_monthly_savings"] is None
    pv = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "recommendation", "id": rec["id"]}).json()
    assert pv["preview"]["cost"]["estimated_monthly_savings"] == pytest.approx(rec["estimated_monthly_savings"], abs=0.01)
    mid = first(c.get("/api/sim/recommendations?page_size=200", headers=h).json()["items"], id=rec["id"])
    assert mid["simulated"] is True and mid["status"] == "OPEN" and mid["whatif_id"] == pv["whatif_id"]
    res = c.post("/api/sim/remediation/apply", headers=h, json={"kind": "recommendation", "id": rec["id"], "plan_hash": pv["plan"]["plan_hash"], "confirm": True}).json()
    assert res["verification"] == "VERIFIED" and res["remediation"]["savings_basis"].startswith("VERIFIED")
    done = first(c.get("/api/sim/recommendations?page_size=200", headers=h).json()["items"], id=rec["id"])
    assert done["status"] == "VERIFIED" and done["savings_basis"].startswith("VERIFIED")
    assert done["realized_monthly_savings"] == pytest.approx(rec["estimated_monthly_savings"], abs=0.01)
    assert c.get("/api/sim/recommendations", headers=h).json()["totals"]["verified_monthly_savings"] >= done["realized_monthly_savings"]


def test_unsupported_remediation_is_reported_not_attempted(sim):
    c, h = sim
    c.post("/api/sim/scenarios/excessive_admin/trigger", headers=h, json={})
    c.post("/api/sim/scans", headers=h)
    f = finding(c, h, "IAM-006")
    r = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": f["id"]}).json()
    assert r["supported"] is False and r["preview"] is None
    assert c.post("/api/sim/remediation/apply", headers=h, json={"kind": "finding", "id": f["id"], "plan_hash": "abcdef12", "confirm": True}).status_code in (409, 422)


# ---------------------------------------------------------------------- what-if
def test_whatif_through_api_leaves_baseline_untouched_until_explicit_apply(sim):
    c, h = sim
    inst = first(c.get("/api/sim/recommendations?page_size=200", headers=h).json()["items"], rule_id="OPT-001")["resource_id"]
    snap = state(c, h)
    audit_before = audit_total(c, h)
    r = c.post("/api/sim/whatif", headers=h, json={"title": "stop idle", "changes": [{"action": "ec2.stop", "target_id": inst}]})
    assert r.status_code == 201
    w = r.json()
    assert w["result"]["baseline_unchanged"] is True and w["status"] == "SIMULATED"
    assert w["result"]["cost"]["delta_monthly"] < 0 and w["result"]["operational"]["requires_restart"]
    assert state(c, h) == snap                                                     # live state identical
    assert c.get(f"/api/sim/resources/{inst}", headers=h).json()["resource"]["state"] == "running"
    assert audit_total(c, h) == audit_before + 1                                   # the what-if itself is audited
    assert c.post(f"/api/sim/whatif/{w['id']}/apply", headers=h, json={}).status_code == 422   # needs confirm
    ok = c.post(f"/api/sim/whatif/{w['id']}/apply", headers=h, json={"confirm": True})
    assert ok.status_code == 200 and c.get(f"/api/sim/resources/{inst}", headers=h).json()["resource"]["state"] == "stopped"
    assert c.post(f"/api/sim/whatif/{w['id']}/apply", headers=h, json={"confirm": True}).status_code == 409
    assert c.get(f"/api/sim/whatif/{w['id']}", headers=h).json()["status"] == "APPLIED"


def test_failing_whatif_is_rejected_without_state_change(sim):
    c, h = sim
    snap = state(c, h)
    r = c.post("/api/sim/whatif", headers=h, json={"changes": [{"action": "ec2.stop", "target_id": "i-missing"}]})
    assert r.status_code == 404 and state(c, h) == snap


# ------------------------------------------------------------ audit/drift/reports
def test_audit_log_is_append_only_filterable_and_paginated(sim):
    c, h = sim
    total = audit_total(c, h)
    assert c.delete("/api/sim/audit", headers=h).status_code in (404, 405)
    assert c.put("/api/sim/audit/1", headers=h, json={}).status_code in (404, 405)
    c.post("/api/sim/time/advance", headers=h, json={"days": 1})
    assert audit_total(c, h) == total + 1
    first_page = c.get("/api/sim/audit?page_size=2&page=1", headers=h).json()
    second = c.get("/api/sim/audit?page_size=2&page=2", headers=h).json()
    assert len(first_page["items"]) == 2 and {e["id"] for e in first_page["items"]}.isdisjoint({e["id"] for e in second["items"]})
    ids = [e["id"] for e in c.get("/api/sim/audit?page_size=200", headers=h).json()["items"]]
    assert ids == sorted(ids, reverse=True)
    assert all(e["action"].startswith("SCAN") for e in c.get("/api/sim/audit?action=SCAN&page_size=50", headers=h).json()["items"])


def test_drift_and_baseline_endpoints(sim):
    c, h = sim
    assert c.get("/api/sim/drift", headers=h).json()["summary"]["total"] == 0
    c.post("/api/sim/scenarios/public_s3_bucket/trigger", headers=h, json={})
    d = c.get("/api/sim/drift", headers=h).json()
    assert d["summary"]["security_relevant"] >= 1 and d["kind"] == "drift"
    assert c.post("/api/sim/drift/baseline", headers=h).status_code == 200
    assert c.get("/api/sim/drift", headers=h).json()["summary"]["total"] == 0
    assert c.post("/api/sim/drift/baseline", headers=h).status_code == 200


def test_reports_are_built_from_state_and_downloadable(sim):
    c, h = sim
    f = finding(c, h, "NET-001")
    pv = c.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": f["id"]}).json()
    c.post("/api/sim/remediation/apply", headers=h, json={"kind": "finding", "id": f["id"], "plan_hash": pv["plan"]["plan_hash"], "confirm": True})
    rid = c.post("/api/sim/reports", headers=h, json={"report_type": "full"}).json()["id"]
    content = c.get(f"/api/sim/reports/{rid}", headers=h).json()["content"]
    assert content["security"]["resolved_findings"] and content["remediation"][0]["verification"] == "VERIFIED"
    assert content["cost"]["estimated_monthly_savings"] > 0 and content["audit_events"] and content["assumptions_and_limitations"]
    assert "ESTIMATED" in str(content["cost"]["recommendations"][0]["savings_basis"])
    pdf = c.get(f"/api/sim/reports/{rid}/download?format=pdf", headers=h)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and "attachment" in pdf.headers["content-disposition"]
    csv = c.get(f"/api/sim/reports/{rid}/download?format=csv", headers=h).text
    assert "SECURITY FINDINGS" in csv and "COST RECOMMENDATIONS" in csv and "REMEDIATIONS" in csv
    assert c.get(f"/api/sim/reports/{rid}/download?format=json", headers=h).json()["title"] == "Full Infrastructure Report"
    assert c.get(f"/api/sim/reports/{rid}/download?format=exe", headers=h).status_code == 422
    for kind in ("security", "cost", "verification"):
        assert c.post("/api/sim/reports", headers=h, json={"report_type": kind}).status_code == 201
    assert len(c.get("/api/sim/reports", headers=h).json()["items"]) == 4
    assert c.post("/api/sim/reports", headers=h, json={"report_type": "secret"}).status_code == 422


def test_presets_and_saved_configurations(sim):
    c, h = sim
    p = c.get("/api/sim/presets", headers=h).json()
    assert {x["name"] for x in p["presets"]} == {"clean", "typical", "neglected"} and "us-east-1" in p["regions"]
    assert len(p["scenarios"]) == 10
    saved = c.post("/api/sim/configs", headers=h, json={"name": "small", "config": {"counts": {"ec2_instances": 3}}})
    assert saved.status_code == 201 and saved.json()["config"]["counts"]["ec2_instances"] == 3
    assert c.post("/api/sim/configs", headers=h, json={"name": "bad", "config": {"region": "x"}}).status_code == 422
    assert [x["name"] for x in c.get("/api/sim/configs", headers=h).json()["items"]] == ["small"]


def test_dashboard_aggregates_real_state(sim):
    c, h = sim
    d = c.get("/api/sim/dashboard", headers=h).json()
    assert d["security"]["open_findings"] == sum(d["security"]["severity_counts"].values()) == d["latest_scan"]["findings_open"]
    assert d["cost"]["monthly_run_rate"] == pytest.approx(sum(d["cost"]["by_service"].values()), abs=0.05)
    assert len(d["cost"]["history"]) == 30 and d["environment"]["counts"]["ec2_instance"] == 14
    assert d["recommendations"]["verified_monthly_savings"] == 0 and d["recommendations"]["estimated_monthly_savings"] > 0
    assert d["top_findings"][0]["severity"] in ("CRITICAL", "HIGH")


def test_network_and_iam_endpoints_return_derived_analysis(sim):
    c, h = sim
    topo = c.get("/api/sim/network/topology", headers=h).json()
    assert topo["summary"]["vpcs"] == 2 and any(n["type"] == "internet" for n in topo["nodes"])
    ex = c.get("/api/sim/network/exposures?reachable=true", headers=h).json()
    assert ex["total"] > 0 and all(e["reachable"] for e in ex["items"])
    ia = c.get("/api/sim/iam/analysis", headers=h).json()
    assert ia["summary"]["users"] == 6 and ia["graph"]["nodes"]
    ev = c.get("/api/sim/iam/evaluate?principal=user:alice&action=s3:GetObject", headers=h).json()
    assert ev["decision"] in ("ALLOW", "IMPLICIT_DENY", "DENY")
    assert c.get("/api/sim/iam/evaluate?principal=user:ghost&action=s3:GetObject", headers=h).status_code == 404


def test_health_endpoints_are_public(client):
    for p in ("/health", "/api/health"):
        r = client.get(p)
        assert r.status_code == 200 and r.json()["database"] == "ok"
    assert "/api/sim/dashboard" in client.get("/openapi.json").json()["paths"]
