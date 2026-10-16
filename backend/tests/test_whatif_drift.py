"""Unit tests: what-if isolation, remediation engine, drift, compliance and scenario reversal."""

import pytest

from app.engines import analysis, compliance, drift, remediation, security, whatif
from app.simulator import lifecycle, scenarios, timeengine
from app.simulator.env import SimError


def run(env, action, target=None, /, **params):
    return lifecycle.execute(env, action, target, params)


def change(action, target=None, **params):
    return {"action": action, "target_id": target, "params": params}


def idle_instance(env):
    return next(i for i in env.of("ec2_instance") if i["profile"] == "idle" and i["state"] == "running")


# -------------------------------------------------------------------- what-if
def test_whatif_never_mutates_the_baseline(env):
    fp = env.fingerprint()
    inst = idle_instance(env)
    result = whatif.simulate(env, [change("ec2.stop", inst["id"])])
    assert result["baseline_unchanged"] is True and env.fingerprint() == fp
    assert env.get(inst["id"])["state"] == "running"


def test_whatif_discarding_leaves_baseline_identical_after_many_runs(env):
    fp = env.fingerprint()
    for inst in env.of("ec2_instance")[:4]:
        try:
            whatif.simulate(env, [change("ec2.stop", inst["id"])])
        except SimError:
            pass
    assert env.fingerprint() == fp


def test_whatif_cost_matches_actually_applying_the_change(env):
    inst = idle_instance(env)
    result = whatif.simulate(env, [change("ec2.stop", inst["id"])])
    run(env, "ec2.stop", inst["id"])
    actual = analysis.analyze(env)["monthly_run_rate"]
    assert result["cost"]["hypothetical_monthly"] == pytest.approx(actual)
    assert result["cost"]["estimated_monthly_savings"] > 0 and result["cost"]["delta_monthly"] < 0
    assert result["cost"]["basis"].startswith("ESTIMATED")


def test_whatif_reports_security_improvement_and_exposure_change(clean_env):
    env = clean_env
    scenarios.trigger(env, "open_ssh")
    base = analysis.analyze(env)
    finding = next(f for f in base["findings"] if f["rule_id"] == "NET-001")
    exposed, sg, rule = finding["resource_id"], finding["evidence"]["security_group"], finding["evidence"]["rule"]
    result = whatif.simulate(env, [change("sg.revoke_ingress", sg, protocol=rule["protocol"], from_port=rule["from_port"],
                                           to_port=rule["to_port"], cidr=rule["cidr"])])
    sec = result["security"]
    assert sec["score_after"] > sec["score_before"] and sec["score_delta"] == sec["score_after"] - sec["score_before"]
    assert [f["rule_id"] for f in sec["findings_resolved"]] == ["NET-001"]
    assert exposed in sec["exposed_before"] and exposed not in sec["exposed_after"]
    assert any(c["id"] == "no_internet_admin_ports" and c["delta"] > 0 for c in result["compliance"])


def test_whatif_can_introduce_new_findings(clean_env):
    bucket = clean_env.of("s3_bucket")[0]
    result = whatif.simulate(clean_env, [change("s3.set_public_access_block", bucket["id"], block=False),
                                         change("s3.set_acl", bucket["id"], acl="public-read")])
    assert [f["rule_id"] for f in result["security"]["findings_introduced"]] == ["S3-001"]
    assert result["security"]["score_delta"] < 0
    assert not clean_env.get(bucket["id"])["acl"] == "public-read"


def test_whatif_flags_downtime_and_dependents(env):
    lb = next(lb for lb in env.of("load_balancer") if lb["targets"])
    target = lb["targets"][0]
    result = whatif.simulate(env, [change("ec2.stop", target)])
    (d,) = result["operational"]["downtime"]
    assert d["resource_id"] == target and lb["id"] in d["dependents"] and result["operational"]["requires_restart"]


def test_whatif_resize_sequence_shows_config_diff_and_savings(env):
    from app.engines import optimization
    rec = next(r for r in optimization.recommend(env) if r["rule_id"] == "OPT-002")
    result = whatif.simulate(env, rec["remediation"]["operations"])
    diff = result["resource_diff"]["modified"][rec["resource_id"]]
    assert diff["instance_type"]["after"] == rec["evidence"]["proposed_type"]
    assert result["cost"]["estimated_monthly_savings"] == pytest.approx(rec["estimated_monthly_savings"], abs=0.5)


def test_whatif_with_invalid_step_fails_atomically_without_side_effects(env):
    fp = env.fingerprint()
    inst = idle_instance(env)
    with pytest.raises(SimError) as exc:
        whatif.simulate(env, [change("ec2.stop", inst["id"]), change("ec2.stop", inst["id"])])
    assert "Step 2" in exc.value.message and env.fingerprint() == fp


def test_whatif_input_limits(env):
    with pytest.raises(SimError):
        whatif.simulate(env, [])
    with pytest.raises(SimError):
        whatif.simulate(env, [change("tags.set", env.of("vpc")[0]["id"], tags={"a": "b"})] * 21)
    with pytest.raises(SimError):
        whatif.simulate(env, [{"target_id": "x"}])


def test_whatif_states_its_limitations(env):
    result = whatif.simulate(env, [change("tags.set", env.of("vpc")[0]["id"], tags={"k": "v"})])
    assert len(result["limitations"]) >= 3


# ---------------------------------------------------------------- remediation
def test_run_operations_is_atomic(env):
    inst = idle_instance(env)
    fp = env.fingerprint()
    ops = [change("ec2.stop", inst["id"]), change("ec2.change_type", inst["id"], instance_type="t3.micro"),
           change("ec2.change_type", inst["id"], instance_type="t3.micro")]
    with pytest.raises(SimError):
        remediation.run_operations(env, ops)
    assert env.fingerprint() == fp and env.get(inst["id"])["state"] == "running"


def test_plan_hash_is_stable_and_sensitive_to_changes(env):
    ops = [change("ec2.stop", "i-1")]
    assert remediation.plan_hash(ops) == remediation.plan_hash([dict(ops[0], description="ignored")])
    assert remediation.plan_hash(ops) != remediation.plan_hash([change("ec2.stop", "i-2")])


def test_every_supported_security_remediation_resolves_its_finding(base_env):
    env = base_env.copy()
    findings = [f for f in security.evaluate(env) if f["remediation"]["supported"]]
    assert len(findings) >= 10
    for f in findings:
        trial = env.copy()
        remediation.run_operations(trial, f["remediation"]["operations"])
        assert f["finding_key"] not in {x["finding_key"] for x in security.evaluate(trial)}, f["finding_key"]


def test_every_supported_cost_recommendation_removes_itself_and_saves_money(base_env):
    from app.engines import optimization
    env = base_env.copy()
    recs = [r for r in optimization.recommend(env) if r["remediation"]["supported"]]
    assert len(recs) >= 5
    baseline = analysis.analyze(env)["monthly_run_rate"]
    for r in recs:
        trial = env.copy()
        remediation.run_operations(trial, r["remediation"]["operations"])
        assert r["rec_key"] not in {x["rec_key"] for x in optimization.recommend(trial)}, r["rec_key"]
        assert analysis.analyze(trial)["monthly_run_rate"] < baseline, r["rec_key"]


def test_manual_only_findings_have_no_automated_plan(clean_env):
    env = clean_env
    run(env, "iam.attach_policy", "role:readonly-role", policy_id="policy:AdministratorAccess")
    run(env, "iam.attach_policy", "role:ec2-app-role", policy_id="policy:AdministratorAccess")
    f = next(x for x in security.evaluate(env) if x["rule_id"] == "IAM-006")
    assert f["remediation"]["supported"] is False and f["remediation"]["operations"] == []
    assert remediation.build_plan(f)["plan_hash"] is None


# ------------------------------------------------------------------------ drift
def test_fresh_environment_has_no_drift(env):
    d = drift.detect(env)
    assert d["has_baseline"] and d["items"] == [] and d["summary"]["total"] == 0


def test_time_passing_does_not_register_as_drift(env):
    timeengine.advance(env, 5)
    assert drift.detect(env)["summary"]["total"] == 0  # usage, policy snapshots and last_used are not configuration


def test_changes_are_reported_as_drift_with_field_level_detail(clean_env):
    env = clean_env
    bucket = env.of("s3_bucket")[0]
    run(env, "s3.set_public_access_block", bucket["id"], block=False)
    run(env, "tags.set", env.of("vpc")[0]["id"], tags={"note": "x"})
    run(env, "ec2.terminate", env.of("ec2_instance")[0]["id"])
    created = run(env, "ebs.create", None, size_gb=10, az="us-east-1a")["created"][0]
    d = drift.detect(env)
    by_id = {i["resource_id"]: i for i in d["items"]}
    assert by_id[bucket["id"]]["security_relevant"] and by_id[bucket["id"]]["fields"][0]["field"] == "block_public_access"
    assert not by_id[env.of("vpc")[0]["id"]]["security_relevant"]
    assert by_id[created]["change"] == "created"
    assert d["summary"]["created"] >= 1 and d["summary"]["modified"] >= 2 and d["kind"] == "drift"
    assert d["items"][0]["security_relevant"]  # security-relevant drift is listed first


def test_drift_is_not_a_finding_and_resolves_when_reverted(clean_env):
    env = clean_env
    bucket = env.of("s3_bucket")[0]
    run(env, "s3.set_public_access_block", bucket["id"], block=False)
    assert drift.detect(env)["summary"]["total"] == 1 and "S3-001" not in {f["rule_id"] for f in security.evaluate(env)}
    run(env, "s3.set_public_access_block", bucket["id"], block=True)
    assert drift.detect(env)["summary"]["total"] == 0


def test_new_baseline_resets_drift(clean_env):
    env = clean_env
    run(env, "tags.set", env.of("vpc")[0]["id"], tags={"note": "x"})
    assert drift.detect(env)["summary"]["total"] == 1
    env.baseline = env.snapshot_resources()
    assert drift.detect(env)["summary"]["total"] == 0


def test_drift_without_baseline(env):
    env.baseline = None
    assert drift.detect(env)["has_baseline"] is False


# ------------------------------------------------------------------- compliance
def test_compliance_percentages_and_status(env):
    checks = {c["id"]: c for c in compliance.checks(env)}
    assert set(checks) == {"encryption_at_rest", "backup_coverage", "mfa_console_users", "no_public_buckets",
                           "no_internet_admin_ports", "required_tags", "no_unapproved_admins"}
    vols = env.of("ebs_volume")
    vol = vols[0]
    was = vol["encrypted"]
    vol["encrypted"] = False
    after = {c["id"]: c for c in compliance.checks(env)}["encryption_at_rest"]
    assert after["compliant"] <= checks["encryption_at_rest"]["compliant"] and after["status"] == "FAIL"
    vol["encrypted"] = was


def test_clean_environment_is_compliant(clean_env):
    assert all(c["status"] == "PASS" for c in compliance.checks(clean_env))


# ----------------------------------------------------------------- scenario revert
@pytest.mark.parametrize("name", [n for n in scenarios.SCENARIOS if n not in ("suspicious_outbound",)])
def test_scenario_revert_restores_exact_resource_state(clean_env, name):
    env = clean_env
    before = env.snapshot_resources()
    result = scenarios.trigger(env, name)
    assert env.resources != before
    scenarios.revert(env, result["before"], result["changes"])
    from app.simulator.env import diff_resources, diff_is_empty
    assert diff_is_empty(diff_resources(before, env.resources))


def test_unknown_scenario_and_missing_target_errors(clean_env):
    with pytest.raises(SimError) as exc:
        scenarios.trigger(clean_env, "meteor_strike")
    assert exc.value.status == 404
    scenarios.trigger(clean_env, "excessive_admin", {"count": 99})
    with pytest.raises(SimError) as exc2:
        scenarios.trigger(clean_env, "excessive_admin")
    assert exc2.value.code == "no_target"


def test_scenario_catalog_documents_expected_detection_rules():
    for item in scenarios.catalog():
        assert item["detected_by"] and item["description"]
        assert all(r in security.RULES for r in item["detected_by"])
