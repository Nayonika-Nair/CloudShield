"""Unit tests: every detection rule fires because of simulated state, and only then."""

from datetime import timedelta

import pytest

from app.engines import analysis, security
from app.simulator import lifecycle, scenarios, timeengine
from app.simulator.env import diff_resources, iso


def run(env, action, target=None, /, **params):
    return lifecycle.execute(env, action, target, params)


def keys(env):
    return {f["finding_key"] for f in security.evaluate(env)}


def rules(env):
    return {f["rule_id"] for f in security.evaluate(env)}


def by_rule(env, rule_id):
    return [f for f in security.evaluate(env) if f["rule_id"] == rule_id]


def test_clean_environment_produces_no_high_or_critical_findings(clean_env):
    assert security.score(security.evaluate(clean_env)) >= 90
    assert [f for f in security.evaluate(clean_env) if f["severity"] in ("HIGH", "CRITICAL")] == []


def test_every_finding_has_required_explainable_fields(base_env):
    findings = security.evaluate(base_env)
    assert findings
    for f in findings:
        for field in ("finding_key", "rule_id", "severity", "category", "resource_id", "title", "explanation", "evidence",
                      "impact", "recommendation", "detection_rule", "remediation", "severity_reason"):
            assert f[field] not in (None, "", {}), (f["finding_key"], field)
        assert f["rule_id"] in security.RULES and f["severity"] in security.SEVERITIES


def test_evaluation_is_pure_and_deterministic(base_env):
    fp = base_env.fingerprint()
    first = security.evaluate(base_env)
    assert security.evaluate(base_env) == first
    assert base_env.fingerprint() == fp


@pytest.mark.parametrize("scenario,expected", [
    ("public_s3_bucket", "S3-001"), ("open_ssh", "NET-001"), ("open_rdp", "NET-002"),
    ("overly_permissive_iam", "IAM-001"), ("missing_encryption", "ENC-001"), ("missing_backup", "BKP-001"),
    ("excessive_admin", "IAM-001"), ("risky_network", "NET-006"),
])
def test_scenarios_are_detected_by_ordinary_rules(clean_env, scenario, expected):
    assert expected not in rules(clean_env)
    scenarios.trigger(clean_env, scenario)
    assert expected in rules(clean_env)


def test_scenario_changes_state_and_never_inserts_findings(clean_env):
    before = clean_env.snapshot_resources()
    result = scenarios.trigger(clean_env, "open_ssh")
    diff = diff_resources(before, clean_env.resources)
    assert diff["created"] or diff["modified"]
    assert result["changes"] == diff
    assert not hasattr(security, "inject")  # no API for injecting findings exists


def test_suspicious_outbound_needs_time_then_is_detected_and_resolved_by_isolation(clean_env):
    result = scenarios.trigger(clean_env, "suspicious_outbound")
    assert result["needs_time"]
    assert "NET-008" not in rules(clean_env)  # no metrics yet
    timeengine.advance(clean_env, 3)
    (f,) = by_rule(clean_env, "NET-008")
    assert f["evidence"]["ratio"] >= clean_env.thresholds["traffic_spike_factor"]
    run(clean_env, "ec2.isolate", f["resource_id"])
    assert "NET-008" not in rules(clean_env)  # traffic condition remains in history; egress is now closed


def test_cost_spike_scenario_is_detected_after_time_advances(clean_env):
    scenarios.trigger(clean_env, "cost_spike")
    assert "COST-001" not in rules(clean_env)
    timeengine.advance(clean_env, 2)
    (f,) = by_rule(clean_env, "COST-001")
    assert f["evidence"]["increase_pct"] > 25 and f["evidence"]["top_contributors"]


def test_ssh_and_rdp_severity_is_raised_for_prod_resources(clean_env):
    inst = next(i for i in clean_env.of("ec2_instance") if i["tags"]["environment"] == "prod" and i["public_ip"] and i["os"] == "linux")
    scenarios.trigger(clean_env, "open_ssh", {"target": inst["id"]})
    f = next(f for f in by_rule(clean_env, "NET-001") if f["resource_id"] == inst["id"])
    assert f["severity"] == "CRITICAL" and "prod" in f["severity_reason"]
    inst["tags"]["environment"] = "dev"
    f = next(f for f in by_rule(clean_env, "NET-001") if f["resource_id"] == inst["id"])
    assert f["severity"] == "HIGH"


def test_all_ports_open_is_critical_and_replaces_individual_port_findings(clean_env):
    inst = next(i for i in clean_env.of("ec2_instance") if i["public_ip"] and i["state"] == "running")
    sg = run(clean_env, "sg.create", None, vpc_id=inst["vpc_id"], name="wide-open")["created"][0]
    run(clean_env, "sg.authorize_ingress", sg, protocol="-1", cidr="0.0.0.0/0")
    run(clean_env, "ec2.set_security_groups", inst["id"], sg_ids=inst["sg_ids"] + [sg])
    f = [x for x in security.evaluate(clean_env) if x["resource_id"] == inst["id"] and x["rule_id"].startswith("NET-")]
    assert [x["rule_id"] for x in f] == ["NET-004"] and f[0]["severity"] == "CRITICAL"


def test_world_open_rule_on_unreachable_resource_is_only_a_low_latent_finding(clean_env):
    private = next(i for i in clean_env.of("ec2_instance") if i["state"] == "running" and not i["public_ip"])
    sg = run(clean_env, "sg.create", None, vpc_id=private["vpc_id"], name="latent")["created"][0]
    run(clean_env, "sg.authorize_ingress", sg, protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0")
    run(clean_env, "ec2.set_security_groups", private["id"], sg_ids=private["sg_ids"] + [sg])
    assert "NET-001" not in rules(clean_env)
    (f,) = [x for x in by_rule(clean_env, "NET-005") if x["resource_id"] == private["id"]]
    assert f["severity"] == "LOW" and "unreachable" in f["title"].lower()


def test_public_database_port_is_critical_for_databases(clean_env):
    scenarios.trigger(clean_env, "risky_network")
    f = by_rule(clean_env, "NET-003")
    assert f and f[0]["severity"] == "CRITICAL" and "database" in f[0]["severity_reason"]


def test_public_bucket_requires_block_off_and_public_acl_or_policy(clean_env):
    bucket = clean_env.of("s3_bucket")[0]
    bucket["acl"] = "public-read"  # block public access still on -> not public
    assert "S3-001" not in rules(clean_env)
    bucket["block_public_access"] = False
    assert "S3-001" in rules(clean_env)
    bucket["acl"], bucket["policy_public"] = "private", True
    assert "S3-001" in rules(clean_env)
    bucket["policy_public"] = False
    assert "S3-001" not in rules(clean_env)


def test_confidential_public_bucket_is_critical(clean_env):
    bucket = next(b for b in clean_env.of("s3_bucket") if b["tags"].get("data_classification") == "confidential")
    run(clean_env, "s3.set_public_access_block", bucket["id"], block=False)
    run(clean_env, "s3.set_acl", bucket["id"], acl="public-read")
    f = next(f for f in by_rule(clean_env, "S3-001") if f["resource_id"] == bucket["id"])
    assert f["severity"] == "CRITICAL"


def test_encryption_rules_track_each_resource_type(clean_env):
    vol = next(v for v in clean_env.of("ebs_volume") if v["attached_to"])
    db, bucket = clean_env.of("rds_instance")[0], clean_env.of("s3_bucket")[0]
    vol["encrypted"], db["storage_encrypted"], bucket["encryption"] = False, False, "none"
    assert {"ENC-001", "ENC-002", "ENC-003"} <= rules(clean_env)
    run(clean_env, "ebs.enable_encryption", vol["id"])
    run(clean_env, "rds.enable_encryption", db["id"])
    run(clean_env, "s3.enable_encryption", bucket["id"])
    assert not ({"ENC-001", "ENC-002", "ENC-003"} & rules(clean_env))


def test_backup_rules(clean_env):
    db = clean_env.of("rds_instance")[0]
    run(clean_env, "rds.set_backup_retention", db["id"], days=0)
    assert any(f["resource_id"] == db["id"] for f in by_rule(clean_env, "BKP-001"))
    run(clean_env, "rds.set_backup_retention", db["id"], days=7)
    assert "BKP-001" not in rules(clean_env)


def test_stale_prod_volume_backup_is_detected_from_backup_age(clean_env):
    vol = next(v for v in clean_env.of("ebs_volume") if v["attached_to"] and v["tags"].get("environment") == "prod")
    run(clean_env, "ebs.set_backup_policy", vol["id"], policy="none")
    for s in [s for s in clean_env.of("snapshot") if s["volume_id"] == vol["id"]]:
        clean_env.remove(s["id"])
    (f,) = [x for x in by_rule(clean_env, "BKP-002") if x["resource_id"] == vol["id"]]
    assert f["severity"] == "HIGH" and f["evidence"]["newest_snapshot_age_days"] is None
    snap = run(clean_env, "snapshot.create", vol["id"])["created"][0]
    assert "BKP-002" not in {x["rule_id"] for x in security.evaluate(clean_env) if x["resource_id"] == vol["id"]}
    clean_env.get(snap)["created_at"] = iso(clean_env.sim_time - timedelta(days=20))
    (f,) = [x for x in by_rule(clean_env, "BKP-002") if x["resource_id"] == vol["id"]]
    assert f["severity"] == "MEDIUM" and f["evidence"]["newest_snapshot_age_days"] == 20


def test_backup_age_grows_with_simulated_time(clean_env):
    vol = next(v for v in clean_env.of("ebs_volume") if v["attached_to"] and v["tags"].get("environment") == "prod")
    run(clean_env, "ebs.set_backup_policy", vol["id"], policy="none")
    assert not any(f["resource_id"] == vol["id"] for f in by_rule(clean_env, "BKP-002"))
    timeengine.advance(clean_env, 9)
    assert any(f["resource_id"] == vol["id"] for f in by_rule(clean_env, "BKP-002"))


def test_iam_wildcard_admin_is_ignored_for_designated_admins_only(clean_env):
    assert "IAM-001" not in rules(clean_env)
    run(clean_env, "iam.attach_policy", "role:readonly-role", policy_id="policy:AdministratorAccess")
    assert {f["resource_id"] for f in by_rule(clean_env, "IAM-001")} == {"role:readonly-role"}


def test_missing_mfa_rule_follows_flag_and_configuration(clean_env):
    user = next(u for u in clean_env.of("iam_user") if u["console_access"] and u["kind"] == "developer")
    user["mfa_enabled"] = False
    assert user["id"] in {f["resource_id"] for f in by_rule(clean_env, "IAM-002")}
    clean_env.config["iam"]["mfa_required"] = False
    assert "IAM-002" not in rules(clean_env)
    clean_env.config["iam"]["mfa_required"] = True
    run(clean_env, "iam.enable_mfa", user["id"])
    assert "IAM-002" not in rules(clean_env)


def test_admin_without_mfa_is_high(clean_env):
    admin = next(u for u in clean_env.of("iam_user") if u["tags"].get("admin") == "designated")
    admin["mfa_enabled"] = False
    f = next(f for f in by_rule(clean_env, "IAM-002") if f["resource_id"] == admin["id"])
    assert f["severity"] == "HIGH"


def test_access_keys_become_stale_as_simulated_time_passes(clean_env):
    user = next(u for u in clean_env.of("iam_user") if u["access_keys"])
    user["access_keys"][0]["usage"] = "never"  # key is never used by the simulator's daily activity
    assert "IAM-003" not in rules(clean_env)
    timeengine.advance(clean_env, 65)
    assert user["id"] in {f["resource_id"] for f in by_rule(clean_env, "IAM-003")}
    run(clean_env, "iam.deactivate_access_key", user["id"], key_id=user["access_keys"][0]["id"])
    assert user["id"] not in {f["resource_id"] for f in by_rule(clean_env, "IAM-003")}


def test_risky_trust_severity_depends_on_principal(clean_env):
    role = clean_env.get("role:readonly-role")
    role["trust"].append({"type": "AWS", "value": "999988887777"})
    assert by_rule(clean_env, "IAM-004")[0]["severity"] == "HIGH"
    role["trust"].append({"type": "AWS", "value": "*"})
    assert {f["severity"] for f in by_rule(clean_env, "IAM-004")} == {"HIGH", "CRITICAL"}
    run(clean_env, "iam.restrict_trust", role["id"])
    assert "IAM-004" not in rules(clean_env)


def test_escalation_findings_are_grouped_by_target(clean_env):
    run(clean_env, "iam.attach_policy", "role:deploy-role", policy_id="policy:AdministratorAccess")
    findings = by_rule(clean_env, "IAM-005")
    assert [f["resource_id"] for f in findings] == ["role:deploy-role"]
    assert len(findings[0]["evidence"]["origins"]) >= 2


def test_excessive_admin_threshold_is_configurable(clean_env):
    assert "IAM-006" not in rules(clean_env)
    clean_env.config["iam"]["excessive_admin_threshold"] = 1
    assert "IAM-006" in rules(clean_env)


def test_findings_are_sorted_by_severity(base_env):
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sevs = [order.index(f["severity"]) for f in security.evaluate(base_env)]
    assert sevs == sorted(sevs)


def test_score_and_counts():
    fs = [{"severity": "CRITICAL"}, {"severity": "HIGH"}, {"severity": "MEDIUM"}, {"severity": "LOW"}]
    assert security.score(fs) == 100 - (8 + 4 + 2 + 1)
    assert security.severity_counts(fs) == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert security.score([{"severity": "CRITICAL"}] * 20) == 0
    assert security.bump("LOW") == "MEDIUM" and security.bump("CRITICAL") == "CRITICAL"


def test_every_rule_in_the_catalog_has_documented_logic():
    for rule_id, meta in security.RULES.items():
        assert meta["logic"] and meta["category"] and meta["severity"] in security.SEVERITIES, rule_id


def test_same_rules_evaluate_scenario_and_manual_changes(clean_base):
    via_scenario = clean_base.copy()
    inst_id = scenarios.trigger(via_scenario, "open_ssh")["targets"][0]
    manual = clean_base.copy()
    inst = manual.get(inst_id)
    sg = run(manual, "sg.create", None, vpc_id=inst["vpc_id"], name="manual-ssh")["created"][0]
    run(manual, "sg.authorize_ingress", sg, protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0")
    run(manual, "ec2.set_security_groups", inst_id, sg_ids=inst["sg_ids"] + [sg])
    pairs = lambda e: {(f["rule_id"], f["resource_id"]) for f in security.evaluate(e)}  # noqa: E731
    assert ("NET-001", inst_id) in pairs(via_scenario)
    assert pairs(via_scenario) == pairs(manual)


def test_full_analysis_bundle_is_consistent(base_env):
    a = analysis.analyze(base_env)
    assert a["security_score"] == security.score(a["findings"])
    assert sum(a["severity_counts"].values()) == len(a["findings"])
    assert a["potential_savings"] <= sum(r["estimated_monthly_savings"] for r in a["recommendations"]) + 0.01
