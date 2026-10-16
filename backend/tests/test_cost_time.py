"""Unit tests: billing arithmetic, simulated time, metrics, anomaly detection, recommendations."""

from datetime import timedelta

import pytest

from app.engines import cost, optimization
from app.simulator import billing, lifecycle, scenarios, timeengine
from app.simulator.env import SimError, iso


def run(env, action, target=None, /, **params):
    return lifecycle.execute(env, action, target, params)


def rec_by(env, rule, **match):
    recs = [r for r in optimization.recommend(env) if r["rule_id"] == rule]
    return [r for r in recs if all(r.get(k) == v for k, v in match.items())]


# ---------------------------------------------------------------------- billing
def test_ec2_daily_cost_is_hourly_price_times_24(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running")
    price = env.pricing["ec2_hourly"][inst["instance_type"]]
    assert billing.fixed_daily(env, inst)["EC2"] == pytest.approx(price * 24)
    inst["state"] = "stopped"
    assert billing.fixed_daily(env, inst) == {}


def test_storage_charges_use_gb_month_price_over_30_days(env):
    vol = next(v for v in env.of("ebs_volume"))
    expected = vol["size_gb"] * env.pricing["ebs_gb_month"][vol["volume_type"]] / 30
    assert billing.fixed_daily(env, vol)["EBS"] == pytest.approx(expected)
    manual = next(s for s in env.of("snapshot") if s["managed_by"] == "manual")
    assert billing.fixed_daily(env, manual)["Snapshots"] == pytest.approx(manual["size_gb"] * env.pricing["snapshot_gb_month"] / 30)
    managed = next(s for s in env.of("snapshot") if s["managed_by"] == "backup_policy")
    fraction = env.pricing["managed_snapshot_billed_fraction"]
    assert billing.fixed_daily(env, managed)["Snapshots"] == pytest.approx(
        managed["size_gb"] * env.pricing["snapshot_gb_month"] * fraction / 30)
    bucket = env.of("s3_bucket")[0]
    assert billing.fixed_daily(env, bucket)["S3"] == pytest.approx(bucket["size_gb"] * env.pricing["s3_gb_month"] / 30)


def test_rds_cost_doubles_compute_for_multi_az(env):
    db = env.of("rds_instance")[0]
    db["multi_az"] = False
    single = billing.fixed_daily(env, db)["RDS"]
    db["multi_az"] = True
    multi = billing.fixed_daily(env, db)["RDS"]
    compute = env.pricing["rds_hourly"][db["instance_class"]] * 24
    assert multi - single == pytest.approx(compute)


def test_elastic_ip_is_free_when_attached_to_running_instance_and_billed_when_idle(env):
    attached = next(e for e in env.of("elastic_ip") if e["instance_id"])
    idle = next(e for e in env.of("elastic_ip") if not e["instance_id"])
    assert billing.fixed_daily(env, attached) == {}
    assert billing.fixed_daily(env, idle)["Elastic IP"] == pytest.approx(env.pricing["eip_idle_hourly"] * 24)
    env.get(attached["instance_id"])["state"] = "stopped"
    assert billing.fixed_daily(env, attached)["Elastic IP"] > 0


def test_pricing_changes_flow_through_to_run_rate(env):
    before = cost.monthly_run_rate(env)["total"]
    env.pricing["ec2_hourly"] = {k: v * 2 for k, v in env.pricing["ec2_hourly"].items()}
    after = cost.monthly_run_rate(env)
    assert after["by_service"]["EC2"] == pytest.approx(cost.monthly_run_rate(env)["by_service"]["EC2"])
    assert after["total"] > before


def test_run_rate_breakdown_sums_to_total_and_matches_resource_costs(env):
    rate = cost.monthly_run_rate(env)
    assert sum(rate["by_service"].values()) == pytest.approx(rate["total"], abs=0.05)
    assert sum(rate["by_resource"].values()) == pytest.approx(rate["total"], abs=0.5)


def test_stopping_an_instance_lowers_run_rate_by_its_compute_cost(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running" and not i["public_ip"])
    before = cost.monthly_run_rate(env)["total"]
    compute = billing.ec2_hourly(env, inst["instance_type"]) * 24 * 30
    dt = cost.resource_monthly(env, inst) - compute
    run(env, "ec2.stop", inst["id"])
    assert cost.monthly_run_rate(env)["total"] == pytest.approx(before - compute - dt, abs=0.05)


def test_data_transfer_cost_uses_current_configuration(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running" and i["public_ip"])
    base = cost.resource_daily_run_rate(env, inst)["Data Transfer"]
    assert base == pytest.approx(billing.data_transfer_daily(env, inst["net_out_gb_base"]))
    inst["traffic_multiplier"] = 10
    assert cost.resource_daily_run_rate(env, inst)["Data Transfer"] == pytest.approx(base * 10)
    run(env, "ec2.isolate", inst["id"])  # no route out: the anomalous multiplier no longer applies
    assert cost.resource_daily_run_rate(env, inst)["Data Transfer"] == pytest.approx(base)


# ------------------------------------------------------------------------- time
def test_advance_moves_time_and_accrues_one_cost_day_per_step(env):
    start, days = env.sim_time, len(env.daily_costs)
    out = timeengine.advance(env, 3)
    assert (env.sim_time - start).days == 3 and len(env.daily_costs) == days + 3
    assert out["days"] == 3 and out["cost_accrued"] > 0


def test_advancing_in_one_step_or_many_gives_identical_state(base_env):
    a, b = base_env.copy(), base_env.copy()
    timeengine.advance(a, 5)
    for _ in range(5):
        timeengine.advance(b, 1)
    assert a.fingerprint() == b.fingerprint()


def test_same_state_and_seed_give_same_future(base_env):
    a, b = base_env.copy(), base_env.copy()
    timeengine.advance(a, 7)
    timeengine.advance(b, 7)
    assert a.metrics == b.metrics and a.daily_costs == b.daily_costs


@pytest.mark.parametrize("days", [0, -1, 91, 1.5, "3", None, True])
def test_invalid_advance_values_are_rejected(env, days):
    with pytest.raises(SimError) as exc:
        timeengine.advance(env, days)
    assert exc.value.code == "invalid_parameter" and exc.value.status == 422


def test_metrics_are_stored_per_resource_with_dates(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running")
    timeengine.advance(env, 2)
    series = env.metrics[inst["id"]]
    assert set(series) == {"cpu", "mem", "net_in_gb", "net_out_gb"}
    assert max(series["cpu"]) == (env.today - timedelta(days=1)).isoformat()
    assert all(0 < v <= 100 for v in series["cpu"].values())


def test_stopped_instances_report_no_metrics_and_cost_nothing_for_compute(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running" and not i["public_ip"])
    run(env, "ec2.stop", inst["id"])
    timeengine.advance(env, 1)
    day = (env.today - timedelta(days=1)).isoformat()
    assert day not in env.metrics[inst["id"]]["cpu"]
    assert "EC2" not in env.daily_costs[day].get(inst["id"], {})


def test_resize_scales_cpu_inversely_with_vcpus(env):
    from app.simulator.catalog import EC2_FAMILIES, EC2_TYPES
    yesterday = lambda: (env.today - timedelta(days=1)).isoformat()  # noqa: E731
    timeengine.advance(env, 1)
    for inst in env.of("ec2_instance"):
        if inst["state"] != "running" or inst["public_ip"] or EC2_TYPES[inst["instance_type"]][0] < 4:
            continue
        target = EC2_FAMILIES[inst["instance_type"].split(".")[0]][0]
        ratio = EC2_TYPES[inst["instance_type"]][0] / EC2_TYPES[target][0]
        before = env.metrics[inst["id"]]["cpu"][yesterday()]
        if before * ratio < 80:
            break
    else:
        pytest.fail("seed has no suitable instance")
    run(env, "ec2.stop", inst["id"])
    run(env, "ec2.change_type", inst["id"], instance_type=target)
    run(env, "ec2.start", inst["id"])
    timeengine.advance(env, 1)
    after = env.metrics[inst["id"]]["cpu"][yesterday()]
    assert after == pytest.approx(before * ratio, rel=0.35)  # same workload on fewer vCPUs, daily noise aside


def test_policy_backups_create_and_expire_snapshots_over_time(env):
    vol = next(v for v in env.of("ebs_volume") if v["backup_policy"] == "daily" and v["attached_to"])
    count = lambda: len([s for s in env.of("snapshot") if s["volume_id"] == vol["id"] and s["managed_by"] == "backup_policy"])  # noqa: E731
    timeengine.advance(env, 3)
    assert count() >= 3
    timeengine.advance(env, 30)
    assert count() <= 16  # daily policy keeps ~14 days


def test_buckets_grow_and_keys_record_usage_as_time_passes(env):
    bucket = env.of("s3_bucket")[0]
    size = bucket["size_gb"]
    timeengine.advance(env, 10)
    assert bucket["size_gb"] == pytest.approx(size + 10 * bucket["growth_gb_per_day"], abs=0.2)
    user = next(u for u in env.of("iam_user") if any(k["usage"] == "active" for k in u["access_keys"]))
    key = next(k for k in user["access_keys"] if k["usage"] == "active")
    assert key["last_used"] == iso(env.sim_time - timedelta(days=1))


def test_rds_backup_timestamp_follows_time_when_enabled(env):
    db = next(d for d in env.of("rds_instance") if d["backup_retention_days"] > 0)
    timeengine.advance(env, 2)
    assert db["last_backup_at"].startswith((env.sim_time - timedelta(days=1)).date().isoformat())


# ---------------------------------------------------------------------- anomalies
def test_steady_state_has_no_cost_anomaly(base_env):
    assert cost.detect_anomalies(base_env) == []
    env = base_env.copy()
    timeengine.advance(env, 10)
    assert cost.detect_anomalies(env) == []


def test_cost_spike_is_flagged_with_contributors_and_baseline(env):
    scenarios.trigger(env, "cost_spike")
    timeengine.advance(env, 2)
    anomalies = [a for a in cost.detect_anomalies(env) if a["scope"] == "total"]
    assert anomalies
    a = anomalies[0]
    assert a["zscore"] >= env.thresholds["anomaly_zscore"] and a["increase_pct"] >= env.thresholds["anomaly_min_increase_pct"]
    assert a["active"] and len(a["top_contributors"]) >= 1
    assert a["value"] > a["baseline_mean"]


def test_small_changes_below_floor_are_not_anomalies(env):
    run(env, "ebs.create", None, size_gb=20, az="us-east-1a")
    timeengine.advance(env, 3)
    assert cost.detect_anomalies(env) == []


def test_anomaly_threshold_is_configurable(env):
    scenarios.trigger(env, "cost_spike", {"count": 1})
    timeengine.advance(env, 2)
    env.thresholds["anomaly_min_increase_pct"] = 500
    assert [a for a in cost.detect_anomalies(env) if a["scope"] == "total"] == []


def test_history_and_summary_shapes(base_env):
    hist = cost.history(base_env, 7)
    assert len(hist) == 7 and all(h["total"] == pytest.approx(sum(h["by_service"].values()), abs=0.01) for h in hist)
    s = cost.summary(base_env)
    assert s["currency"] == "USD" and "Simulated prices" in s["pricing_note"] and s["top_resources"]


# ------------------------------------------------------------- recommendations
def test_idle_instance_recommendation_uses_metrics_and_full_compute_saving(env):
    inst = next(i for i in env.of("ec2_instance") if i["profile"] == "idle" and i["state"] == "running")
    (rec,) = rec_by(env, "OPT-001", resource_id=inst["id"])
    compute = billing.ec2_hourly(env, inst["instance_type"]) * 24 * 30
    assert rec["estimated_monthly_savings"] == pytest.approx(compute, abs=0.01)
    assert rec["evidence"]["cpu_avg_pct"] < env.thresholds["idle_cpu_avg_pct"]
    assert rec["assumptions"] and rec["risk"] and rec["recommended_action"]
    assert rec["remediation"]["operations"][0]["action"] == "ec2.stop"


def test_busy_instance_is_not_recommended_for_stop_or_resize(env):
    busy = next(i for i in env.of("ec2_instance") if i["profile"] == "busy" and i["state"] == "running")
    assert not any(r["resource_id"] == busy["id"] for r in optimization.recommend(env) if r["rule_id"] in ("OPT-001", "OPT-002"))


def test_rightsizing_projects_cpu_and_never_overshoots_headroom(env):
    recs = [r for r in optimization.recommend(env) if r["rule_id"] == "OPT-002"]
    assert recs
    for r in recs:
        assert r["evidence"]["projected_cpu_avg_pct"] <= 60 and r["evidence"]["projected_cpu_max_pct"] <= 80
        assert [o["action"] for o in r["remediation"]["operations"]] == ["ec2.stop", "ec2.change_type", "ec2.start"]
        inst = env.get(r["resource_id"])
        saving = (billing.ec2_hourly(env, inst["instance_type"]) - billing.ec2_hourly(env, r["evidence"]["proposed_type"])) * 24 * 30
        assert r["estimated_monthly_savings"] == pytest.approx(saving, abs=0.01)


def test_unattached_volume_without_snapshot_takes_safety_snapshot_and_reduces_savings(env):
    vol = next(v for v in env.of("ebs_volume") if v["state"] == "available")
    for s in [s for s in env.of("snapshot") if s["volume_id"] == vol["id"]]:
        env.remove(s["id"])
    (rec,) = rec_by(env, "OPT-003", resource_id=vol["id"])
    monthly = billing.fixed_daily(env, vol)["EBS"] * 30
    assert rec["remediation"]["operations"][0]["action"] == "snapshot.create"
    assert rec["estimated_monthly_savings"] == pytest.approx(monthly - vol["size_gb"] * env.pricing["snapshot_gb_month"], abs=0.01)


def test_old_snapshot_rule_requires_age_and_a_newer_copy_or_missing_source(env):
    old = [r for r in optimization.recommend(env) if r["rule_id"] == "OPT-004"]
    assert old
    for r in old:
        assert r["evidence"]["age_days"] > env.thresholds["old_snapshot_days"]
        assert r["evidence"]["newer_snapshots"] > 0 or not r["evidence"]["source_exists"]
    env.thresholds["old_snapshot_days"] = 700
    assert not [r for r in optimization.recommend(env) if r["rule_id"] == "OPT-004"]


def test_deleting_a_volume_leaves_orphaned_snapshots_that_become_reclaimable(env):
    vol = run(env, "ebs.create", None, size_gb=40, az="us-east-1a")["created"][0]
    snap = run(env, "snapshot.create", vol)["created"][0]
    env.get(snap)["created_at"] = iso(env.sim_time - timedelta(days=200))
    assert not rec_by(env, "OPT-004", resource_id=snap)  # sole backup of an existing volume is kept
    run(env, "ebs.delete", vol)
    (rec,) = rec_by(env, "OPT-004", resource_id=snap)
    assert rec["evidence"]["source_exists"] is False


def test_unused_eip_and_idle_load_balancer_recommendations(env):
    idle_ips = {e["id"] for e in env.of("elastic_ip") if not e["instance_id"]}
    assert idle_ips <= {r["resource_id"] for r in optimization.recommend(env) if r["rule_id"] == "OPT-005"}
    (r,) = [r for r in optimization.recommend(env) if r["rule_id"] == "OPT-005"][:1]
    assert r["estimated_monthly_savings"] == pytest.approx(env.pricing["eip_idle_hourly"] * 24 * 30, abs=0.01)
    empty = [lb for lb in env.of("load_balancer") if not lb["targets"]]
    assert empty and empty[0]["id"] in {r["resource_id"] for r in optimization.recommend(env) if r["rule_id"] == "OPT-008"}


def test_overprovisioned_database_downsize_is_cheaper_and_safe(env):
    recs = [r for r in optimization.recommend(env) if r["rule_id"] == "OPT-006"]
    for r in recs:
        db = env.get(r["resource_id"])
        assert billing.rds_hourly(env, r["evidence"]["proposed_class"]) < billing.rds_hourly(env, db["instance_class"])
        assert r["estimated_monthly_savings"] > 0


def test_long_stopped_instance_is_flagged(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "stopped")
    inst["stopped_at"] = iso(env.sim_time - timedelta(days=45))
    (rec,) = rec_by(env, "OPT-007", resource_id=inst["id"])
    assert rec["evidence"]["stopped_days"] == 45


def test_total_savings_does_not_double_count_overlapping_advice():
    recs = [{"resource_id": "a", "estimated_monthly_savings": 10.0}, {"resource_id": "a", "estimated_monthly_savings": 25.0},
            {"resource_id": "b", "estimated_monthly_savings": 5.0}]
    assert optimization.total_savings(recs) == 30.0


def test_priority_buckets_follow_savings():
    assert optimization._priority(150) == "HIGH" and optimization._priority(50) == "MEDIUM" and optimization._priority(5) == "LOW"


def test_recommendation_requires_enough_metric_history(clean_env):
    env = clean_env.copy()
    env.metrics.clear()
    assert not [r for r in optimization.recommend(env) if r["rule_id"] in ("OPT-001", "OPT-002", "OPT-006")]
