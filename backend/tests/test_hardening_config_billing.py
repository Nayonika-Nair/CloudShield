"""Hardening tests added after the first mutation-testing round: exact boundaries, defaults and arithmetic.

Each test pins behaviour that earlier tests only exercised loosely (the surviving mutants showed the gaps).
"""

import copy
from datetime import date

import pytest
from pydantic import ValidationError

from app.engines import remediation
from app.simulator import billing
from app.simulator.config import (
    Counts, IamSettings, Pricing, Quotas, SecuritySettings, SimConfig, Thresholds, TimeSettings, Utilization, preset_config,
)
from app.simulator.env import SimError


# ------------------------------------------------------------------ defaults
def test_documented_defaults_are_pinned():
    d = SimConfig().to_dict()
    assert d["counts"] == {"vpcs": 2, "subnets_per_vpc": 4, "ec2_instances": 14, "unattached_volumes": 3, "snapshots": 8, "s3_buckets": 6,
                           "rds_instances": 3, "elastic_ips": 4, "load_balancers": 2, "iam_users": 6, "iam_roles": 4}
    assert d["thresholds"] == {"idle_cpu_avg_pct": 5.0, "idle_cpu_max_pct": 15.0, "underutilized_cpu_avg_pct": 20.0,
                               "underutilized_cpu_max_pct": 40.0, "metric_window_days": 14, "old_snapshot_days": 90,
                               "backup_max_age_days": 7, "anomaly_zscore": 3.0, "anomaly_min_increase_pct": 25.0, "traffic_spike_factor": 8.0}
    assert d["quotas"] == {"ec2_instances": 100, "ebs_volumes": 300, "s3_buckets": 100, "rds_instances": 40, "elastic_ips": 10, "vpcs": 5,
                           "security_groups": 200, "iam_users": 100, "load_balancers": 20, "snapshots": 600}
    assert d["iam"] == {"admin_users": 1, "mfa_required": True, "access_key_max_age_days": 90, "excessive_admin_threshold": 2}
    assert d["time"] == {"start_date": "2026-10-01", "history_days": 30, "auto_advance": False, "auto_advance_interval_seconds": 0, "days_per_tick": 1}
    assert d["seed"] == 42 and d["region"] == "us-east-1" and d["preset"] == "typical"
    assert d["utilization"] == {"idle": 0.15, "underutilized": 0.2, "normal": 0.5, "busy": 0.15}
    assert d["security"]["public_s3_pct"] == 0.15 and d["security"]["stopped_pct"] == 0.08 and d["security"]["untagged_pct"] == 0.1
    assert d["pricing"]["s3_gb_month"] == 0.023 and d["pricing"]["data_transfer_out_gb"] == 0.09


# ----------------------------------------------------------- numeric bounds
def _bounds(model):
    out = []
    for name, info in model.model_fields.items():
        ge = next((m.ge for m in info.metadata if hasattr(m, "ge")), None)
        le = next((m.le for m in info.metadata if hasattr(m, "le")), None)
        if ge is not None or le is not None:
            out.append((name, ge, le, info.annotation))
    return out


SECTIONS = [("counts", Counts), ("thresholds", Thresholds), ("quotas", Quotas), ("iam", IamSettings), ("time", TimeSettings), ("security", SecuritySettings)]
HIGH_QUOTAS = {k: getattr(Quotas.model_fields[k], "metadata")[-1].le for k in Quotas.model_fields}


def _cfg(section, field, value):
    data = {section: {field: value}}
    if section == "counts":                      # counts are capped by quotas; lift the quotas so only the field under test can fail
        data["quotas"] = dict(HIGH_QUOTAS)
    if section == "quotas":                      # the default counts must still fit the quota under test
        data["counts"] = {"ec2_instances": 0, "s3_buckets": 0, "rds_instances": 0, "elastic_ips": 0, "vpcs": 1, "iam_users": 1, "load_balancers": 0}
    return SimConfig.model_validate(data)


@pytest.mark.parametrize("section,model", SECTIONS)
def test_every_numeric_bound_is_enforced_exactly(section, model):
    checked = 0
    for name, ge, le, ann in _bounds(model):
        if section == "counts" and name == "subnets_per_vpc":
            continue                              # also constrained to even numbers; covered separately
        step = 1 if ann is int else 0.001
        if ge is not None:
            if not (section == "quotas" and name == "iam_users"):      # a zero IAM-user quota can never satisfy counts.iam_users >= 1
                _cfg(section, name, ge)                                # lower bound accepted
            with pytest.raises(ValidationError):
                _cfg(section, name, ge - step)                         # just below rejected
            checked += 1
        if le is not None:
            _cfg(section, name, le)
            with pytest.raises(ValidationError):
                _cfg(section, name, le + step)
            checked += 1
    assert checked >= 6


def test_pricing_scalar_bounds_and_quota_bounds():
    SimConfig.model_validate({"pricing": {"s3_gb_month": 0}})
    with pytest.raises(ValidationError):
        SimConfig.model_validate({"pricing": {"s3_gb_month": -0.001}})
    SimConfig.model_validate({"pricing": {"managed_snapshot_billed_fraction": 1}})
    with pytest.raises(ValidationError):
        SimConfig.model_validate({"pricing": {"managed_snapshot_billed_fraction": 1.001}})


def test_top_level_field_bounds():
    SimConfig.model_validate({"seed": 0})
    SimConfig.model_validate({"seed": 2**31 - 1})
    for bad in (-1, 2**31):
        with pytest.raises(ValidationError):
            SimConfig.model_validate({"seed": bad})
    SimConfig.model_validate({"name": "x"})
    SimConfig.model_validate({"name": "n" * 64})
    for bad in ("", "n" * 65):
        with pytest.raises(ValidationError):
            SimConfig.model_validate({"name": bad})
    SimConfig.model_validate({"naming": {"org": "ab"}})
    SimConfig.model_validate({"naming": {"org": "a" * 16}})
    for bad in ("a", "a" * 17):
        with pytest.raises(ValidationError):
            SimConfig.model_validate({"naming": {"org": bad}})
    SimConfig.model_validate({"account_name": "a" * 64})
    with pytest.raises(ValidationError):
        SimConfig.model_validate({"account_name": "a" * 65})
    SimConfig.model_validate({"time": {"start_date": "2030-01-31"}})


def test_odd_subnet_count_rejected_even_accepted():
    for n in (2, 4, 6, 8):
        assert SimConfig.model_validate({"counts": {"subnets_per_vpc": n}}).counts.subnets_per_vpc == n
    for n in (3, 5, 7):
        with pytest.raises(ValidationError):
            SimConfig.model_validate({"counts": {"subnets_per_vpc": n}})


def test_tag_environment_weight_rules():
    SimConfig.model_validate({"tags": {"environments": {"a": 0, "b": 1}}})                 # a zero weight is allowed
    SimConfig.model_validate({"tags": {"environments": {"only": 3}}})
    for bad in ({}, {"a": 0}, {"a": 0, "b": 0}, {"a": -1, "b": 2}):
        with pytest.raises(ValidationError):
            SimConfig.model_validate({"tags": {"environments": bad}})


def test_price_list_validators_accept_zero_and_reject_negative():
    base = Pricing().model_dump()["ec2_hourly"]
    Pricing(ec2_hourly={**base, "t3.micro": 0})
    with pytest.raises(ValidationError):
        Pricing(ec2_hourly={**base, "t3.micro": -0.0001})
    rds = Pricing().model_dump()["rds_hourly"]
    rds.pop("db.t3.large")
    with pytest.raises(ValidationError):
        Pricing(rds_hourly=rds)


def test_scenario_probability_bounds_and_region_validator():
    SimConfig.model_validate({"scenario_probabilities": {"open_ssh": 0}})
    SimConfig.model_validate({"scenario_probabilities": {"open_ssh": 1}})
    for bad in (-0.01, 1.01):
        with pytest.raises(ValidationError):
            SimConfig.model_validate({"scenario_probabilities": {"open_ssh": bad}})
    with pytest.raises(ValidationError):
        SimConfig.model_validate({"region": "us-east-9"})


def test_utilization_sum_tolerance():
    Utilization(idle=0.25, underutilized=0.25, normal=0.25, busy=0.25)
    Utilization(idle=0.255, underutilized=0.25, normal=0.25, busy=0.25)      # within +-0.01
    with pytest.raises(ValidationError):
        Utilization(idle=0.27, underutilized=0.25, normal=0.25, busy=0.25)


def test_capacity_checks_allow_equality_and_reject_excess():
    for counts_key, quota_key, n in (("ec2_instances", "ec2_instances", 5), ("s3_buckets", "s3_buckets", 5), ("rds_instances", "rds_instances", 2),
                                     ("elastic_ips", "elastic_ips", 3), ("vpcs", "vpcs", 2), ("iam_users", "iam_users", 6), ("load_balancers", "load_balancers", 2)):
        ok = {"counts": {counts_key: n}, "quotas": {quota_key: n}}
        SimConfig.model_validate(ok)                                                       # equal is fine
        if n > 1:
            with pytest.raises(ValidationError):
                SimConfig.model_validate({"counts": {counts_key: n}, "quotas": {quota_key: n - 1}})


def test_presets_validate_and_unknown_preset_is_rejected():
    for name in ("clean", "typical", "neglected"):
        assert preset_config(name).preset == name
    with pytest.raises(ValueError):
        preset_config("chaotic")
    assert preset_config("clean").security.open_ssh_pct == 0 and preset_config("neglected").security.open_ssh_pct == 0.5
    assert copy.deepcopy(preset_config("clean", seed=9).seed) == 9 and date(2026, 10, 1) == preset_config("clean").time.start_date


# ------------------------------------------------------------------- billing
def test_rds_cost_is_compute_plus_storage_exactly(env):
    db = env.of("rds_instance")[0]
    db["multi_az"] = False
    expected = env.pricing["rds_hourly"][db["instance_class"]] * 24 + db["storage_gb"] * env.pricing["rds_storage_gb_month"] / 30
    assert billing.fixed_daily(env, db)["RDS"] == pytest.approx(expected)
    db["state"] = "stopped"
    assert billing.fixed_daily(env, db) == {}


def test_load_balancer_cost_includes_capacity_units(env):
    lb = env.of("load_balancer")[0]
    assert billing.fixed_daily(env, lb)["Load Balancing"] == pytest.approx((env.pricing["alb_hourly"] + env.pricing["alb_lcu_hourly"]) * 24)


def test_s3_cost_uses_override_size_and_each_type_has_its_own_service(env):
    bucket = env.of("s3_bucket")[0]
    assert billing.fixed_daily(env, bucket, size_gb=300.0)["S3"] == pytest.approx(300 * env.pricing["s3_gb_month"] / 30)
    names = {t: list(billing.fixed_daily(env, env.of(t)[0]).keys()) for t in ("ebs_volume", "snapshot", "s3_bucket", "load_balancer")}
    assert names == {"ebs_volume": ["EBS"], "snapshot": ["Snapshots"], "s3_bucket": ["S3"], "load_balancer": ["Load Balancing"]}
    assert billing.fixed_daily(env, env.of("vpc")[0]) == {} and billing.fixed_daily(env, env.of("iam_user")[0]) == {}


def test_elastic_ip_associated_with_running_instance_is_free_but_not_when_stopped_or_missing(env):
    eip = next(e for e in env.of("elastic_ip") if e["instance_id"])
    assert billing.fixed_daily(env, eip) == {}
    env.get(eip["instance_id"])["state"] = "stopped"
    assert billing.fixed_daily(env, eip)["Elastic IP"] == pytest.approx(env.pricing["eip_idle_hourly"] * 24)
    eip["instance_id"] = "i-gone"
    assert billing.fixed_daily(env, eip)["Elastic IP"] > 0


def test_instance_state_override_and_ebs_prices_per_type(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "stopped")
    assert billing.fixed_daily(env, inst) == {}
    assert billing.fixed_daily(env, inst, state="running")["EC2"] == pytest.approx(env.pricing["ec2_hourly"][inst["instance_type"]] * 24)
    vol = env.of("ebs_volume")[0]
    for vtype, price in env.pricing["ebs_gb_month"].items():
        vol["volume_type"] = vtype
        assert billing.fixed_daily(env, vol)["EBS"] == pytest.approx(vol["size_gb"] * price / 30)
    assert billing.data_transfer_daily(env, 10) == pytest.approx(10 * env.pricing["data_transfer_out_gb"])


# --------------------------------------------------------------- remediation
def test_plan_hash_depends_on_params_and_ignores_key_order_and_descriptions():
    a = [{"action": "sg.revoke_ingress", "target_id": "sg-1", "params": {"protocol": "tcp", "from_port": 22}}]
    b = [{"action": "sg.revoke_ingress", "target_id": "sg-1", "params": {"from_port": 22, "protocol": "tcp"}, "description": "x"}]
    c = [{"action": "sg.revoke_ingress", "target_id": "sg-1", "params": {"protocol": "tcp", "from_port": 23}}]
    assert remediation.plan_hash(a) == remediation.plan_hash(b)
    assert remediation.plan_hash(a) != remediation.plan_hash(c)
    assert len(remediation.plan_hash(a)) == 16
    assert remediation.plan_hash([{"action": "x", "target_id": None}]) == remediation.plan_hash([{"action": "x", "target_id": None, "params": {}}])
    assert remediation.plan_hash([{"action": "x", "target_id": None, "params": {"k": 1}}]) != remediation.plan_hash([{"action": "x", "target_id": None}])


def test_normalise_ops_rejects_missing_action_with_422_and_fills_defaults():
    with pytest.raises(SimError) as exc:
        remediation.normalise_ops([{"target_id": "x"}])
    assert exc.value.status == 422 and exc.value.code == "invalid_parameter"
    (op,) = remediation.normalise_ops([{"action": "ec2.stop", "target_id": "i-1"}])
    assert op == {"action": "ec2.stop", "target_id": "i-1", "params": {}, "description": ""}
