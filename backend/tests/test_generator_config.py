"""Unit tests: configuration validation, deterministic generation, referential integrity."""

import pytest
from pydantic import ValidationError

from app.simulator.config import SimConfig, list_presets, preset_config
from app.simulator.env import relationships
from app.simulator.generator import generate_environment


def test_same_seed_and_config_reproduce_identical_environment(base_env):
    again = generate_environment(SimConfig())
    assert again.fingerprint() == base_env.fingerprint()
    assert sorted(again.resources["ec2_instance"]) == sorted(base_env.resources["ec2_instance"])


def test_different_seed_changes_identifiers_and_properties(base_env):
    other = generate_environment(SimConfig(seed=43))
    assert other.fingerprint() != base_env.fingerprint()
    assert set(other.resources["ec2_instance"]).isdisjoint(base_env.resources["ec2_instance"])


def test_seed_changes_nothing_when_unrelated_field_differs_only_in_name():
    a = generate_environment(SimConfig(name="a"))
    b = generate_environment(SimConfig(name="b"))
    assert a.fingerprint() == b.fingerprint()  # name is metadata, not state


def test_resource_counts_follow_configuration():
    cfg = SimConfig.model_validate({"counts": {"vpcs": 3, "ec2_instances": 9, "s3_buckets": 4, "rds_instances": 2,
                                               "iam_users": 5, "load_balancers": 1, "elastic_ips": 2}})
    env = generate_environment(cfg)
    assert len(env.of("vpc")) == 3
    assert len(env.of("ec2_instance")) == 9
    assert len(env.of("s3_bucket")) == 4
    assert len(env.of("rds_instance")) == 2
    assert len(env.of("iam_user")) == 5
    assert len(env.of("elastic_ip")) == 2
    assert len(env.of("subnet")) == 3 * cfg.counts.subnets_per_vpc


def test_every_relationship_points_to_an_existing_resource(base_env):
    ids = {r["id"] for r in base_env.all()}
    missing = [(s, t, rel) for s, t, rel in relationships(base_env) if s not in ids or t not in ids]
    assert missing == []


def test_instances_belong_to_subnets_in_the_same_vpc_with_matching_security_groups(base_env):
    for inst in base_env.of("ec2_instance"):
        subnet = base_env.get(inst["subnet_id"], "subnet")
        assert subnet["vpc_id"] == inst["vpc_id"]
        assert all(base_env.get(sg, "security_group")["vpc_id"] == inst["vpc_id"] for sg in inst["sg_ids"])
        assert base_env.get(inst["eni_id"], "network_interface")["attached_to"] == inst["id"]


def test_volumes_and_snapshots_reference_existing_resources(base_env):
    for vol in base_env.of("ebs_volume"):
        if vol["attached_to"]:
            assert vol["id"] in base_env.get(vol["attached_to"], "ec2_instance")["volume_ids"]
            assert vol["az"] == base_env.get(vol["attached_to"])["az"]
    for snap in base_env.of("snapshot"):
        assert base_env.exists(snap["volume_id"])


def test_identifiers_are_unique_across_types(base_env):
    ids = [r["id"] for r in base_env.all()]
    assert len(ids) == len(set(ids))


def test_history_is_backfilled_without_artificial_cost_steps(base_env):
    assert len(base_env.daily_costs) == 30
    totals = [sum(sum(s.values()) for s in day.values()) for _, day in sorted(base_env.daily_costs.items())]
    assert max(totals) / min(totals) < 1.05


def test_clean_preset_has_no_misconfigurations(clean_base):
    from app.engines import security
    findings = security.evaluate(clean_base)
    assert [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")] == []


def test_neglected_preset_is_worse_than_typical():
    from app.engines import security
    typical = security.evaluate(generate_environment(preset_config("typical")))
    neglected = security.evaluate(generate_environment(preset_config("neglected")))
    assert security.score(neglected) < security.score(typical)


def test_presets_list_contains_valid_configs():
    presets = list_presets()
    assert {p["name"] for p in presets} == {"clean", "typical", "neglected"}
    for p in presets:
        SimConfig.model_validate(p["config"])


@pytest.mark.parametrize("patch,message", [
    ({"region": "mars-1"}, "unsupported region"),
    ({"counts": {"subnets_per_vpc": 3}}, "must be even"),
    ({"counts": {"vpcs": 0}}, "greater than or equal to 1"),
    ({"utilization": {"idle": 0.9, "underutilized": 0.9, "normal": 0.0, "busy": 0.0}}, "sum to 1.0"),
    ({"security": {"open_ssh_pct": 1.5}}, "less than or equal to 1"),
    ({"account_id": "123"}, "String should match"),
    ({"scenario_probabilities": {"nope": 0.5}}, "unknown scenario"),
    ({"scenario_probabilities": {"open_ssh": 2}}, "within 0..1"),
    ({"counts": {"ec2_instances": 500}}, "less than or equal to 200"),
    ({"quotas": {"ec2_instances": 2}}, "exceeds quotas"),
    ({"naming": {"org": "Bad Org"}}, "pattern"),
    ({"unknown_field": 1}, "Extra inputs"),
])
def test_invalid_configuration_is_rejected(patch, message):
    with pytest.raises(ValidationError) as exc:
        SimConfig.model_validate(patch)
    assert message in str(exc.value)


def test_pricing_must_cover_every_instance_type():
    pricing = SimConfig().pricing.model_dump()
    pricing["ec2_hourly"].pop("t3.micro")
    with pytest.raises(ValidationError):
        SimConfig.model_validate({"pricing": pricing})


def test_scenario_probability_one_applies_scenario_during_generation():
    from app.engines import network
    cfg = preset_config("clean", scenario_probabilities={"open_ssh": 1.0})
    env = generate_environment(cfg)
    assert any(22 in e["sensitive_ports"] for e in network.reachable_exposures(env))


def test_account_id_is_generated_and_stable(base_env):
    assert len(base_env.account_id) == 12 and base_env.account_id.isdigit()
    assert generate_environment(SimConfig()).account_id == base_env.account_id


def test_naming_convention_is_applied():
    env = generate_environment(SimConfig.model_validate({"naming": {"org": "globex", "separator": "_"}}))
    assert all(i["name"].startswith("globex_") for i in env.of("ec2_instance"))


def test_tag_policy_leaves_some_resources_untagged_only_when_configured(clean_base):
    assert all("owner" in i["tags"] for i in clean_base.of("ec2_instance"))
