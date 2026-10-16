"""Unit tests: validated lifecycle operations and their prerequisites."""

import pytest

from app.simulator import lifecycle
from app.simulator.env import SimError


def run(env, action, target=None, /, **params):
    return lifecycle.execute(env, action, target, params)


def expect_error(env, action, target=None, /, code=None, **params):
    with pytest.raises(SimError) as exc:
        run(env, action, target, **params)
    if code:
        assert exc.value.code == code
    return exc.value


def running_private_instance(env):
    return next(i for i in env.of("ec2_instance") if i["state"] == "running" and not i.get("public_ip"))


def subnet_of(env, tier):
    return next(s for s in env.of("subnet") if s["tags"]["tier"] == tier)


def sg_in(env, vpc_id, suffix):
    return next(s for s in env.of("security_group") if s["vpc_id"] == vpc_id and s["name"].endswith(suffix))


def launch(env, **over):
    subnet = subnet_of(env, "private")
    params = dict(subnet_id=subnet["id"], instance_type="t3.small", sg_ids=[sg_in(env, subnet["vpc_id"], "app-sg")["id"]])
    params.update(over)
    return run(env, "ec2.create", None, **params)


# ----------------------------------------------------------------------- EC2
def test_launch_creates_instance_volume_and_interface(env):
    before = (len(env.of("ec2_instance")), len(env.of("ebs_volume")), len(env.of("network_interface")))
    res = launch(env, name="new-box")
    inst = env.get(res["created"][0], "ec2_instance")
    assert inst["state"] == "running" and inst["name"] == "new-box"
    assert (len(env.of("ec2_instance")), len(env.of("ebs_volume")), len(env.of("network_interface"))) == tuple(b + 1 for b in before)
    assert env.get(inst["volume_ids"][0], "ebs_volume")["attached_to"] == inst["id"]


def test_launch_rejects_unknown_type_subnet_and_foreign_security_group(env):
    expect_error(env, "ec2.create", None, subnet_id=subnet_of(env, "private")["id"], instance_type="x9.huge", sg_ids=["sg-1"])
    expect_error(env, "ec2.create", None, code="not_found", subnet_id="subnet-nope", instance_type="t3.small", sg_ids=["sg-1"])
    vpc_a, vpc_b = env.of("vpc")[:2]
    sn = next(s for s in env.of("subnet") if s["vpc_id"] == vpc_a["id"])
    foreign_sg = sg_in(env, vpc_b["id"], "app-sg")["id"]
    expect_error(env, "ec2.create", None, code="invalid_relationship", subnet_id=sn["id"], instance_type="t3.small", sg_ids=[foreign_sg])


def test_launch_missing_required_parameter_is_reported(env):
    err = expect_error(env, "ec2.create", None, code="invalid_parameter", instance_type="t3.small")
    assert "Missing required parameter" in err.message


def test_unknown_and_wrongly_typed_parameters_are_rejected(env):
    expect_error(env, "ec2.stop", running_private_instance(env)["id"], code="invalid_parameter", bogus=1)
    expect_error(env, "ebs.create", None, code="invalid_parameter", size_gb="abc", az="us-east-1a")


def test_instance_quota_is_enforced(env):
    env.config["quotas"]["ec2_instances"] = env.count("ec2_instance")
    sub = subnet_of(env, "private")
    err = expect_error(env, "ec2.create", None, code="quota_exceeded", subnet_id=sub["id"], instance_type="t3.small",
                       sg_ids=[sg_in(env, sub["vpc_id"], "app-sg")["id"]])
    assert "Quota exceeded" in err.message


def test_stop_start_transitions_and_idempotency_errors(env):
    inst = running_private_instance(env)
    run(env, "ec2.stop", inst["id"])
    assert inst["state"] == "stopped" and inst["stopped_at"]
    expect_error(env, "ec2.stop", inst["id"], code="invalid_state")
    run(env, "ec2.start", inst["id"])
    assert inst["state"] == "running" and inst["stopped_at"] is None
    expect_error(env, "ec2.start", inst["id"], code="invalid_state")


def test_stopping_releases_auto_public_ip_but_keeps_elastic_ip(env):
    eip = next(e for e in env.of("elastic_ip") if e["instance_id"])
    inst = env.get(eip["instance_id"])
    run(env, "ec2.stop", inst["id"])
    assert inst["public_ip"] == eip["public_ip"]
    auto = next(i for i in env.of("ec2_instance") if i["state"] == "running" and i["public_ip"]
                and not any(e["instance_id"] == i["id"] for e in env.of("elastic_ip")))
    run(env, "ec2.stop", auto["id"])
    assert auto["public_ip"] is None


def test_change_type_requires_stopped_instance_and_a_real_change(env):
    inst = running_private_instance(env)
    expect_error(env, "ec2.change_type", inst["id"], code="invalid_state", instance_type="t3.small")
    run(env, "ec2.stop", inst["id"])
    expect_error(env, "ec2.change_type", inst["id"], code="no_change", instance_type=inst["instance_type"])
    run(env, "ec2.change_type", inst["id"], instance_type="m5.large")
    assert inst["instance_type"] == "m5.large"


def test_terminate_cleans_up_dependents_and_blocks_further_use(env):
    eip = next(e for e in env.of("elastic_ip") if e["instance_id"])
    inst = env.get(eip["instance_id"])
    root = inst["volume_ids"][0]
    run(env, "ec2.terminate", inst["id"])
    assert inst["state"] == "terminated" and not env.exists(root)
    assert eip["instance_id"] is None and eip["state"] == "unassociated"
    assert not env.exists(inst.get("eni_id") or "x")
    expect_error(env, "ec2.stop", inst["id"], code="invalid_state")


def test_actions_on_missing_or_wrong_type_targets_fail_cleanly(env):
    expect_error(env, "ec2.stop", "i-doesnotexist", code="not_found")
    expect_error(env, "ec2.stop", env.of("vpc")[0]["id"], code="wrong_type")
    expect_error(env, "ec2.stop", None, code="invalid_parameter")
    expect_error(env, "no.such.action", "x", code="unsupported_action")


def test_isolate_replaces_security_groups_with_empty_quarantine_group(env):
    inst = running_private_instance(env)
    run(env, "ec2.isolate", inst["id"])
    sg = env.get(inst["sg_ids"][0], "security_group")
    assert sg["name"] == "quarantine" and sg["ingress"] == [] and sg["egress"] == []
    assert env.get(inst["eni_id"])["sg_ids"] == inst["sg_ids"]


# ----------------------------------------------------------------------- EBS
def test_volume_attach_detach_delete_rules(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running")
    vol = run(env, "ebs.create", None, size_gb=10, az=inst["az"])["created"][0]
    expect_error(env, "ebs.detach", vol, code="invalid_state")
    run(env, "ebs.attach", vol, instance_id=inst["id"], device="/dev/sdx")
    assert env.get(vol)["state"] == "in-use"
    expect_error(env, "ebs.delete", vol, code="invalid_state")
    expect_error(env, "ebs.attach", vol, code="invalid_state", instance_id=inst["id"])
    run(env, "ebs.detach", vol)
    run(env, "ebs.delete", vol)
    assert not env.exists(vol)


def test_attach_requires_same_az_and_unique_device(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running")
    other_az = next(a for a in ("us-east-1a", "us-east-1b", "us-east-1c") if a != inst["az"])
    vol = run(env, "ebs.create", None, size_gb=10, az=other_az)["created"][0]
    expect_error(env, "ebs.attach", vol, code="invalid_relationship", instance_id=inst["id"])
    vol2 = run(env, "ebs.create", None, size_gb=10, az=inst["az"])["created"][0]
    expect_error(env, "ebs.attach", vol2, code="duplicate_device", instance_id=inst["id"], device="/dev/xvda")


def test_root_volume_of_running_instance_cannot_be_detached(env):
    inst = running_private_instance(env)
    expect_error(env, "ebs.detach", inst["volume_ids"][0], code="invalid_state")


def test_volume_creation_validates_size_type_and_az(env):
    expect_error(env, "ebs.create", None, code="invalid_parameter", size_gb=0, az="us-east-1a")
    expect_error(env, "ebs.create", None, code="invalid_parameter", size_gb=10, az="eu-west-1a")
    expect_error(env, "ebs.create", None, code="invalid_parameter", size_gb=10, az="us-east-1a", volume_type="floppy")


def test_encryption_and_backup_configuration(env):
    vol = next(v for v in env.of("ebs_volume") if v["attached_to"])
    vol["encrypted"] = False
    run(env, "ebs.enable_encryption", vol["id"])
    assert vol["encrypted"] is True
    expect_error(env, "ebs.enable_encryption", vol["id"], code="no_change")
    vol["backup_policy"] = "none"
    n = len(env.of("snapshot"))
    run(env, "ebs.set_backup_policy", vol["id"], policy="daily")
    assert vol["backup_policy"] == "daily" and len(env.of("snapshot")) == n + 1
    expect_error(env, "ebs.set_backup_policy", vol["id"], code="no_change", policy="daily")
    orphan = next(v for v in env.of("ebs_volume") if v["state"] == "available")
    expect_error(env, "ebs.set_backup_policy", orphan["id"], code="invalid_state", policy="daily")


def test_snapshot_create_and_delete(env):
    vol = next(v for v in env.of("ebs_volume"))
    snap = run(env, "snapshot.create", vol["id"])["created"][0]
    assert env.get(snap, "snapshot")["volume_id"] == vol["id"]
    run(env, "snapshot.delete", snap)
    assert not env.exists(snap)


# ------------------------------------------------------------------------ S3
def test_bucket_name_rules_and_duplicates(env):
    expect_error(env, "s3.create_bucket", None, code="invalid_parameter", name="Bad_Name")
    expect_error(env, "s3.create_bucket", None, code="invalid_parameter", name="ab")
    run(env, "s3.create_bucket", None, name="acme-new-bucket")
    expect_error(env, "s3.create_bucket", None, code="duplicate_id", name="acme-new-bucket")
    assert env.get("acme-new-bucket")["encryption"] == "AES256"


def test_non_empty_bucket_needs_force_to_delete(env):
    bucket = next(b for b in env.of("s3_bucket") if b["size_gb"] > 0)
    expect_error(env, "s3.delete_bucket", bucket["id"], code="not_empty")
    run(env, "s3.delete_bucket", bucket["id"], force=True)
    assert not env.exists(bucket["id"])


def test_public_acl_is_rejected_while_block_public_access_is_on(env):
    bucket = next(b for b in env.of("s3_bucket") if b["block_public_access"])
    expect_error(env, "s3.set_acl", bucket["id"], code="access_denied", acl="public-read")
    expect_error(env, "s3.set_public_policy", bucket["id"], code="access_denied", enabled=True)
    run(env, "s3.set_public_access_block", bucket["id"], block=False)
    run(env, "s3.set_acl", bucket["id"], acl="public-read")
    run(env, "s3.make_private", bucket["id"])
    assert bucket["block_public_access"] and bucket["acl"] == "private" and not bucket["policy_public"]


def test_bucket_encryption_toggle(env):
    bucket = env.of("s3_bucket")[0]
    bucket["encryption"] = "none"
    run(env, "s3.enable_encryption", bucket["id"])
    assert bucket["encryption"] == "AES256"
    expect_error(env, "s3.enable_encryption", bucket["id"], code="no_change")


# ----------------------------------------------------------- security groups
def test_security_group_rule_validation(env):
    sg = env.of("security_group")[0]
    expect_error(env, "sg.authorize_ingress", sg["id"], code="invalid_parameter", protocol="tcp", from_port=100, to_port=10, cidr="10.0.0.0/8")
    expect_error(env, "sg.authorize_ingress", sg["id"], code="invalid_parameter", protocol="tcp", from_port=1, to_port=70000, cidr="10.0.0.0/8")
    expect_error(env, "sg.authorize_ingress", sg["id"], code="invalid_parameter", protocol="tcp", from_port=1, to_port=2, cidr="not-a-cidr")
    expect_error(env, "sg.authorize_ingress", sg["id"], code="invalid_parameter", protocol="tcp", from_port=1, to_port=2)
    expect_error(env, "sg.authorize_ingress", sg["id"], code="invalid_parameter", protocol="tcp", from_port=1, to_port=2,
                 cidr="10.0.0.0/8", source_sg=sg["id"])
    expect_error(env, "sg.authorize_ingress", sg["id"], code="invalid_parameter", protocol="tcp")


def test_duplicate_rules_are_rejected_and_revoke_requires_existing_rule(env):
    sg = env.of("security_group")[0]
    run(env, "sg.authorize_ingress", sg["id"], protocol="tcp", from_port=9000, to_port=9000, cidr="10.1.0.0/16")
    expect_error(env, "sg.authorize_ingress", sg["id"], code="duplicate_rule", protocol="tcp", from_port=9000, to_port=9000, cidr="10.1.0.0/16")
    run(env, "sg.revoke_ingress", sg["id"], protocol="tcp", from_port=9000, to_port=9000, cidr="10.1.0.0/16")
    expect_error(env, "sg.revoke_ingress", sg["id"], code="not_found", protocol="tcp", from_port=9000, to_port=9000, cidr="10.1.0.0/16")


def test_all_traffic_rule_ignores_ports(env):
    sg = env.of("security_group")[0]
    run(env, "sg.authorize_ingress", sg["id"], protocol="-1", cidr="10.9.0.0/16")
    assert sg["ingress"][-1]["from_port"] == 0 and sg["ingress"][-1]["to_port"] == 65535


def test_restrict_ingress_changes_source_and_rejects_noop(env):
    sg = next(s for s in env.of("security_group") if any(r["cidr"] == "0.0.0.0/0" for r in s["ingress"]))
    rule = next(r for r in sg["ingress"] if r["cidr"] == "0.0.0.0/0")
    expect_error(env, "sg.restrict_ingress", sg["id"], code="no_change", protocol=rule["protocol"], from_port=rule["from_port"],
                 to_port=rule["to_port"], cidr="0.0.0.0/0", new_cidr="0.0.0.0/0")
    run(env, "sg.restrict_ingress", sg["id"], protocol=rule["protocol"], from_port=rule["from_port"], to_port=rule["to_port"],
        cidr="0.0.0.0/0", new_cidr="203.0.113.0/24")
    assert rule["cidr"] == "203.0.113.0/24"


def test_security_group_in_use_cannot_be_deleted(env):
    used = env.get(env.of("ec2_instance")[0]["sg_ids"][0])
    expect_error(env, "sg.delete", used["id"], code="in_use")
    new = run(env, "sg.create", None, vpc_id=used["vpc_id"], name="temp-sg")["created"][0]
    expect_error(env, "sg.create", None, code="duplicate_id", vpc_id=used["vpc_id"], name="temp-sg")
    run(env, "sg.delete", new)
    assert not env.exists(new)


# ------------------------------------------------------------------- network
def test_route_and_igw_operations(env):
    private_rt = next(r for r in env.of("route_table") if r["name"].endswith("private-rt"))
    igw = env.get(env.get(private_rt["vpc_id"])["igw_id"])
    expect_error(env, "route.delete", private_rt["id"], code="invalid_operation", destination=env.get(private_rt["vpc_id"])["cidr"])
    expect_error(env, "route.delete", private_rt["id"], code="not_found", destination="0.0.0.0/0")
    run(env, "route.set", private_rt["id"], destination="0.0.0.0/0", target_type="igw", target=igw["id"])
    run(env, "route.delete", private_rt["id"], destination="0.0.0.0/0")
    run(env, "igw.detach", igw["id"])
    expect_error(env, "igw.detach", igw["id"], code="invalid_state")
    expect_error(env, "route.set", private_rt["id"], code="invalid_relationship", destination="0.0.0.0/0", target_type="igw", target=igw["id"])
    run(env, "igw.attach", igw["id"])
    expect_error(env, "igw.attach", igw["id"], code="invalid_state")


def test_route_cannot_target_gateway_of_another_vpc(env):
    vpc_a, vpc_b = env.of("vpc")[:2]
    rt = next(r for r in env.of("route_table") if r["vpc_id"] == vpc_a["id"])
    expect_error(env, "route.set", rt["id"], code="invalid_relationship", destination="0.0.0.0/0", target_type="igw", target=vpc_b["igw_id"])


def test_subnet_route_table_association_must_stay_inside_vpc(env):
    sub = subnet_of(env, "private")
    foreign = next(r for r in env.of("route_table") if r["vpc_id"] != sub["vpc_id"])
    expect_error(env, "subnet.associate_route_table", sub["id"], code="invalid_relationship", route_table_id=foreign["id"])
    expect_error(env, "subnet.associate_route_table", sub["id"], code="no_change", route_table_id=sub["route_table_id"])


def test_elastic_ip_lifecycle_and_quota(env):
    eip = run(env, "eip.allocate")["created"][0]
    inst = running_private_instance(env)
    run(env, "eip.associate", eip, instance_id=inst["id"])
    assert inst["public_ip"] == env.get(eip)["public_ip"]
    expect_error(env, "eip.associate", eip, code="invalid_state", instance_id=inst["id"])
    expect_error(env, "eip.release", eip, code="in_use")
    run(env, "eip.disassociate", eip)
    assert inst["public_ip"] is None
    run(env, "eip.release", eip)
    env.config["quotas"]["elastic_ips"] = len(env.of("elastic_ip"))
    expect_error(env, "eip.allocate", code="quota_exceeded")


# ----------------------------------------------------------------------- RDS
def test_rds_modify_rules(env):
    db = env.of("rds_instance")[0]
    expect_error(env, "rds.modify", db["id"], code="invalid_parameter")
    expect_error(env, "rds.modify", db["id"], code="invalid_parameter", storage_gb=db["storage_gb"] - 10)
    expect_error(env, "rds.modify", db["id"], code="no_change", instance_class=db["instance_class"])
    run(env, "rds.modify", db["id"], storage_gb=db["storage_gb"] + 50)


def test_rds_backup_retention_bounds(env):
    db = next(d for d in env.of("rds_instance") if d["backup_retention_days"] > 0)
    expect_error(env, "rds.set_backup_retention", db["id"], code="invalid_parameter", days=99)
    run(env, "rds.set_backup_retention", db["id"], days=0)
    assert db["last_backup_at"] is None
    run(env, "rds.set_backup_retention", db["id"], days=5)
    assert db["last_backup_at"] is not None


def test_rds_create_validates_identifier_and_network(env):
    vpc = env.of("vpc")[0]
    expect_error(env, "rds.create", None, code="duplicate_id", name=env.of("rds_instance")[0]["id"], vpc_id=vpc["id"],
                 engine="postgres", instance_class="db.t3.large")
    run(env, "rds.create", None, name="orders-db", vpc_id=vpc["id"], engine="postgres", instance_class="db.t3.large")
    assert env.get("orders-db")["publicly_accessible"] is False
    expect_error(env, "rds.create", None, code="invalid_parameter", name="x-db", vpc_id=vpc["id"], engine="postgres",
                 instance_class="db.t3.large", storage_gb=5)


# ----------------------------------------------------------------------- IAM
def test_iam_policy_attachment_rules(env):
    user = env.of("iam_user")[-1]
    expect_error(env, "iam.attach_policy", user["id"], code="not_found", policy_id="policy:Nope")
    pol = next(p for p in user["policy_ids"])
    expect_error(env, "iam.attach_policy", user["id"], code="duplicate_rule", policy_id=pol)
    run(env, "iam.detach_policy", user["id"], policy_id=pol)
    expect_error(env, "iam.detach_policy", user["id"], code="not_found", policy_id=pol)


def test_create_policy_and_user_validation(env):
    expect_error(env, "iam.create_policy", None, code="invalid_parameter", name="bad name!", effect="Allow", actions=["s3:*"], resources=["*"])
    run(env, "iam.create_policy", None, name="Custom1", effect="Allow", actions="s3:GetObject,s3:ListBucket", resources=["*"])
    assert env.get("policy:Custom1")["statements"][0]["actions"] == ["s3:GetObject", "s3:ListBucket"]
    expect_error(env, "iam.create_policy", None, code="duplicate_id", name="Custom1", effect="Allow", actions=["s3:*"], resources=["*"])
    run(env, "iam.create_user", None, name="zed")
    expect_error(env, "iam.create_user", None, code="duplicate_id", name="zed")


def test_mfa_and_access_key_operations(env):
    user = next(u for u in env.of("iam_user") if u["console_access"] and u["access_keys"])
    user["mfa_enabled"] = False
    run(env, "iam.enable_mfa", user["id"])
    expect_error(env, "iam.enable_mfa", user["id"], code="no_change")
    key = user["access_keys"][0]["id"]
    run(env, "iam.deactivate_access_key", user["id"], key_id=key)
    expect_error(env, "iam.deactivate_access_key", user["id"], code="no_change", key_id=key)
    expect_error(env, "iam.deactivate_access_key", user["id"], code="not_found", key_id="AKIAMISSING")
    run(env, "iam.delete_access_key", user["id"], key_id=key)
    assert user["access_keys"] == []
    svc = next(u for u in env.of("iam_user") if not u["console_access"])
    expect_error(env, "iam.enable_mfa", svc["id"], code="no_change") if svc["mfa_enabled"] else expect_error(env, "iam.enable_mfa", svc["id"], code="invalid_state")


def test_trust_restriction_removes_only_wildcard_and_external_principals(env):
    role = env.get("role:deploy-role")
    role["trust"] += [{"type": "AWS", "value": "*"}, {"type": "AWS", "value": "111122223333"}]
    run(env, "iam.restrict_trust", role["id"])
    assert role["trust"] == [{"type": "AWS", "value": env.account_id}]
    expect_error(env, "iam.restrict_trust", role["id"], code="no_change")


# ---------------------------------------------------------------------- tags
def test_tag_operations_and_limits(env):
    inst = env.of("ec2_instance")[0]
    run(env, "tags.set", inst["id"], tags={"cost-center": "42"})
    assert inst["tags"]["cost-center"] == "42"
    expect_error(env, "tags.set", inst["id"], code="invalid_parameter", tags={"": "x"})
    expect_error(env, "tags.set", inst["id"], code="quota_exceeded", tags={f"k{i}": "v" for i in range(60)})
    run(env, "tags.remove", inst["id"], keys=["cost-center"])
    expect_error(env, "tags.remove", inst["id"], code="not_found", keys=["cost-center"])


def test_action_catalog_describes_every_operation():
    cat = lifecycle.catalog()
    assert {c["name"] for c in cat} == set(lifecycle.OPS)
    assert all(c["description"] and "params" in c for c in cat)
