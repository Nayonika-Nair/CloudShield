"""Unit tests: derived network reachability and the simplified IAM model."""

import pytest

from app.engines import iam, network
from app.simulator import lifecycle


def run(env, action, target=None, /, **params):
    return lifecycle.execute(env, action, target, params)


def public_instance(env):
    pub = {s["id"] for s in env.of("subnet") if network.subnet_is_public(env, s)}
    return next(i for i in env.of("ec2_instance") if i["state"] == "running" and i["subnet_id"] in pub and i["public_ip"]
                and i["os"] == "linux")


def open_ssh(env, inst):
    sg = run(env, "sg.create", None, vpc_id=inst["vpc_id"], name="test-ssh")["created"][0]
    run(env, "sg.authorize_ingress", sg, protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0")
    run(env, "ec2.set_security_groups", inst["id"], sg_ids=inst["sg_ids"] + [sg])
    return sg


def ssh_exposure(env, inst):
    return [e for e in network.exposures(env, inst["id"]) if 22 in e["sensitive_ports"]]


# ------------------------------------------------------------------ reachability
def test_clean_environment_has_no_reachable_sensitive_exposure(clean_env):
    assert [e for e in network.reachable_exposures(clean_env) if e["sensitive_ports"] or e["all_ports"]] == []


def test_world_open_ssh_on_public_instance_is_reachable_with_explained_path(clean_env):
    inst = public_instance(clean_env)
    sg = open_ssh(clean_env, inst)
    (exp,) = ssh_exposure(clean_env, inst)
    assert exp["reachable"] and exp["security_group"] == sg
    assert [s["ok"] for s in exp["steps"]] == [True, True, True, True]
    assert "Reachable from the internet" in exp["explanation"] and inst["public_ip"] in exp["steps"][2]["detail"]


def test_same_rule_on_private_instance_is_latent_not_reachable(clean_env):
    private = next(i for i in clean_env.of("ec2_instance") if i["state"] == "running" and not i["public_ip"])
    open_ssh(clean_env, private)
    (exp,) = ssh_exposure(clean_env, private)
    assert not exp["reachable"]
    assert exp["blocked_at"] == "Resource has a public address"
    assert "not reachable" in exp["explanation"]


def test_removing_the_default_route_blocks_an_otherwise_open_instance(clean_env):
    inst = public_instance(clean_env)
    open_ssh(clean_env, inst)
    rt = clean_env.get(clean_env.get(inst["subnet_id"])["route_table_id"])
    run(clean_env, "route.delete", rt["id"], destination="0.0.0.0/0")
    (exp,) = ssh_exposure(clean_env, inst)
    assert not exp["reachable"] and exp["blocked_at"] == "Subnet routes to an internet gateway"
    run(clean_env, "route.set", rt["id"], destination="0.0.0.0/0", target_type="igw", target=clean_env.get(inst["vpc_id"])["igw_id"])
    assert ssh_exposure(clean_env, inst)[0]["reachable"]


def test_detached_internet_gateway_creates_blackhole_and_blocks_exposure(clean_env):
    inst = public_instance(clean_env)
    open_ssh(clean_env, inst)
    run(clean_env, "igw.detach", clean_env.get(inst["vpc_id"])["igw_id"])
    assert not ssh_exposure(clean_env, inst)[0]["reachable"]
    kinds = {i["kind"] for i in network.topology_issues(clean_env)}
    assert "blackhole_route" in kinds


def test_stopped_instance_is_not_reachable(clean_env):
    inst = public_instance(clean_env)
    open_ssh(clean_env, inst)
    run(clean_env, "ec2.stop", inst["id"])
    assert not any(e["reachable"] for e in ssh_exposure(clean_env, inst))


def test_changing_the_security_group_rule_changes_reachability(clean_env):
    inst = public_instance(clean_env)
    sg = open_ssh(clean_env, inst)
    run(clean_env, "sg.restrict_ingress", sg, protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0", new_cidr="203.0.113.0/24")
    assert ssh_exposure(clean_env, inst) == []


def test_security_group_source_rules_are_not_internet_exposure(clean_env):
    # app tier allows 8080 from the web security group, never from 0.0.0.0/0
    app_inst = next(i for i in clean_env.of("ec2_instance") if i["role"] == "app")
    assert network.exposures(clean_env, app_inst["id"]) == []


def test_load_balancer_http_listener_is_reachable_but_not_sensitive(clean_env):
    lb = clean_env.of("load_balancer")[0]
    exposures = network.exposures(clean_env, lb["id"])
    assert exposures and all(e["reachable"] for e in exposures)
    assert all(not e["sensitive_ports"] for e in exposures)


def test_public_database_with_open_port_is_reachable_only_with_public_subnet(clean_env):
    db = clean_env.of("rds_instance")[0]
    clean_env.get(db["sg_ids"][0])["ingress"].append(
        {"protocol": "tcp", "from_port": db["port"], "to_port": db["port"], "cidr": "0.0.0.0/0", "source_sg": None, "description": ""})
    assert not any(e["reachable"] for e in network.exposures(clean_env, db["id"]))
    db["publicly_accessible"] = True
    assert not any(e["reachable"] for e in network.exposures(clean_env, db["id"]))  # still in private subnets
    run(clean_env, "route.set", clean_env.get(clean_env.get(db["eni_id"])["subnet_id"])["route_table_id"],
        destination="0.0.0.0/0", target_type="igw", target=clean_env.get(db["vpc_id"])["igw_id"])
    assert any(e["reachable"] for e in network.exposures(clean_env, db["id"]))


def test_egress_requires_route_public_ip_and_world_rule(clean_env):
    inst = public_instance(clean_env)
    assert network.egress_open(clean_env, inst)
    run(clean_env, "ec2.isolate", inst["id"])
    assert not network.egress_open(clean_env, inst)
    private = next(i for i in clean_env.of("ec2_instance") if i["state"] == "running" and not i["public_ip"])
    assert not network.egress_open(clean_env, private)


def test_private_tier_routed_to_internet_is_reported(clean_env):
    rt = next(r for r in clean_env.of("route_table") if r["name"].endswith("private-rt"))
    run(clean_env, "route.set", rt["id"], destination="0.0.0.0/0", target_type="igw", target=clean_env.get(rt["vpc_id"])["igw_id"])
    kinds = [i["kind"] for i in network.topology_issues(clean_env)]
    assert "private_subnet_public" in kinds


def test_topology_graph_contains_all_network_layers_and_flags_exposure(clean_env):
    inst = public_instance(clean_env)
    open_ssh(clean_env, inst)
    topo = network.topology(clean_env)
    types = {n["type"] for n in topo["nodes"]}
    assert {"internet", "vpc", "subnet", "internet_gateway", "security_group", "ec2_instance", "rds_instance", "s3_bucket"} <= types
    node = next(n for n in topo["nodes"] if n["id"] == inst["id"])
    assert node["exposed"] and 22 in node["exposed_ports"]
    ids = {n["id"] for n in topo["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in topo["edges"])


def test_explain_reachability_rejects_unsupported_types(clean_env):
    with pytest.raises(Exception) as exc:
        network.explain_reachability(clean_env, clean_env.of("vpc")[0]["id"])
    assert "reachability applies" in str(exc.value)


# -------------------------------------------------------------------------- IAM
def test_policy_evaluation_allow_deny_implicit(clean_env):
    env = clean_env
    run(env, "iam.create_policy", None, name="DenyDelete", effect="Deny", actions=["s3:DeleteBucket"], resources=["*"])
    user = next(u for u in env.of("iam_user") if "policy:S3AppAccess" in u["policy_ids"])
    assert iam.evaluate(env, user["id"], "s3:GetObject", "arn:aws:s3:::acme-logs")["decision"] == "ALLOW"
    assert iam.evaluate(env, user["id"], "ec2:TerminateInstances")["decision"] == "IMPLICIT_DENY"
    run(env, "iam.attach_policy", user["id"], policy_id="policy:DenyDelete")
    run(env, "iam.create_policy", None, name="AllowAllS3", effect="Allow", actions=["s3:*"], resources=["*"])
    run(env, "iam.attach_policy", user["id"], policy_id="policy:AllowAllS3")
    verdict = iam.evaluate(env, user["id"], "s3:DeleteBucket", "*")
    assert verdict["decision"] == "DENY" and verdict["policy"] == "policy:DenyDelete"  # explicit deny wins


def test_wildcard_matching_is_case_insensitive_for_actions_and_scoped_for_resources(clean_env):
    env = clean_env
    reader = next(u for u in env.of("iam_user") if u["policy_ids"] == ["policy:ReadOnlyAccess"])
    assert iam.allowed(env, reader["id"], "S3:listbucket")
    assert not iam.allowed(env, reader["id"], "s3:PutObject")
    dev = next(u for u in env.of("iam_user") if "policy:S3AppAccess" in u["policy_ids"])
    assert iam.allowed(env, dev["id"], "s3:PutObject", f"arn:aws:s3:::{env.config['naming']['org']}-data")
    assert not iam.allowed(env, dev["id"], "s3:PutObject", "arn:aws:s3:::other-company-data")


def test_admin_detection_requires_wildcard_action_and_resource(clean_env):
    env = clean_env
    admin = next(u for u in env.of("iam_user") if u["tags"].get("admin") == "designated")
    assert iam.is_admin(env, admin["id"]) and iam.admin_policies(env, admin) == ["policy:AdministratorAccess"]
    dev = next(u for u in env.of("iam_user") if u["kind"] == "developer")
    assert not iam.is_admin(env, dev["id"])


def test_trust_with_account_root_needs_identity_permission(clean_env):
    env = clean_env
    deploy = env.get("role:deploy-role")
    dev = next(u for u in env.of("iam_user") if "policy:DeployerAssume" in u["policy_ids"])
    reader = next(u for u in env.of("iam_user") if u["policy_ids"] == ["policy:ReadOnlyAccess"])
    assert iam.can_assume(env, dev, deploy)
    assert not iam.can_assume(env, reader, deploy)  # trusted by account but lacks sts:AssumeRole
    deploy["trust"].append({"type": "AWS", "value": reader["id"]})
    assert iam.can_assume(env, reader, deploy)  # explicit principal in the trust policy


def test_wildcard_trust_lets_anyone_assume(clean_env):
    env = clean_env
    role = env.get("role:readonly-role")
    reader = next(u for u in env.of("iam_user") if u["policy_ids"] == ["policy:ReadOnlyAccess"])
    assert not iam.can_assume(env, reader, role)
    role["trust"].append({"type": "AWS", "value": "*"})
    assert iam.can_assume(env, reader, role)
    assert iam.risky_trusts(env, role)[0]["principal"] == "*"


def test_clean_environment_has_no_escalation_paths(clean_env):
    assert iam.escalation_paths(clean_env) == []


def test_assume_role_chain_to_admin_is_found(clean_env):
    env = clean_env
    run(env, "iam.attach_policy", "role:deploy-role", policy_id="policy:AdministratorAccess")
    paths = iam.escalation_paths(env)
    origins = {p["origin"] for p in paths}
    assert any(o.startswith("user:") for o in origins)
    p = next(p for p in paths if p["target"] == "role:deploy-role")
    assert p["steps"][0]["via"] == "sts:AssumeRole"


def test_passrole_plus_runinstances_reaches_instance_profile_role(clean_env):
    env = clean_env
    run(env, "iam.attach_policy", "role:ec2-app-role", policy_id="policy:AdministratorAccess")
    paths = {(p["origin"], p["target"]) for p in iam.escalation_paths(env)}
    assert ("role:deploy-role", "role:ec2-app-role") in paths  # deploy-role holds PassRole + RunInstances
    step = next(p for p in iam.escalation_paths(env) if p["origin"] == "role:deploy-role")["steps"][0]
    assert step["via"] == "iam:PassRole + ec2:RunInstances"


def test_iam_write_permission_is_an_escalation_edge_to_admin(clean_env):
    env = clean_env
    run(env, "iam.create_policy", None, name="PolicyEditor", effect="Allow", actions=["iam:AttachUserPolicy"], resources=["*"])
    user = next(u for u in env.of("iam_user") if u["kind"] == "readonly")
    run(env, "iam.attach_policy", user["id"], policy_id="policy:PolicyEditor")
    path = next(p for p in iam.escalation_paths(env) if p["origin"] == user["id"])
    assert path["target"] == iam.ADMIN and path["steps"][0]["via"] == "iam:AttachUserPolicy"


def test_key_report_flags_old_and_unused_keys(clean_env):
    env = clean_env
    user = next(u for u in env.of("iam_user") if u["access_keys"])
    key = user["access_keys"][0]
    assert iam.key_report(env, user)[0]["reasons"] == []
    from datetime import timedelta
    from app.simulator.env import iso
    key["created_at"] = iso(env.sim_time - timedelta(days=200))
    key["last_used"] = iso(env.sim_time - timedelta(days=90))
    reasons = iam.key_report(env, user)[0]["reasons"]
    assert len(reasons) == 2 and "200 days old" in reasons[0]


def test_analysis_summary_counts(base_env):
    a = iam.analyze(base_env)
    assert a["summary"]["users"] == len(base_env.of("iam_user"))
    assert a["summary"]["admins"] == len(a["admin_principals"])
    ids = {n["id"] for n in a["graph"]["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in a["graph"]["edges"])
