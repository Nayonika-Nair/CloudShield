"""Hardening tests for the network, IAM, cost, optimisation and security engines (boundary and exactness checks)."""

import statistics
from datetime import timedelta

import pytest

from app.engines import cost, iam, network, optimization, security
from app.simulator import builders as b
from app.simulator import lifecycle, scenarios, timeengine
from app.simulator.env import SimError, iso


def run(env, action, target=None, /, **params):
    return lifecycle.execute(env, action, target, params)


def set_series(env, rid, metric, values):
    """Daily metric points for the last len(values) days (oldest first)."""
    env.metrics.setdefault(rid, {})[metric] = {}
    for i, v in enumerate(values):
        env.metrics[rid][metric][(env.today - timedelta(days=len(values) - i)).isoformat()] = v


def flat(env, rid, cpu, mx=None, mem=None, net=0.5, days=14):
    """CPU series whose window average is exactly ``cpu`` and whose single peak is ``mx``."""
    vals = [cpu] * days
    if mx is not None:
        vals = [(cpu * days - mx) / (days - 1)] * (days - 1) + [mx]
    set_series(env, rid, "cpu", vals)
    if mem is not None:
        set_series(env, rid, "mem", [mem] * days)
    else:
        env.metrics[rid].pop("mem", None)
    set_series(env, rid, "net_out_gb", [net] * days)


def pub_instance(env, os="linux"):
    pub = {s["id"] for s in env.of("subnet") if network.subnet_is_public(env, s)}
    return next(i for i in env.of("ec2_instance") if i["state"] == "running" and i["subnet_id"] in pub and i["public_ip"] and i["os"] == os)


def recs(env, rule, **match):
    return [r for r in optimization.recommend(env) if r["rule_id"] == rule and all(r.get(k) == v for k, v in match.items())]


# =================================================================== network
def test_rule_coverage_and_all_ports_predicates():
    tcp22 = b.rule("tcp", 22, 22, "0.0.0.0/0")
    assert network.rule_covers(tcp22, 22) and not network.rule_covers(tcp22, 21) and not network.rule_covers(tcp22, 23)
    assert not network.rule_covers(b.rule("udp", 22, 22, "0.0.0.0/0"), 22)
    assert network.rule_covers(b.rule("-1", 0, 65535, "0.0.0.0/0"), 5)
    assert network.rule_covers(b.rule("tcp", 20, 25, "0.0.0.0/0"), 25) and network.rule_covers(b.rule("tcp", 20, 25, "0.0.0.0/0"), 20)
    assert network.rule_is_all_ports(b.rule("tcp", 0, 65535, "0.0.0.0/0"))
    assert network.rule_is_all_ports(b.rule("-1", 22, 22, "0.0.0.0/0"))
    assert not network.rule_is_all_ports(b.rule("tcp", 1, 65535, "0.0.0.0/0"))
    assert not network.rule_is_all_ports(b.rule("tcp", 0, 65534, "0.0.0.0/0"))
    assert network.sensitive_ports_in(b.rule("tcp", 20, 25, "0.0.0.0/0")) == [22, 23]
    assert 3389 in network.sensitive_ports_in(b.rule("-1", 0, 65535, "0.0.0.0/0"))


def test_rule_descriptions_are_exact():
    assert network.describe_rule(b.rule("tcp", 22, 22, "0.0.0.0/0")) == "tcp/22 from 0.0.0.0/0"
    assert network.describe_rule(b.rule("tcp", 1000, 2000, "10.0.0.0/8")) == "tcp/1000-2000 from 10.0.0.0/8"
    assert network.describe_rule(b.rule("-1", 0, 65535, "10.0.0.0/8")) == "all traffic from 10.0.0.0/8"
    assert network.describe_rule(b.rule("tcp", 80, 80, source_sg="sg-1")) == "tcp/80 from sg-1"
    assert network.describe_rule(b.rule("tcp", 80, 80)) == "tcp/80 from ?"


def test_route_table_lookup_falls_back_to_the_main_table_of_the_same_vpc(clean_env):
    sub = next(s for s in clean_env.of("subnet") if s["tags"]["tier"] == "private")
    sub["route_table_id"] = None
    rt = network.route_table_for(clean_env, sub)
    assert rt["vpc_id"] == sub["vpc_id"] and rt["main"]
    sub["route_table_id"] = "rtb-missing"
    assert network.route_table_for(clean_env, sub)["id"] == rt["id"]
    for r in clean_env.of("route_table"):
        if r["vpc_id"] == sub["vpc_id"]:
            r["main"] = False
    assert network.route_table_for(clean_env, sub) is None
    assert network.internet_route(clean_env, sub)["status"] == "none"


def test_gateway_must_belong_to_the_subnets_vpc_in_both_directions(clean_env):
    vpc_a, vpc_b = clean_env.of("vpc")[:2]
    for src, other in ((vpc_a, vpc_b), (vpc_b, vpc_a)):
        rt = next(r for r in clean_env.of("route_table") if r["vpc_id"] == src["id"] and r["name"].endswith("public-rt"))
        sub = next(s for s in clean_env.of("subnet") if s["route_table_id"] == rt["id"])
        assert network.internet_route(clean_env, sub)["status"] == "igw"
        for route in rt["routes"]:
            if route["destination"] == "0.0.0.0/0":
                route["target"] = other["igw_id"]
        result = network.internet_route(clean_env, sub)
        assert result["status"] == "blackhole" and not network.subnet_is_public(clean_env, sub)
    igw = clean_env.get(vpc_a["igw_id"])
    rt = next(r for r in clean_env.of("route_table") if r["vpc_id"] == vpc_b["id"] and r["name"].endswith("public-rt"))
    for route in rt["routes"]:
        if route["destination"] == "0.0.0.0/0":
            route["target"] = vpc_b["igw_id"]
    clean_env.get(vpc_b["igw_id"])["state"] = "detached"
    sub = next(s for s in clean_env.of("subnet") if s["route_table_id"] == rt["id"])
    assert network.internet_route(clean_env, sub)["status"] == "blackhole" and igw


def test_load_balancer_reachability_depends_on_state_scheme_and_first_subnet(clean_env):
    lb = clean_env.of("load_balancer")[0]
    assert all(e["reachable"] for e in network.exposures(clean_env, lb["id"]))
    lb["state"] = "draining"
    assert not any(e["reachable"] for e in network.exposures(clean_env, lb["id"]))
    assert network.exposures(clean_env, lb["id"])[0]["blocked_at"] == "Resource is running"
    lb["state"], lb["scheme"] = "active", "internal"
    assert network.exposures(clean_env, lb["id"])[0]["blocked_at"] == "Resource has a public address"
    lb["scheme"] = "internet-facing"
    private = next(s for s in clean_env.of("subnet") if s["vpc_id"] == lb["vpc_id"] and s["tags"]["tier"] == "private")
    public = clean_env.get(lb["subnet_ids"][0])
    lb["subnet_ids"] = [public["id"], private["id"]]
    assert all(e["reachable"] for e in network.exposures(clean_env, lb["id"]))
    lb["subnet_ids"] = [private["id"], public["id"]]
    assert not any(e["reachable"] for e in network.exposures(clean_env, lb["id"]))


def test_egress_profile_details(clean_env):
    inst = pub_instance(clean_env)
    prof = network.egress_profile(clean_env, inst)
    assert prof["route"] == "igw" and prof["has_public_ip"] and prof["open"] and prof["unrestricted"] and prof["world_rules"]
    sg = clean_env.get(inst["sg_ids"][0])
    keep = sg["egress"]
    sg["egress"] = [b.rule("tcp", 443, 443, "0.0.0.0/0")]
    prof = network.egress_profile(clean_env, inst)
    assert prof["open"] and not prof["unrestricted"]
    sg["egress"] = [b.rule("-1", 0, 65535, "10.0.0.0/8")]
    assert not network.egress_profile(clean_env, inst)["open"]
    sg["egress"] = keep
    inst["public_ip"] = None
    assert not network.egress_profile(clean_env, inst)["open"] and not network.egress_profile(clean_env, inst)["has_public_ip"]
    inst["public_ip"] = "1.2.3.4"
    inst["state"] = "stopped"
    assert not network.egress_open(clean_env, inst)
    inst["state"] = "running"
    inst["subnet_id"] = next(s["id"] for s in clean_env.of("subnet") if s["tags"]["tier"] == "private" and s["vpc_id"] == inst["vpc_id"])
    prof = network.egress_profile(clean_env, inst)
    assert prof["route"] == "none" and not prof["open"]


def test_topology_issue_kinds_and_their_fields(clean_env):
    env = clean_env
    assert network.topology_issues(env) == []
    # private tier routed to the internet
    rt = next(r for r in env.of("route_table") if r["name"].endswith("private-rt"))
    run(env, "route.set", rt["id"], destination="0.0.0.0/0", target_type="igw", target=env.get(rt["vpc_id"])["igw_id"])
    issues = [i for i in network.topology_issues(env) if i["kind"] == "private_subnet_public"]
    assert issues and all(i["route_table"] == rt["id"] and i["subnet_id"] for i in issues)
    run(env, "route.delete", rt["id"], destination="0.0.0.0/0")
    # blackhole: detached gateway
    igw = env.get(env.of("vpc")[0]["igw_id"])
    run(env, "igw.detach", igw["id"])
    kinds = {i["kind"] for i in network.topology_issues(env)}
    assert {"blackhole_route", "public_ip_without_route"} <= kinds and "private_subnet_public" not in kinds
    bh = next(i for i in network.topology_issues(env) if i["kind"] == "blackhole_route")
    assert bh["subnet_id"] and bh["route_table"] and "missing or detached" in bh["detail"]
    # running instance with a public IP in an unrouted subnet is flagged; a stopped one is not
    unroutable = [i for i in network.topology_issues(env) if i["kind"] == "public_ip_unroutable"]
    assert unroutable and all(env.get(i["resource_id"])["state"] == "running" and env.get(i["resource_id"])["public_ip"] for i in unroutable)
    for i in unroutable:
        env.get(i["resource_id"])["state"] = "stopped"
    assert not [i for i in network.topology_issues(env) if i["kind"] == "public_ip_unroutable"]


def test_topology_nodes_edges_and_exposure_flags(clean_env):
    env = clean_env
    inst = pub_instance(env)
    run(env, "ec2.terminate", env.of("ec2_instance")[0]["id"]) if env.of("ec2_instance")[0]["id"] != inst["id"] else None
    terminated = next((i for i in env.of("ec2_instance") if i["state"] == "terminated"), None)
    bucket = env.of("s3_bucket")[0]
    bucket["block_public_access"], bucket["acl"] = False, "private"
    topo = network.topology(env)
    node = lambda rid: next(n for n in topo["nodes"] if n["id"] == rid)  # noqa: E731
    assert node(bucket["id"])["exposed"] is False
    bucket["policy_public"] = True
    assert next(n for n in network.topology(env)["nodes"] if n["id"] == bucket["id"])["exposed"] is True
    bucket["block_public_access"] = True
    assert next(n for n in network.topology(env)["nodes"] if n["id"] == bucket["id"])["exposed"] is False
    topo = network.topology(env)
    if terminated:
        assert all(n["id"] != terminated["id"] for n in topo["nodes"])
    lb = env.of("load_balancer")[0]
    assert node(lb["id"])["parent"] == lb["subnet_ids"][0]
    eip = next(e for e in env.of("elastic_ip") if e["instance_id"])
    assert node(eip["id"])["label"] == eip["public_ip"]
    assert {"source": eip["id"], "target": eip["instance_id"], "kind": "associated"} in topo["edges"]
    unattached = next(e for e in env.of("elastic_ip") if not e["instance_id"])
    assert not [e for e in topo["edges"] if e["source"] == unattached["id"]]
    assert {n["id"] for n in topo["nodes"] if n["type"] == "iam_role"} == {r["id"] for r in env.of("iam_role")}
    assert topo["summary"]["public_subnets"] == sum(1 for s in env.of("subnet") if network.subnet_is_public(env, s))
    lb_empty = env.of("load_balancer")[0]
    lb_empty["subnet_ids"] = []
    assert next(n for n in network.topology(env)["nodes"] if n["id"] == lb_empty["id"])["parent"] == lb_empty["vpc_id"]


def test_explain_reachability_shapes_and_errors(clean_env):
    env = clean_env
    with pytest.raises(SimError) as exc:
        network.explain_reachability(env, env.of("vpc")[0]["id"])
    assert exc.value.status == 422 and exc.value.code == "unsupported"
    inst = pub_instance(env)
    out = network.explain_reachability(env, inst["id"])
    assert out["resource_type"] == "ec2_instance" and "egress" in out and out["internet_reachable"] is True
    run(env, "sg.create", None, vpc_id=inst["vpc_id"], name="w")
    db = env.of("rds_instance")[0]
    out = network.explain_reachability(env, db["id"])
    assert "egress" not in out and out["resource_type"] == "rds_instance"
    assert network.port_label(22) == "SSH" and network.port_label(9999) == "9999"


# ======================================================================== IAM
def add_role(env, name, trust, policies=(), tags=None):
    return env.add("iam_role", {"id": f"role:{name}", "name": name, "trust": trust, "policy_ids": list(policies), "state": "active",
                                "tags": tags or {}, "created_at": iso(env.sim_time), "last_used": None, "region": "global"})


def add_user(env, name, policies=()):
    return env.add("iam_user", {"id": f"user:{name}", "name": name, "console_access": True, "mfa_enabled": True, "access_keys": [],
                                "policy_ids": list(policies), "kind": "developer", "state": "active", "tags": {}, "created_at": iso(env.sim_time),
                                "region": "global"})


def test_arn_format_and_trust_clauses_are_independent(clean_env):
    env = clean_env
    alice = add_user(env, "alice-t")
    bob = add_user(env, "bob-t")
    assert iam.arn(env, alice) == f"arn:aws:iam::{env.account_id}:user/alice-t"
    assert iam.arn(env, env.get("role:deploy-role")) == f"arn:aws:iam::{env.account_id}:role/deploy-role"
    r = add_role(env, "t1", [{"type": "AWS", "value": "*"}])
    assert iam.trust_match(env, r, alice) == (True, False)
    r["trust"] = [{"type": "AWS", "value": alice["id"]}]
    assert iam.trust_match(env, r, alice) == (True, False) and iam.trust_match(env, r, bob) == (False, False)
    r["trust"] = [{"type": "AWS", "value": iam.arn(env, alice)}]
    assert iam.trust_match(env, r, alice) == (True, False) and iam.trust_match(env, r, bob) == (False, False)
    r["trust"] = [{"type": "AWS", "value": env.account_id}]
    assert iam.trust_match(env, r, alice) == (True, True)
    r["trust"] = [{"type": "Service", "value": "ec2.amazonaws.com"}]
    assert iam.trust_match(env, r, alice) == (False, False)
    for junk in ("000000000000", "AAAA", "zzzz", "user:aaa", "user:zzz"):     # strings ordered before and after the principal id
        r["trust"] = [{"type": "AWS", "value": junk}]
        assert iam.trust_match(env, r, alice) == (False, False), junk


def test_risky_trust_detection_is_exact(clean_env):
    env = clean_env
    r = add_role(env, "t2", [{"type": "AWS", "value": env.account_id}])
    assert iam.risky_trusts(env, r) == []
    r["trust"] = [{"type": "AWS", "value": "".join(list(env.account_id))}]        # equal text, different object
    assert iam.risky_trusts(env, r) == []
    r["trust"] = [{"type": "Service", "value": "*"}, {"type": "AWS", "value": "user:someone"}]
    assert iam.risky_trusts(env, r) == []
    r["trust"] = [{"type": "AWS", "value": "*"}, {"type": "AWS", "value": "999988887777"}]
    found = iam.risky_trusts(env, r)
    assert [x["principal"] for x in found] == ["*", "999988887777"] and "any AWS principal" in found[0]["reason"] and "external account" in found[1]["reason"]


def test_access_key_unused_threshold_is_inclusive_at_60_days(clean_env):
    env = clean_env
    user = next(u for u in env.of("iam_user") if u["access_keys"])
    key = user["access_keys"][0]
    key["created_at"] = iso(env.sim_time - timedelta(days=10))
    for days, flagged in ((59, False), (60, True), (61, True)):
        key["last_used"] = iso(env.sim_time - timedelta(days=days))
        rep = iam.key_report(env, user)[0]
        assert bool(rep["reasons"]) is flagged and rep["unused_days"] == days
    key["last_used"] = None
    assert iam.key_report(env, user)[0]["unused_days"] is None
    key["last_used"] = iso(env.sim_time - timedelta(days=80))
    key["status"] = "inactive"
    assert iam.key_report(env, user)[0]["reasons"] == []
    key["status"] = "active"
    key["created_at"] = iso(env.sim_time - timedelta(days=env.config["iam"]["access_key_max_age_days"]))
    key["last_used"] = iso(env.sim_time)
    assert iam.key_report(env, user)[0]["reasons"] == []                           # exactly at the limit is fine
    key["created_at"] = iso(env.sim_time - timedelta(days=env.config["iam"]["access_key_max_age_days"] + 1))
    assert "days old" in iam.key_report(env, user)[0]["reasons"][0]


def test_escalation_depth_limit_and_path_contents(clean_env):
    env = clean_env
    u = add_user(env, "climber")
    admin = add_role(env, "boss", [{"type": "AWS", "value": "role:h3"}], ["policy:AdministratorAccess"])
    add_role(env, "h1", [{"type": "AWS", "value": u["id"]}])
    add_role(env, "h2", [{"type": "AWS", "value": "role:h1"}])
    add_role(env, "h3", [{"type": "AWS", "value": "role:h2"}])
    paths = [p for p in iam.escalation_paths(env) if p["origin"] == u["id"]]
    assert len(paths) == 1 and paths[0]["target"] == admin["id"]
    assert [s["target"] for s in paths[0]["steps"]] == ["role:h1", "role:h2", "role:h3", "role:boss"] and len(paths[0]["steps"]) == 4
    assert paths[0]["description"].startswith(u["id"] + " -> role:h1")
    admin["trust"] = [{"type": "AWS", "value": "role:h4"}]                          # one hop further than the limit
    add_role(env, "h4", [{"type": "AWS", "value": "role:h3"}])
    assert [p for p in iam.escalation_paths(env) if p["origin"] == u["id"]] == []


def test_every_origin_is_reported_and_roles_cannot_assume_themselves(clean_env):
    env = clean_env
    boss = add_role(env, "boss2", [{"type": "AWS", "value": "*"}], ["policy:AdministratorAccess"])
    users = [add_user(env, f"w{i}") for i in range(3)]
    origins = {p["origin"] for p in iam.escalation_paths(env)}
    assert {u["id"] for u in users} <= origins
    selfy = add_role(env, "selfy", [{"type": "AWS", "value": env.account_id}])
    run(env, "iam.create_policy", None, name="AssumeSelf", effect="Allow", actions=["sts:AssumeRole"], resources=[iam.arn(env, selfy)])
    run(env, "iam.attach_policy", selfy["id"], policy_id="policy:AssumeSelf")
    assert not [e for e in iam.escalation_edges(env) if e["source"] == e["target"]]
    assert boss["id"] in iam.analyze(env)["admin_principals"]


def test_passrole_edges_only_reach_roles_that_ec2_can_assume(clean_env):
    env = clean_env
    run(env, "iam.create_policy", None, name="PassAndRun", effect="Allow", actions=["iam:PassRole", "ec2:RunInstances"], resources=["*"])
    u = add_user(env, "passer", ["policy:PassAndRun"])
    add_role(env, "ec2ish", [{"type": "Service", "value": "ec2.amazonaws.com"}])
    add_role(env, "lambdaish", [{"type": "Service", "value": "lambda.amazonaws.com"}])
    targets = {e["target"] for e in iam.escalation_edges(env) if e["source"] == u["id"]}
    assert "role:ec2ish" in targets and "role:lambdaish" not in targets
    only_run = add_user(env, "runner")
    run(env, "iam.create_policy", None, name="OnlyRun", effect="Allow", actions=["ec2:RunInstances"], resources=["*"])
    run(env, "iam.attach_policy", only_run["id"], policy_id="policy:OnlyRun")
    assert not [e for e in iam.escalation_edges(env) if e["source"] == only_run["id"]]


def test_analysis_rows_graph_and_summary_counts(clean_env):
    env = clean_env
    run(env, "iam.create_policy", None, name="Editor", effect="Allow", actions=["iam:PutUserPolicy"], resources=["*"])
    u = add_user(env, "editor-user", ["policy:Editor"])
    for name in ("m1", "m2"):
        add_user(env, name)["mfa_enabled"] = False
    a = iam.analyze(env)
    admin_node = next(n for n in a["graph"]["nodes"] if n["id"] == iam.ADMIN)
    assert admin_node["admin"] is True and admin_node["type"] == "virtual"
    on_path = [e for e in a["graph"]["edges"] if e["on_escalation_path"]]
    assert any(e["source"] == u["id"] and e["target"] == iam.ADMIN for e in on_path)
    assert all("on_escalation_path" in e for e in a["graph"]["edges"])
    assert a["summary"]["users_without_mfa"] == 2 and a["summary"]["escalation_paths"] == len(a["escalation_paths"])
    row = next(r for r in a["principals"] if r["id"] == "user:editor-user")
    assert row["type"] == "iam_user" and row["console_access"] and "keys" in row and "trust" not in row
    role_row = next(r for r in a["principals"] if r["id"] == "role:deploy-role")
    assert role_row["designated_admin"] is False and "trust" in role_row and "keys" not in role_row
    admin_user = next(r for r in a["principals"] if r["designated_admin"])
    assert admin_user["admin"] and admin_user["admin_policies"] == ["policy:AdministratorAccess"]
    env2 = env.copy()
    for e in iam.escalation_edges(env2):
        pass
    clean_without_write = iam.analyze(clean_env.copy())
    assert any(n["id"] == iam.ADMIN for n in clean_without_write["graph"]["nodes"])


def test_virtual_admin_node_exists_only_while_someone_can_write_iam(clean_base):
    env = clean_base.copy()
    assert any(n["id"] == iam.ADMIN for n in iam.analyze(env)["graph"]["nodes"])
    for p in env.of("iam_user") + env.of("iam_role"):
        p["policy_ids"] = []
    assert not any(n["id"] == iam.ADMIN for n in iam.analyze(env)["graph"]["nodes"])


# ======================================================================= cost
def test_run_rate_is_rounded_to_cents_and_consistent(env):
    rate = cost.monthly_run_rate(env)
    assert all(round(v, 2) == v for v in rate["by_service"].values()) and round(rate["total"], 2) == rate["total"]
    assert rate["total"] == round(sum(rate["by_service"].values()), 1) or abs(rate["total"] - sum(rate["by_service"].values())) < 0.1
    assert all(round(v, 2) == v for v in rate["by_resource"].values())
    assert list(rate["by_service"].values()) == sorted(rate["by_service"].values(), reverse=True)
    inst = env.of("ec2_instance")[0]
    assert cost.resource_monthly(env, inst) == round(cost.resource_monthly(env, inst), 2)


def test_history_defaults_to_30_days_and_is_ordered(env):
    timeengine.advance(env, 5)
    assert len(cost.history(env)) == 30 and len(cost.history(env, 7)) == 7 and len(cost.history(env, 500)) == len(env.daily_costs)
    dates = [h["date"] for h in cost.history(env)]
    assert dates == sorted(dates) and dates[-1] == (env.today - timedelta(days=1)).isoformat()
    for h in cost.history(env, 3):
        assert h["total"] == round(sum(h["by_service"].values()), 4) or abs(h["total"] - sum(h["by_service"].values())) < 0.001


def test_anomaly_numbers_match_an_independent_calculation(env):
    scenarios.trigger(env, "cost_spike")
    timeengine.advance(env, 2)
    rows = cost.history(env, 120)
    totals = [(r["date"], r["total"]) for r in rows]
    anomalies = [a for a in cost.detect_anomalies(env) if a["scope"] == "total"]
    assert anomalies and [a["date"] for a in anomalies] == sorted((a["date"] for a in anomalies), reverse=True)
    a = anomalies[-1]
    i = next(k for k, (d, _) in enumerate(totals) if d == a["date"])
    window = [v for _, v in totals[max(0, i - 14):i]]
    mean = statistics.fmean(window)
    std = max(statistics.pstdev(window), 0.05 * mean)
    value = totals[i][1]
    assert a["value"] == round(value, 2) and a["baseline_mean"] == round(mean, 2) and a["baseline_std"] == round(std, 2)
    assert a["zscore"] == round((value - mean) / std, 2) and a["increase_pct"] == round((value / mean - 1) * 100, 1)
    assert a["active"] is (a["date"] >= (env.today - timedelta(days=3)).isoformat())
    for c in a["top_contributors"]:
        assert abs(c["increase"] - (c["cost"] - c["baseline"])) <= 0.011 and c["increase"] > 0
    prior = [d for d, _ in totals[max(0, i - 14):i]]
    top = a["top_contributors"][0]
    base = sum(sum(env.daily_costs.get(d, {}).get(top["resource_id"], {}).values()) for d in prior) / len(prior)
    assert top["baseline"] == round(base, 2)
    assert [c["increase"] for c in a["top_contributors"]] == sorted((c["increase"] for c in a["top_contributors"]), reverse=True)


def test_anomalies_need_eight_days_and_old_ones_become_inactive():
    from app.simulator.config import SimConfig
    from app.simulator.generator import generate_environment
    env = generate_environment(SimConfig.model_validate({"time": {"history_days": 7}}))
    scenarios.trigger(env, "cost_spike")
    timeengine.advance(env, 1)                      # exactly 8 daily rows: the first day on which detection is possible
    assert len(env.daily_costs) == 8 and [a for a in cost.detect_anomalies(env) if a["scope"] == "total"]
    timeengine.advance(env, 6)
    old = [a for a in cost.detect_anomalies(env) if a["scope"] == "total" and a["date"] < (env.today - timedelta(days=3)).isoformat()]
    assert old and all(a["active"] is False for a in old)
    short = generate_environment(SimConfig.model_validate({"time": {"history_days": 6}}))
    assert cost.detect_anomalies(short) == []


def test_summary_top_resources_are_sorted_and_limited(env):
    s = cost.summary(env)
    values = [r["monthly"] for r in s["top_resources"]]
    assert values == sorted(values, reverse=True) and len(values) == 8
    assert s["last_30_days_total"] == round(sum(r["total"] for r in cost.history(env, 30)), 2)


# =============================================================== optimisation
def test_stats_are_rounded_and_respect_the_window_and_resize_marker(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running")
    set_series(env, inst["id"], "cpu", [1.234, 5.678, 3.0, 9.999, 2.5, 4.4, 6.666])
    st = optimization.stats(env, inst["id"], "cpu", 14)
    assert st == {"avg": round(sum([1.234, 5.678, 3.0, 9.999, 2.5, 4.4, 6.666]) / 7, 2), "max": 9.999 and round(9.999, 2), "min": 1.23, "days": 7}
    assert optimization.stats(env, inst["id"], "cpu", 3) is None                      # fewer than five points in the window
    cutoff = (env.today - timedelta(days=4)).isoformat() + "T00:00:00"
    assert optimization.stats(env, inst["id"], "cpu", 14, since=cutoff) is None       # points before the resize are ignored
    assert optimization.stats(env, inst["id"], "cpu", 14, since=(env.today - timedelta(days=5)).isoformat())["days"] == 5


def test_priority_boundaries():
    assert optimization._priority(100) == "HIGH" and optimization._priority(99.99) == "MEDIUM"
    assert optimization._priority(20) == "MEDIUM" and optimization._priority(19.99) == "LOW"


def test_idle_instance_thresholds_are_strict(env):
    inst = next(i for i in env.of("ec2_instance") if i["state"] == "running" and i["profile"] == "busy")
    th = env.thresholds
    avg, mx = th["idle_cpu_avg_pct"], th["idle_cpu_max_pct"]
    flat(env, inst["id"], avg - 0.01, mx - 0.01)
    assert recs(env, "OPT-001", resource_id=inst["id"])
    flat(env, inst["id"], avg, mx - 0.01)
    assert not recs(env, "OPT-001", resource_id=inst["id"])                              # average at the limit is not idle
    flat(env, inst["id"], avg - 0.01, mx)
    assert not recs(env, "OPT-001", resource_id=inst["id"])                              # peak at the limit is not idle
    flat(env, inst["id"], avg - 0.01, mx - 0.01, net=2.0)
    assert not recs(env, "OPT-001", resource_id=inst["id"])                              # busy network is not idle
    flat(env, inst["id"], avg - 0.01, mx - 0.01, net=1.99)
    (r,) = recs(env, "OPT-001", resource_id=inst["id"])
    assert r["confidence"] == 0.9 and r["priority"] == optimization._priority(r["estimated_monthly_savings"]) and r["type"] == "Idle instance"
    assert r["evidence"]["days_observed"] == 14 and r["current_monthly_cost"] == round(cost.monthly_run_rate(env)["by_resource"][inst["id"]], 2)


def make_instance(env, itype, **kw):
    sub = next(s for s in env.of("subnet") if s["tags"]["tier"] == "private")
    sg = next(s["id"] for s in env.of("security_group") if s["vpc_id"] == sub["vpc_id"] and s["name"].endswith("app-sg"))
    res = run(env, "ec2.create", None, subnet_id=sub["id"], instance_type="t3.small", sg_ids=[sg], **kw)
    inst = env.get(res["created"][0])
    inst["state"], inst["instance_type"] = "running", itype
    return inst


def test_rightsizing_boundaries_for_cpu_peak_and_memory(clean_env):
    env = clean_env
    inst = make_instance(env, "m5.2xlarge")                                  # 8 vCPU / 32 GiB; one size down = m5.xlarge (4 / 16)
    th = env.thresholds
    flat(env, inst["id"], 15.0, 20.0)
    (r,) = recs(env, "OPT-002", resource_id=inst["id"])
    assert r["evidence"]["proposed_type"] == "m5.large"                       # 15% * 8/2 = 60% (limit is inclusive), 20% * 4 = 80% (inclusive)
    assert r["evidence"]["projected_cpu_avg_pct"] == 60.0 and r["evidence"]["projected_cpu_max_pct"] == 80.0
    flat(env, inst["id"], 15.01, 20.0)
    assert recs(env, "OPT-002", resource_id=inst["id"])[0]["evidence"]["proposed_type"] == "m5.xlarge"       # average would exceed 60%
    flat(env, inst["id"], 15.0, 20.01)
    assert recs(env, "OPT-002", resource_id=inst["id"])[0]["evidence"]["proposed_type"] == "m5.xlarge"       # peak would exceed 80%
    flat(env, inst["id"], 10.0, 15.0, mem=40.0)
    assert recs(env, "OPT-002", resource_id=inst["id"])[0]["evidence"]["proposed_type"] == "m5.xlarge"   # 40% * 2 = 80% fits exactly
    flat(env, inst["id"], 10.0, 15.0, mem=40.01)
    assert not recs(env, "OPT-002", resource_id=inst["id"])                                              # 80.02% fits nowhere
    flat(env, inst["id"], 10.0, 15.0, mem=25.0)                                # memory 25% * 32/8 = 100% > 80% on m5.large (8 GiB)
    assert recs(env, "OPT-002", resource_id=inst["id"])[0]["evidence"]["proposed_type"] == "m5.xlarge"       # 25% * 32/16 = 50%
    flat(env, inst["id"], 10.0, 15.0, mem=20.0)                                # 20% * 4 = 80% fits exactly
    assert recs(env, "OPT-002", resource_id=inst["id"])[0]["evidence"]["proposed_type"] == "m5.large"
    flat(env, inst["id"], 10.0, 15.0, mem=20.1)
    assert recs(env, "OPT-002", resource_id=inst["id"])[0]["evidence"]["proposed_type"] == "m5.xlarge"
    flat(env, inst["id"], th["underutilized_cpu_avg_pct"] - 0.01, th["underutilized_cpu_max_pct"])    # peak at the limit: no recommendation
    assert not recs(env, "OPT-002", resource_id=inst["id"])
    flat(env, inst["id"], th["underutilized_cpu_avg_pct"], th["underutilized_cpu_max_pct"] - 0.01)
    assert not recs(env, "OPT-002", resource_id=inst["id"])
    flat(env, inst["id"], 5.0, 50.0)
    assert not recs(env, "OPT-002", resource_id=inst["id"])                    # low average alone is not enough
    flat(env, inst["id"], 5.0, 10.0)
    r = recs(env, "OPT-002", resource_id=inst["id"])[0]
    assert r["evidence"]["projected_cpu_max_pct"] == round(10.0 * 8 / 2, 1) and r["confidence"] == 0.8 and r["type"] == "Oversized instance"
    assert [o["action"] for o in r["remediation"]["operations"]] == ["ec2.stop", "ec2.change_type", "ec2.start"]


def test_cheapest_candidate_wins_and_smallest_size_has_no_recommendation(clean_env):
    env = clean_env
    inst = make_instance(env, "t3.micro")
    flat(env, inst["id"], 2.0, 3.0)
    assert not recs(env, "OPT-002", resource_id=inst["id"])
    inst2 = make_instance(env, "c5.2xlarge")
    flat(env, inst2["id"], 5.0, 8.0)
    assert recs(env, "OPT-002", resource_id=inst2["id"])[0]["evidence"]["proposed_type"] == "c5.large"


def test_snapshot_age_boundary_and_sibling_rules(env):
    vol = run(env, "ebs.create", None, size_gb=10, az="us-east-1a")["created"][0]
    old, newer = run(env, "snapshot.create", vol)["created"][0], run(env, "snapshot.create", vol)["created"][0]
    limit = env.thresholds["old_snapshot_days"]
    env.get(old)["created_at"] = iso(env.sim_time - timedelta(days=limit))
    env.get(newer)["created_at"] = iso(env.sim_time - timedelta(days=1))
    assert not recs(env, "OPT-004", resource_id=old)                                    # exactly at the limit is not old
    env.get(old)["created_at"] = iso(env.sim_time - timedelta(days=limit + 1))
    (r,) = recs(env, "OPT-004", resource_id=old)
    assert r["evidence"]["newer_snapshots"] == 1 and r["evidence"]["age_days"] == limit + 1 and r["confidence"] == 0.8
    env.get(newer)["created_at"] = iso(env.sim_time - timedelta(days=limit + 2))         # the "newer" copy is now older
    assert not recs(env, "OPT-004", resource_id=old)
    assert recs(env, "OPT-004", resource_id=newer) == [] or recs(env, "OPT-004", resource_id=newer)[0]["evidence"]["newer_snapshots"] == 1


def test_database_downsizing_boundaries(clean_env):
    env = clean_env
    db = env.of("rds_instance")[0]
    db.update(instance_class="db.m5.2xlarge", state="available", multi_az=False)
    flat(env, db["id"], 7.5, 20.0, mem=10.0)
    (r,) = recs(env, "OPT-006", resource_id=db["id"])
    assert r["evidence"]["proposed_class"] == "db.t3.medium" and r["confidence"] == 0.75        # 7.5*8/2 = 30%, memory 10% * 32/4 = 80% (inclusive)
    flat(env, db["id"], 7.5, 20.0, mem=10.5)
    assert recs(env, "OPT-006", resource_id=db["id"])[0]["evidence"]["proposed_class"] == "db.t3.large"
    flat(env, db["id"], 14.99, 39.99, mem=5.0)
    assert recs(env, "OPT-006", resource_id=db["id"])
    flat(env, db["id"], 15.0, 20.0, mem=5.0)
    assert not recs(env, "OPT-006", resource_id=db["id"])                                       # average at the limit
    flat(env, db["id"], 7.0, 40.0, mem=5.0)
    assert not recs(env, "OPT-006", resource_id=db["id"])                                       # peak at the limit
    flat(env, db["id"], 14.0, 39.0, mem=5.0)
    assert not [x for x in recs(env, "OPT-006", resource_id=db["id"]) if x["evidence"]["proposed_class"] == db["instance_class"]]
    db["state"] = "stopped"
    assert not recs(env, "OPT-006", resource_id=db["id"])
    db["state"] = "available"
    db["multi_az"] = True
    flat(env, db["id"], 7.5, 20.0, mem=10.0)
    saving = recs(env, "OPT-006", resource_id=db["id"])[0]["estimated_monthly_savings"]
    db["multi_az"] = False
    assert saving == pytest.approx(2 * recs(env, "OPT-006", resource_id=db["id"])[0]["estimated_monthly_savings"], abs=0.02)


def test_long_stopped_instances_use_root_volume_savings_and_a_30_day_boundary(clean_env):
    env = clean_env
    inst = make_instance(env, "t3.small")
    run(env, "ebs.create", None, size_gb=500, az=inst["az"], name="data")
    data = next(v for v in env.of("ebs_volume") if v["name"] == "data")
    run(env, "ebs.attach", data["id"], instance_id=inst["id"], device="/dev/sdh")
    run(env, "ec2.stop", inst["id"])
    for days, flagged in ((29, False), (30, True)):
        inst["stopped_at"] = iso(env.sim_time - timedelta(days=days))
        assert bool(recs(env, "OPT-007", resource_id=inst["id"])) is flagged
    (r,) = recs(env, "OPT-007", resource_id=inst["id"])
    root = env.get(inst["volume_ids"][0])
    from app.simulator import billing
    assert r["estimated_monthly_savings"] == pytest.approx(billing.fixed_daily(env, root)["EBS"] * 30, abs=0.01)
    assert r["current_monthly_cost"] == pytest.approx(sum(billing.fixed_daily(env, env.get(v))["EBS"] * 30 for v in inst["volume_ids"]), abs=0.01)
    assert r["confidence"] == 0.7


def test_idle_load_balancer_needs_a_running_target_and_savings_are_monthly(env):
    from app.simulator import billing
    lb = next(l for l in env.of("load_balancer") if l["targets"])
    assert not recs(env, "OPT-008", resource_id=lb["id"])
    for t in lb["targets"]:
        env.get(t)["state"] = "stopped"
    (r,) = recs(env, "OPT-008", resource_id=lb["id"])
    assert r["estimated_monthly_savings"] == pytest.approx(billing.fixed_daily(env, lb)["Load Balancing"] * 30, abs=0.01) and r["confidence"] == 0.85
    lb["targets"] = ["i-ghost"]
    assert recs(env, "OPT-008", resource_id=lb["id"])


def test_cost_growth_recommendation_covers_top_three_contributors(env):
    scenarios.trigger(env, "cost_spike")
    timeengine.advance(env, 2)
    growth = [r for r in optimization.recommend(env) if r["rule_id"] == "OPT-009"]
    assert growth and all(r["remediation"]["supported"] is False and r["confidence"] == 0.6 for r in growth)
    by_day = {}
    for r in growth:
        by_day[r["evidence"]["anomaly_date"]] = by_day.get(r["evidence"]["anomaly_date"], 0) + 1
    assert max(by_day.values()) == 3                                                     # at most the top three per anomaly day
    for r in growth:
        assert r["estimated_monthly_savings"] == pytest.approx((r["evidence"]["daily_cost"] - r["evidence"]["baseline_daily_cost"]) * 30, abs=0.5)
    anomalies = cost.detect_anomalies(env)
    for a in anomalies:
        a["active"] = False
    assert [r for r in optimization.recommend(env, anomalies) if r["rule_id"] == "OPT-009"] == []
    for a in anomalies:
        a["active"], a["scope"] = True, "EC2"
    assert [r for r in optimization.recommend(env, anomalies) if r["rule_id"] == "OPT-009"] == []


def test_unattached_eip_and_stopped_attachment_are_both_flagged(env):
    eip = next(e for e in env.of("elastic_ip") if e["instance_id"])
    assert not recs(env, "OPT-005", resource_id=eip["id"])
    env.get(eip["instance_id"])["state"] = "stopped"
    (r,) = recs(env, "OPT-005", resource_id=eip["id"])
    assert [o["action"] for o in r["remediation"]["operations"]] == ["eip.disassociate", "eip.release"]


# ===================================================================== security
def sec(env, rule):
    return [f for f in security.evaluate(env) if f["rule_id"] == rule]


def test_telnet_smb_and_database_ports_each_trigger_the_database_rule(clean_env):
    env = clean_env
    inst = pub_instance(env)
    for port in (23, 445, 3306, 5432, 1433, 6379, 9200, 27017):
        sg = run(env, "sg.create", None, vpc_id=inst["vpc_id"], name=f"p{port}")["created"][0]
        run(env, "sg.authorize_ingress", sg, protocol="tcp", from_port=port, to_port=port, cidr="0.0.0.0/0")
        run(env, "ec2.set_security_groups", inst["id"], sg_ids=inst["sg_ids"][:1] + [sg])
        found = [f for f in sec(env, "NET-003") if f["evidence"]["security_group"] == sg]
        assert len(found) == 1 and found[0]["evidence"]["ports"] == [port], port
    sg = run(env, "sg.create", None, vpc_id=inst["vpc_id"], name="p22")["created"][0]
    run(env, "sg.authorize_ingress", sg, protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0")
    run(env, "ec2.set_security_groups", inst["id"], sg_ids=inst["sg_ids"][:1] + [sg])
    assert [f for f in sec(env, "NET-003") if f["evidence"]["security_group"] == sg] == []


@pytest.mark.parametrize("target,env_tag,expected,reason", [
    ("instance", "dev", "HIGH", "base severity HIGH"), ("instance", "prod", "CRITICAL", "prod"),
    ("database", "dev", "CRITICAL", "database"), ("database", "prod", "CRITICAL", "database")])
def test_database_port_severity_matrix(clean_env, target, env_tag, expected, reason):
    env = clean_env
    if target == "instance":
        res = pub_instance(env)
        sg = run(env, "sg.create", None, vpc_id=res["vpc_id"], name="db-open")["created"][0]
        run(env, "sg.authorize_ingress", sg, protocol="tcp", from_port=3306, to_port=3306, cidr="0.0.0.0/0")
        run(env, "ec2.set_security_groups", res["id"], sg_ids=res["sg_ids"][:1] + [sg])
    else:
        scenarios.trigger(env, "risky_network")
        res = next(d for d in env.of("rds_instance") if d["publicly_accessible"])
    res["tags"]["environment"] = env_tag
    f = next(x for x in sec(env, "NET-003") if x["resource_id"] == res["id"])
    assert f["severity"] == expected and reason in f["severity_reason"]


def test_non_sensitive_world_rules_do_not_create_latent_findings_and_routing_issues_do(clean_env):
    env = clean_env
    assert sec(env, "NET-005") == []
    rt = next(r for r in env.of("route_table") if r["name"].endswith("private-rt"))
    run(env, "route.set", rt["id"], destination="0.0.0.0/0", target_type="igw", target=env.get(rt["vpc_id"])["igw_id"])
    nets = sec(env, "NET-006")
    assert nets and all(f["remediation"]["operations"][0]["action"] == "route.delete" and f["resource_type"] == "subnet" for f in nets)
    run(env, "route.delete", rt["id"], destination="0.0.0.0/0")
    run(env, "igw.detach", env.get(rt["vpc_id"])["igw_id"])
    latent = sec(env, "NET-005")
    assert latent and all(f["severity"] == "LOW" and f["remediation"]["supported"] is False for f in latent)
    kinds = {f["evidence"]["kind"] for f in latent if "kind" in f["evidence"]}
    assert {"blackhole_route", "public_ip_without_route"} <= kinds
    unroutable = [f for f in latent if f["evidence"].get("kind") == "public_ip_unroutable"]
    assert unroutable and all(f["resource_type"] == "ec2_instance" for f in unroutable)
    assert all(f["resource_type"] == "subnet" for f in latent if f["evidence"].get("kind") in ("blackhole_route", "public_ip_without_route"))


def test_outbound_traffic_windows_and_boundaries(clean_env):
    env = clean_env
    inst = pub_instance(env)
    factor = env.thresholds["traffic_spike_factor"]
    base, spike = 2.0, 2.0 * factor
    set_series(env, inst["id"], "net_out_gb", [base] * 3 + [spike] * 3)
    (f,) = sec(env, "NET-008")
    assert f["evidence"]["recent_avg_gb"] == spike and f["evidence"]["baseline_avg_gb"] == base and f["evidence"]["ratio"] == factor
    assert f"({factor:.0f}x)" in f["explanation"] and len(f["evidence"]["daily_net_out_gb"]) == 6
    set_series(env, inst["id"], "net_out_gb", [base] * 3 + [spike - 0.01] * 3)
    assert sec(env, "NET-008") == []                                                       # just under the factor
    set_series(env, inst["id"], "net_out_gb", [base] * 5)
    assert sec(env, "NET-008") == []                                                       # fewer than six points
    # the baseline is the 14 days before the last 3; older points must not count, and only the last 3 are "recent"
    set_series(env, inst["id"], "net_out_gb", [100.0] * 5 + [base] * 14 + [spike] * 3)
    (f,) = sec(env, "NET-008")
    assert f["evidence"]["baseline_avg_gb"] == base and f["evidence"]["recent_avg_gb"] == spike
    set_series(env, inst["id"], "net_out_gb", [base] * 14 + [spike] * 2 + [base])
    assert sec(env, "NET-008") == []
    set_series(env, inst["id"], "net_out_gb", [0.0] * 3 + [spike] * 3)
    assert sec(env, "NET-008") == []                                                       # zero baseline never divides


def test_s3_confidentiality_and_encryption_severity(clean_env):
    env = clean_env
    bucket = next(b_ for b_ in env.of("s3_bucket") if b_["tags"].get("data_classification") == "internal")
    bucket["tags"]["data_classification"] = "archive"                                     # sorts before "confidential"
    run(env, "s3.set_public_access_block", bucket["id"], block=False)
    run(env, "s3.set_acl", bucket["id"], acl="public-read")
    bucket["encryption"] = "none"
    (pub,) = [f for f in sec(env, "S3-001") if f["resource_id"] == bucket["id"]]
    (enc,) = [f for f in sec(env, "ENC-002") if f["resource_id"] == bucket["id"]]
    assert pub["severity"] == "HIGH" and pub["severity_reason"] == "base severity HIGH" and enc["severity"] == "MEDIUM"
    bucket["tags"]["data_classification"] = "confidential"
    assert [f for f in sec(env, "S3-001")][0]["severity"] == "CRITICAL"
    assert next(f for f in sec(env, "ENC-002") if f["resource_id"] == bucket["id"])["severity"] == "HIGH"


def test_encryption_and_backup_severity_rules(clean_env):
    env = clean_env
    db = next(d for d in env.of("rds_instance") if d["tags"]["environment"] == "prod")
    db["storage_encrypted"] = False
    assert sec(env, "ENC-003")[0]["severity"] == "HIGH" and "prod" not in sec(env, "ENC-003")[0]["severity_reason"]
    db["backup_retention_days"] = 0
    assert sec(env, "BKP-001")[0]["severity"] == "HIGH"
    db["tags"]["environment"] = "dev"
    assert sec(env, "BKP-001")[0]["severity"] == "MEDIUM"
    vol = next(v for v in env.of("ebs_volume") if v["attached_to"] and v["tags"].get("environment") == "prod")
    for policy in ("daily", "weekly"):
        vol["backup_policy"] = policy
        assert [f for f in sec(env, "BKP-002") if f["resource_id"] == vol["id"]] == []
    vol["backup_policy"] = "none"
    for s_ in [s for s in env.of("snapshot") if s["volume_id"] == vol["id"]]:
        env.remove(s_["id"])
    assert [f for f in sec(env, "BKP-002") if f["resource_id"] == vol["id"]]


def test_escalation_findings_describe_origins_and_plans(clean_env):
    env = clean_env
    run(env, "iam.attach_policy", "role:deploy-role", policy_id="policy:AdministratorAccess")
    (f,) = sec(env, "IAM-005")
    n = len(f["evidence"]["origins"])
    assert f["title"] == f"{n} identities can escalate to deploy-role" and f["remediation"]["supported"] is True
    assert f["remediation"]["operations"][0]["action"] == "iam.detach_policy"
    if n > 3:
        assert f"and {n - 3} more" in f["explanation"]
    else:
        assert "more" not in f["explanation"]
    # a single origin uses the singular form; a designated admin end-point has only a manual plan
    env2 = clean_env.copy()
    only = add_user(env2, "solo")
    for u in env2.of("iam_user"):
        if u["id"] != only["id"] and u["kind"] != "admin":
            u["policy_ids"] = []
    for r in env2.of("iam_role"):
        r["trust"] = [{"type": "Service", "value": "ec2.amazonaws.com"}] if r["name"] == "ec2-app-role" else [{"type": "AWS", "value": "role:none"}]
    add_role(env2, "stepping", [{"type": "AWS", "value": only["id"]}])
    env2.get("role:admin-role")["trust"] = [{"type": "AWS", "value": "role:stepping"}]
    found = sec(env2, "IAM-005")
    assert [x["title"] for x in found] == ["2 identities can escalate to admin-role"]
    env2.get("role:admin-role")["trust"] = [{"type": "AWS", "value": only["id"]}]
    found = sec(env2, "IAM-005")
    assert [x["title"] for x in found] == ["1 identity can escalate to admin-role"]
    assert found[0]["remediation"]["supported"] is False and "explanation" in found[0]
    # IAM-write permission ends at the virtual administrator node
    run(env2, "iam.create_policy", None, name="Editor2", effect="Allow", actions=["iam:AttachRolePolicy"], resources=["*"])
    writer = add_user(env2, "writer")
    run(env2, "iam.attach_policy", writer["id"], policy_id="policy:Editor2")
    virtual = [x for x in sec(env2, "IAM-005") if x["resource_id"] == iam.ADMIN]
    assert virtual and virtual[0]["evidence"]["origins"] == [writer["id"]] and "administrator access" in virtual[0]["title"] and virtual[0]["remediation"]["supported"] is False


def test_cost_anomaly_finding_severity_boundary(clean_env):
    anomaly = {"scope": "total", "active": True, "date": "2026-10-01", "value": 200.0, "baseline_mean": 100.0, "increase_pct": 100.0, "zscore": 9.0, "top_contributors": []}
    (f,) = security.rule_cost(clean_env, {"cost_anomalies": [anomaly]})
    assert f["severity"] == "HIGH" and f["severity_reason"] == "increase of 100% or more"
    (f,) = security.rule_cost(clean_env, {"cost_anomalies": [dict(anomaly, increase_pct=99.9)]})
    assert f["severity"] == "MEDIUM" and f["severity_reason"] == "base severity MEDIUM"
    assert security.rule_cost(clean_env, {"cost_anomalies": [dict(anomaly, active=False)]}) == []
    assert security.rule_cost(clean_env, {"cost_anomalies": [dict(anomaly, scope="EC2")]}) == []
    assert f["title"].startswith("Daily cost jumped 100%")


def test_manual_plans_have_no_operations_and_supported_plans_have_hashes(clean_env):
    assert security.manual("s", "r") == {"supported": False, "summary": "s", "operations": [], "risk": "r", "downtime": False}
    plan = security.remediation("s", [security.op("a", "t")], "risk", downtime=True)
    assert plan["supported"] is True and plan["downtime"] is True and plan["operations"][0] == {"action": "a", "target_id": "t", "params": {}, "description": ""}
    assert security.bump("MEDIUM") == "HIGH" and security.bump("HIGH") == "CRITICAL"
