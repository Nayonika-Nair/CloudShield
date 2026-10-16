"""Scenarios change simulated *state*; they never insert findings.

A scenario applies the same kind of mistake an engineer could make (open a
port, make a bucket public, ...). The ordinary security and cost rules then
detect - or fail to detect - the resulting condition.
"""

from __future__ import annotations

from typing import Any, Callable

from app.engines import network
from app.simulator import builders as bld
from app.simulator import lifecycle
from app.simulator.env import Environment, SimError, diff_resources

ScenarioFn = Callable[[Environment, dict[str, Any]], dict[str, Any]]


def _run(env: Environment, action: str, target: str | None, params: dict[str, Any] | None = None) -> str:
    return lifecycle.execute(env, action, target, params)["message"]


def _public_subnets(env: Environment) -> list[dict[str, Any]]:
    return [s for s in env.of("subnet") if network.subnet_is_public(env, s)]


def _sg_for(env: Environment, vpc_id: str, name: str) -> str | None:
    return next((s["id"] for s in env.of("security_group") if s["vpc_id"] == vpc_id and s["name"].endswith(name)), None)


def _public_instance(env: Environment, os_name: str, params: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """An existing running public instance, or a freshly launched one."""
    notes: list[str] = []
    if params.get("target"):
        return env.get(params["target"], "ec2_instance"), notes
    pub = {s["id"] for s in _public_subnets(env)}
    for inst in env.of("ec2_instance"):
        if inst["state"] == "running" and inst["os"] == os_name and inst["subnet_id"] in pub and inst.get("public_ip"):
            return inst, notes
    subnet = next(iter(sorted(_public_subnets(env), key=lambda s: s["id"])), None)
    if subnet is None:
        raise SimError("The environment has no public subnet to host an exposed instance", "no_target", 409)
    sg = _sg_for(env, subnet["vpc_id"], "bastion-sg") or _sg_for(env, subnet["vpc_id"], "web-sg")
    if sg is None:
        raise SimError("No suitable security group found", "no_target", 409)
    res = lifecycle.execute(env, "ec2.create", None, {
        "subnet_id": subnet["id"], "instance_type": "t3.small", "sg_ids": [sg],
        "role": "bastion", "os": os_name, "assign_public_ip": True, "tags": {"environment": "dev", "owner": "web-team"}})
    notes.append(res["message"])
    return env.get(res["created"][0]), notes


def _open_port(env: Environment, params: dict[str, Any], os_name: str, port: int, label: str) -> dict[str, Any]:
    inst, notes = _public_instance(env, os_name, params)
    n = env.id_counters.get("launch-wizard", 0) + 1
    env.id_counters["launch-wizard"] = n
    created = lifecycle.execute(env, "sg.create", None, {
        "vpc_id": inst["vpc_id"], "name": f"launch-wizard-{n}", "description": f"{label} access"})
    sg_id = created["created"][0]
    notes.append(created["message"])
    notes.append(_run(env, "sg.authorize_ingress", sg_id, {
        "protocol": "tcp", "from_port": port, "to_port": port, "cidr": "0.0.0.0/0", "description": f"{label} from anywhere"}))
    notes.append(_run(env, "ec2.set_security_groups", inst["id"], {"sg_ids": inst["sg_ids"] + [sg_id]}))
    return {"targets": [inst["id"], sg_id], "messages": notes}


def public_s3_bucket(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    if params.get("target"):
        bucket = env.get(params["target"], "s3_bucket")
    else:
        cands = sorted((b for b in env.of("s3_bucket") if b["block_public_access"] and b["acl"] == "private"),
                       key=lambda b: (b["tags"].get("data_classification") != "confidential", b["id"]))
        if not cands:
            raise SimError("No private bucket is available to expose", "no_target", 409)
        bucket = cands[0]
    notes = [_run(env, "s3.set_public_access_block", bucket["id"], {"block": False}),
             _run(env, "s3.set_acl", bucket["id"], {"acl": "public-read"})]
    return {"targets": [bucket["id"]], "messages": notes}


def open_ssh(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    return _open_port(env, params, "linux", 22, "SSH")


def open_rdp(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    return _open_port(env, params, "windows", 3389, "RDP")


def overly_permissive_iam(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    if params.get("target"):
        role = env.get(params["target"], "iam_role")
    else:
        names = ["role:deploy-role", "role:ec2-app-role"]
        role = next((env.resources["iam_role"][n] for n in names
                     if n in env.resources["iam_role"] and "policy:AdministratorAccess" not in env.resources["iam_role"][n]["policy_ids"]), None)
        if role is None:
            role = next((r for r in env.of("iam_role") if "policy:AdministratorAccess" not in r["policy_ids"]), None)
        if role is None:
            raise SimError("Every role already has administrative access", "no_target", 409)
    note = _run(env, "iam.attach_policy", role["id"], {"policy_id": "policy:AdministratorAccess"})
    return {"targets": [role["id"]], "messages": [note]}


def missing_encryption(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    targets, notes = [], []
    vol = next((v for v in sorted(env.of("ebs_volume"), key=lambda v: v["id"]) if v["encrypted"] and v["attached_to"]), None)
    if vol:
        vol["encrypted"] = False
        targets.append(vol["id"])
        notes.append(f"Volume {vol['id']} switched to unencrypted storage")
    bucket = next((b for b in sorted(env.of("s3_bucket"), key=lambda b: b["id"]) if b["encryption"] != "none"), None)
    if bucket:
        bucket["encryption"] = "none"
        targets.append(bucket["id"])
        notes.append(f"Default encryption removed from bucket {bucket['id']}")
    db = next((d for d in sorted(env.of("rds_instance"), key=lambda d: d["id"]) if d["storage_encrypted"]), None)
    if db:
        db["storage_encrypted"] = False
        targets.append(db["id"])
        notes.append(f"Database {db['id']} switched to unencrypted storage")
    if not targets:
        raise SimError("Nothing encrypted is left to weaken", "no_target", 409)
    return {"targets": targets, "messages": notes}


def missing_backup(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    targets, notes = [], []
    db = next((d for d in sorted(env.of("rds_instance"), key=lambda d: d["id"]) if d["backup_retention_days"] > 0), None)
    if db:
        notes.append(_run(env, "rds.set_backup_retention", db["id"], {"days": 0}))
        targets.append(db["id"])
    vol = next((v for v in sorted(env.of("ebs_volume"), key=lambda v: v["id"])
                if v["attached_to"] and v["backup_policy"] != "none"), None)
    if vol:
        notes.append(_run(env, "ebs.set_backup_policy", vol["id"], {"policy": "none"}))
        for snap in [s for s in env.of("snapshot") if s["volume_id"] == vol["id"] and s["managed_by"] == "backup_policy"]:
            env.remove(snap["id"])
        notes.append(f"Automated snapshots of {vol['id']} removed")
        targets.append(vol["id"])
    if not targets:
        raise SimError("No backed-up resource is available", "no_target", 409)
    return {"targets": targets, "messages": notes}


def suspicious_outbound(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    if params.get("target"):
        inst = env.get(params["target"], "ec2_instance")
    else:
        inst = next((i for i in sorted(env.of("ec2_instance"), key=lambda i: i["id"])
                     if network.egress_open(env, i) and i.get("traffic_multiplier", 1.0) == 1.0), None)
    if inst is None:
        raise SimError("No instance with open internet egress is available", "no_target", 409)
    inst["traffic_multiplier"] = float(params.get("multiplier", 25.0))
    return {"targets": [inst["id"]], "needs_time": True,
            "messages": [f"{inst['id']} now sends {inst['traffic_multiplier']:.0f}x its normal outbound traffic "
                         "(visible in metrics once simulated time advances)"]}


def cost_spike(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    subnets = sorted((s for s in env.of("subnet") if s["tags"].get("tier") == "private"), key=lambda s: s["id"])
    if not subnets:
        raise SimError("No private subnet available", "no_target", 409)
    created, notes = [], []
    count = int(params.get("count", 3))
    for k in range(count):
        subnet = subnets[k % len(subnets)]
        sg = _sg_for(env, subnet["vpc_id"], "app-sg")
        res = lifecycle.execute(env, "ec2.create", None, {
            "subnet_id": subnet["id"], "instance_type": "r5.2xlarge", "sg_ids": [sg], "role": "batch",
            "profile": "busy", "tags": {"environment": "dev", "owner": "data-team", "application": "ad-hoc-analysis"}})
        created += res["created"]
        notes.append(res["message"])
    return {"targets": created, "needs_time": True, "messages": notes}


def excessive_admin(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    users = [u for u in sorted(env.of("iam_user"), key=lambda u: u["id"])
             if "policy:AdministratorAccess" not in u["policy_ids"] and u["console_access"]]
    if not users:
        raise SimError("Every console user already has administrative access", "no_target", 409)
    chosen = users[: int(params.get("count", 2))]
    notes = [_run(env, "iam.attach_policy", u["id"], {"policy_id": "policy:AdministratorAccess"}) for u in chosen]
    return {"targets": [u["id"] for u in chosen], "messages": notes}


def risky_network(env: Environment, params: dict[str, Any]) -> dict[str, Any]:
    rts, notes, targets = env.resources["route_table"], [], []
    private_rt = next((rt for rt in sorted(rts.values(), key=lambda r: r["id"])
                       if rt["name"].endswith("private-rt")
                       and not any(r["destination"] == "0.0.0.0/0" for r in rt["routes"])), None)
    if private_rt is None:
        raise SimError("No private route table available", "no_target", 409)
    igw = env.get(env.get(private_rt["vpc_id"])["igw_id"], "internet_gateway")
    notes.append(_run(env, "route.set", private_rt["id"], {"destination": "0.0.0.0/0", "target_type": "igw", "target": igw["id"]}))
    targets.append(private_rt["id"])
    db = next((d for d in sorted(env.of("rds_instance"), key=lambda d: d["id"])
               if d["vpc_id"] == private_rt["vpc_id"] and not d["publicly_accessible"]), None)
    if db:
        eni = env.get(db["eni_id"])
        db["publicly_accessible"] = True
        eni["public_ip"] = eni["public_ip"] or bld.alloc_public_ip(env)
        sg_id = db["sg_ids"][0]
        notes.append(_run(env, "sg.authorize_ingress", sg_id, {
            "protocol": "tcp", "from_port": db["port"], "to_port": db["port"], "cidr": "0.0.0.0/0", "description": "temporary debugging"}))
        notes.append(f"{db['id']} made publicly accessible")
        targets += [db["id"], sg_id]
    return {"targets": targets, "messages": notes}


SCENARIOS: dict[str, dict[str, Any]] = {
    "public_s3_bucket": {"label": "Public S3 bucket", "fn": public_s3_bucket, "time_dependent": False,
                         "description": "Disables Block Public Access and sets a public-read ACL on a private bucket.",
                         "detected_by": ["S3-001"]},
    "open_ssh": {"label": "SSH open to the internet", "fn": open_ssh, "time_dependent": False,
                 "description": "Adds a launch-wizard security group allowing tcp/22 from 0.0.0.0/0 to a public Linux instance.",
                 "detected_by": ["NET-001"]},
    "open_rdp": {"label": "RDP open to the internet", "fn": open_rdp, "time_dependent": False,
                 "description": "Adds a security group allowing tcp/3389 from 0.0.0.0/0 to a public Windows instance.",
                 "detected_by": ["NET-002"]},
    "overly_permissive_iam": {"label": "Overly permissive IAM role", "fn": overly_permissive_iam, "time_dependent": False,
                              "description": "Attaches AdministratorAccess to a workload role.",
                              "detected_by": ["IAM-001", "IAM-005", "IAM-006"]},
    "missing_encryption": {"label": "Missing encryption", "fn": missing_encryption, "time_dependent": False,
                           "description": "Removes encryption from a volume, a bucket and a database.",
                           "detected_by": ["ENC-001", "ENC-002", "ENC-003"]},
    "missing_backup": {"label": "Missing backups", "fn": missing_backup, "time_dependent": False,
                       "description": "Disables RDS automated backups and the snapshot schedule of a volume.",
                       "detected_by": ["BKP-001", "BKP-002"]},
    "suspicious_outbound": {"label": "Suspicious outbound traffic", "fn": suspicious_outbound, "time_dependent": True,
                            "description": "Makes an internet-facing instance send many times its normal outbound traffic.",
                            "detected_by": ["NET-008", "COST-001"]},
    "cost_spike": {"label": "Unexpected cost spike", "fn": cost_spike, "time_dependent": True,
                   "description": "Launches several large, busy instances. The anomaly shows after time advances.",
                   "detected_by": ["COST-001"]},
    "excessive_admin": {"label": "Excessive administrators", "fn": excessive_admin, "time_dependent": False,
                        "description": "Grants AdministratorAccess to additional console users.",
                        "detected_by": ["IAM-001", "IAM-006"]},
    "risky_network": {"label": "Risky network change", "fn": risky_network, "time_dependent": False,
                      "description": "Routes the private tier to the internet gateway and exposes a database on its port.",
                      "detected_by": ["NET-006", "NET-003"]},
}


def catalog() -> list[dict[str, Any]]:
    return [{"name": k, "label": v["label"], "description": v["description"],
             "time_dependent": v["time_dependent"], "detected_by": v["detected_by"]} for k, v in SCENARIOS.items()]


def trigger(env: Environment, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = SCENARIOS.get(name)
    if spec is None:
        raise SimError(f"Unknown scenario '{name}'", "unknown_scenario", 404)
    before = env.snapshot_resources()
    result = spec["fn"](env, params or {})
    result["scenario"] = name
    result["changes"] = diff_resources(before, env.resources)
    result["before"] = {rid: before[t][rid] for t in before for rid in before[t]
                        if rid in result["changes"]["modified"] or rid in result["changes"]["deleted"]}
    return result


def revert(env: Environment, before: dict[str, Any], changes: dict[str, Any]) -> list[str]:
    """Undo a scenario using the pre-scenario copies of the resources it touched."""
    notes = []
    for rid in changes["created"]:
        if env.exists(rid):
            env.remove(rid)
            notes.append(f"removed {rid}")
    for rid, original in before.items():
        rtype = original["type"]
        if env.exists(rid):
            env.resources[rtype][rid].clear()
            env.resources[rtype][rid].update(original)
        else:
            env.add(rtype, dict(original))
        notes.append(f"restored {rid}")
    return notes
