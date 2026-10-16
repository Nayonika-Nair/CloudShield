"""Simplified network reachability analysis over the simulated topology.

Exposure is *derived* from VPC, subnet, route table, internet gateway,
network interface and security-group state - never from a label.
"""

from __future__ import annotations

from typing import Any

from app.simulator.catalog import DATABASE_PORTS, SENSITIVE_PORTS
from app.simulator.env import Environment, SimError

WORLD = {"0.0.0.0/0", "::/0"}


def is_world(cidr: str | None) -> bool:
    return cidr in WORLD


def rule_covers(rule: dict[str, Any], port: int) -> bool:
    if rule["protocol"] == "-1":
        return True
    return rule["protocol"] == "tcp" and rule["from_port"] <= port <= rule["to_port"]


def rule_is_all_ports(rule: dict[str, Any]) -> bool:
    return rule["protocol"] == "-1" or (rule["from_port"] <= 0 and rule["to_port"] >= 65535)


def describe_rule(rule: dict[str, Any]) -> str:
    if rule["protocol"] == "-1":
        ports = "all traffic"
    elif rule["from_port"] == rule["to_port"]:
        ports = f"{rule['protocol']}/{rule['from_port']}"
    else:
        ports = f"{rule['protocol']}/{rule['from_port']}-{rule['to_port']}"
    src = rule.get("cidr") or rule.get("source_sg") or "?"
    return f"{ports} from {src}"


def sensitive_ports_in(rule: dict[str, Any]) -> list[int]:
    return sorted(p for p in SENSITIVE_PORTS if rule_covers(rule, p))


# --------------------------------------------------------------------- routing
def route_table_for(env: Environment, subnet: dict[str, Any]) -> dict[str, Any] | None:
    rt = env.resources["route_table"].get(subnet.get("route_table_id") or "")
    if rt:
        return rt
    for cand in env.of("route_table"):  # fall back to the VPC main route table
        if cand["vpc_id"] == subnet["vpc_id"] and cand.get("main"):
            return cand
    return None


def internet_route(env: Environment, subnet: dict[str, Any]) -> dict[str, Any]:
    """Describe how (and whether) a subnet reaches the internet."""
    rt = route_table_for(env, subnet)
    if rt is None:
        return {"status": "none", "route_table": None, "igw": None, "detail": "subnet has no route table"}
    for route in rt.get("routes", []):
        if route["destination"] == "0.0.0.0/0":
            if route["target_type"] == "igw":
                igw = env.resources["internet_gateway"].get(route["target"])
                if igw and igw["vpc_id"] == subnet["vpc_id"] and igw.get("state") == "attached":
                    return {"status": "igw", "route_table": rt["id"], "igw": igw["id"],
                            "detail": f"route table {rt['id']} routes 0.0.0.0/0 to attached internet gateway {igw['id']}"}
                return {"status": "blackhole", "route_table": rt["id"], "igw": route["target"],
                        "detail": f"route table {rt['id']} points 0.0.0.0/0 at {route['target']}, which is missing or detached"}
    return {"status": "none", "route_table": rt["id"], "igw": None,
            "detail": f"route table {rt['id']} has no default route to an internet gateway"}


def subnet_is_public(env: Environment, subnet: dict[str, Any]) -> bool:
    return internet_route(env, subnet)["status"] == "igw"


# ------------------------------------------------------- attached resources
def _attachments(env: Environment) -> list[dict[str, Any]]:
    """Network-attached resources with the facts the exposure check needs."""
    out: list[dict[str, Any]] = []
    for inst in env.of("ec2_instance"):
        subnet = env.resources["subnet"].get(inst["subnet_id"])
        if subnet is None:
            continue
        out.append({
            "res": inst, "type": "ec2_instance", "subnet": subnet, "sg_ids": inst["sg_ids"],
            "up": inst["state"] == "running", "state_label": inst["state"],
            "public": bool(inst.get("public_ip")),
            "public_detail": f"instance has public IP {inst.get('public_ip')}" if inst.get("public_ip")
            else "instance has no public IP address",
        })
    for db in env.of("rds_instance"):
        eni = env.resources["network_interface"].get(db.get("eni_id") or "")
        subnet = env.resources["subnet"].get(eni["subnet_id"]) if eni else None
        if subnet is None:
            continue
        out.append({
            "res": db, "type": "rds_instance", "subnet": subnet, "sg_ids": db["sg_ids"],
            "up": db["state"] == "available", "state_label": db["state"],
            "public": bool(db.get("publicly_accessible")),
            "public_detail": "database is publicly accessible" if db.get("publicly_accessible")
            else "database is not publicly accessible",
        })
    for lb in env.of("load_balancer"):
        subnets = [env.resources["subnet"][s] for s in lb["subnet_ids"] if s in env.resources["subnet"]]
        if not subnets:
            continue
        out.append({
            "res": lb, "type": "load_balancer", "subnet": subnets[0], "sg_ids": lb["sg_ids"],
            "up": lb["state"] == "active", "state_label": lb["state"],
            "public": lb["scheme"] == "internet-facing",
            "public_detail": f"load balancer scheme is {lb['scheme']}",
        })
    return out


def _exposure(env: Environment, att: dict[str, Any], sg: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    route = internet_route(env, att["subnet"])
    res = att["res"]
    steps = [
        {"check": "Security group allows inbound from the internet", "ok": True,
         "detail": f"{sg['id']} ({sg['name']}) allows {describe_rule(rule)}"},
        {"check": "Resource is running", "ok": att["up"], "detail": f"state is {att['state_label']}"},
        {"check": "Resource has a public address", "ok": att["public"], "detail": att["public_detail"]},
        {"check": "Subnet routes to an internet gateway", "ok": route["status"] == "igw",
         "detail": f"subnet {att['subnet']['id']}: {route['detail']}"},
    ]
    failing = next((s for s in steps if not s["ok"]), None)
    reachable = failing is None
    if reachable:
        explanation = (f"Reachable from the internet on {describe_rule(rule)}: every hop allows traffic "
                       f"({sg['id']} -> public address -> {att['subnet']['id']} -> {route['igw']}).")
    else:
        explanation = (f"Rule {describe_rule(rule)} on {sg['id']} is open to the world, but the resource is not "
                       f"reachable because: {failing['check'].lower()} failed ({failing['detail']}).")
    return {
        "resource_id": res["id"], "resource_type": att["type"], "resource_name": res.get("name", res["id"]),
        "security_group": sg["id"], "security_group_name": sg["name"], "rule": rule,
        "protocol": rule["protocol"], "from_port": rule["from_port"], "to_port": rule["to_port"],
        "source": rule["cidr"], "all_ports": rule_is_all_ports(rule), "sensitive_ports": sensitive_ports_in(rule),
        "reachable": reachable, "blocked_at": None if reachable else failing["check"], "steps": steps,
        "subnet_id": att["subnet"]["id"], "explanation": explanation,
    }


def exposures(env: Environment, resource_id: str | None = None) -> list[dict[str, Any]]:
    """All security-group rules open to the internet, with reachability verdicts."""
    result = []
    for att in _attachments(env):
        if resource_id and att["res"]["id"] != resource_id:
            continue
        for sg_id in att["sg_ids"]:
            sg = env.resources["security_group"].get(sg_id)
            if sg is None:
                continue
            for rule in sg["ingress"]:
                if is_world(rule.get("cidr")):
                    result.append(_exposure(env, att, sg, rule))
    return result


def risky_exposure_ids(env: Environment) -> list[str]:
    """Resources reachable from the internet on a sensitive port or on all ports."""
    return sorted({e["resource_id"] for e in exposures(env) if e["reachable"] and (e["sensitive_ports"] or e["all_ports"])})


def reachable_exposures(env: Environment, port: int | None = None) -> list[dict[str, Any]]:
    out = [e for e in exposures(env) if e["reachable"]]
    if port is not None:
        out = [e for e in out if rule_covers(e["rule"], port)]
    return out


# --------------------------------------------------------------------- egress
def egress_profile(env: Environment, inst: dict[str, Any]) -> dict[str, Any]:
    subnet = env.resources["subnet"].get(inst["subnet_id"])
    route = internet_route(env, subnet) if subnet else {"status": "none", "detail": "no subnet"}
    world = []
    for sg_id in inst["sg_ids"]:
        sg = env.resources["security_group"].get(sg_id)
        if sg:
            world += [dict(r, sg=sg_id) for r in sg["egress"] if is_world(r.get("cidr"))]
    has_public = bool(inst.get("public_ip"))
    open_ = route["status"] == "igw" and has_public and bool(world) and inst["state"] == "running"
    return {
        "route": route["status"], "has_public_ip": has_public, "world_rules": world, "open": open_,
        "unrestricted": open_ and any(rule_is_all_ports(r) for r in world),
        "detail": route["detail"],
    }


def egress_open(env: Environment, inst: dict[str, Any]) -> bool:
    return egress_profile(env, inst)["open"]


# ----------------------------------------------------------------- topology
def topology_issues(env: Environment) -> list[dict[str, Any]]:
    """Misconfigurations visible purely from the routing/addressing layer."""
    issues = []
    for subnet in env.of("subnet"):
        route = internet_route(env, subnet)
        tier = (subnet.get("tags") or {}).get("tier")
        if tier == "private" and route["status"] == "igw":
            issues.append({"kind": "private_subnet_public", "subnet_id": subnet["id"], "detail": route["detail"],
                           "route_table": route["route_table"]})
        if route["status"] == "blackhole":
            issues.append({"kind": "blackhole_route", "subnet_id": subnet["id"], "detail": route["detail"],
                           "route_table": route["route_table"]})
        if subnet.get("map_public_ip") and route["status"] != "igw":
            issues.append({"kind": "public_ip_without_route", "subnet_id": subnet["id"], "detail": route["detail"],
                           "route_table": route["route_table"]})
    for inst in env.of("ec2_instance"):
        subnet = env.resources["subnet"].get(inst["subnet_id"])
        if inst["state"] == "running" and inst.get("public_ip") and subnet and internet_route(env, subnet)["status"] != "igw":
            issues.append({"kind": "public_ip_unroutable", "resource_id": inst["id"], "subnet_id": subnet["id"],
                           "detail": f"{inst['id']} has public IP {inst['public_ip']} but subnet {subnet['id']} has no internet route"})
    return issues


def topology(env: Environment) -> dict[str, Any]:
    exposed: dict[str, list[int]] = {}   # reachable on a sensitive port or all ports
    facing: set[str] = set()             # reachable from the internet on any port (e.g. HTTPS)
    for e in exposures(env):
        if e["reachable"]:
            facing.add(e["resource_id"])
            if e["sensitive_ports"] or e["all_ports"]:
                exposed.setdefault(e["resource_id"], [])
                exposed[e["resource_id"]] += e["sensitive_ports"] or [0]
    nodes: list[dict[str, Any]] = [{"id": "internet", "type": "internet", "label": "Internet", "parent": None}]
    edges: list[dict[str, Any]] = []
    for vpc in env.of("vpc"):
        nodes.append({"id": vpc["id"], "type": "vpc", "label": vpc["name"], "parent": None,
                      "attrs": {"cidr": vpc["cidr"]}})
    for igw in env.of("internet_gateway"):
        nodes.append({"id": igw["id"], "type": "internet_gateway", "label": igw["name"], "parent": igw["vpc_id"],
                      "state": igw["state"]})
        edges.append({"source": "internet", "target": igw["id"], "kind": "traffic"})
    for sn in env.of("subnet"):
        route = internet_route(env, sn)
        nodes.append({"id": sn["id"], "type": "subnet", "label": sn["name"], "parent": sn["vpc_id"],
                      "attrs": {"cidr": sn["cidr"], "az": sn["az"], "tier": (sn.get("tags") or {}).get("tier"),
                                "internet_route": route["status"]}})
        if route["status"] == "igw":
            edges.append({"source": route["igw"], "target": sn["id"], "kind": "route"})
    for sg in env.of("security_group"):
        world = [r for r in sg["ingress"] if is_world(r.get("cidr"))]
        risky = [r for r in world if sensitive_ports_in(r) or rule_is_all_ports(r)]
        nodes.append({"id": sg["id"], "type": "security_group", "label": sg["name"], "parent": sg["vpc_id"],
                      "attrs": {"open_to_world": [describe_rule(r) for r in world]}, "exposed": bool(risky)})
    for inst in env.of("ec2_instance"):
        if inst["state"] == "terminated":
            continue
        nodes.append({"id": inst["id"], "type": "ec2_instance", "label": inst["name"], "parent": inst["subnet_id"],
                      "state": inst["state"], "exposed": inst["id"] in exposed, "internet_facing": inst["id"] in facing,
                      "exposed_ports": sorted(set(exposed.get(inst["id"], []))),
                      "attrs": {"instance_type": inst["instance_type"], "private_ip": inst["private_ip"],
                                "public_ip": inst.get("public_ip")}})
        for sg in inst["sg_ids"]:
            edges.append({"source": inst["id"], "target": sg, "kind": "uses"})
        if inst.get("iam_role"):
            edges.append({"source": inst["id"], "target": inst["iam_role"], "kind": "assumes"})
    for vol in env.of("ebs_volume"):
        nodes.append({"id": vol["id"], "type": "ebs_volume", "label": vol["name"], "parent": None,
                      "state": vol["state"], "attrs": {"size_gb": vol["size_gb"], "encrypted": vol["encrypted"]}})
        if vol.get("attached_to"):
            edges.append({"source": vol["id"], "target": vol["attached_to"], "kind": "attached"})
    for db in env.of("rds_instance"):
        eni = env.resources["network_interface"].get(db.get("eni_id") or "")
        nodes.append({"id": db["id"], "type": "rds_instance", "label": db["name"],
                      "parent": eni["subnet_id"] if eni else None, "state": db["state"],
                      "exposed": db["id"] in exposed, "internet_facing": db["id"] in facing,
                      "exposed_ports": sorted(set(exposed.get(db["id"], []))),
                      "attrs": {"engine": db["engine"], "instance_class": db["instance_class"],
                                "public": db["publicly_accessible"]}})
        for sg in db["sg_ids"]:
            edges.append({"source": db["id"], "target": sg, "kind": "uses"})
    for lb in env.of("load_balancer"):
        nodes.append({"id": lb["id"], "type": "load_balancer", "label": lb["name"],
                      "parent": lb["subnet_ids"][0] if lb["subnet_ids"] else lb["vpc_id"], "state": lb["state"],
                      "exposed": lb["id"] in exposed, "internet_facing": lb["id"] in facing,
                      "exposed_ports": sorted(set(exposed.get(lb["id"], []))),
                      "attrs": {"targets": len(lb["targets"]), "scheme": lb["scheme"]}})
        for t in lb["targets"]:
            if env.exists(t):
                edges.append({"source": lb["id"], "target": t, "kind": "forwards"})
    for eip in env.of("elastic_ip"):
        nodes.append({"id": eip["id"], "type": "elastic_ip", "label": eip["public_ip"], "parent": None,
                      "state": eip["state"]})
        if eip.get("instance_id"):
            edges.append({"source": eip["id"], "target": eip["instance_id"], "kind": "associated"})
    for b in env.of("s3_bucket"):
        public = (not b["block_public_access"]) and (b["acl"] != "private" or b.get("policy_public"))
        nodes.append({"id": b["id"], "type": "s3_bucket", "label": b["name"], "parent": None, "exposed": public,
                      "attrs": {"public": public, "encryption": b["encryption"]}})
    for r in env.of("iam_role"):
        nodes.append({"id": r["id"], "type": "iam_role", "label": r["name"], "parent": None})
    ids = {n["id"] for n in nodes}
    edges = [e for e in edges if e["source"] in ids and e["target"] in ids]
    return {
        "nodes": nodes, "edges": edges,
        "summary": {"vpcs": len(env.of("vpc")), "subnets": len(env.of("subnet")),
                    "exposed_resources": len(exposed), "internet_facing": len(facing),
                    "public_subnets": sum(1 for s in env.of("subnet") if subnet_is_public(env, s))},
    }


def explain_reachability(env: Environment, resource_id: str) -> dict[str, Any]:
    rtype, res = env.find(resource_id)
    if rtype not in ("ec2_instance", "rds_instance", "load_balancer"):
        raise SimError(f"{resource_id} is a {rtype}; reachability applies to instances, databases and load balancers",
                       "unsupported", 422)
    result = {"resource_id": resource_id, "resource_type": rtype, "exposures": exposures(env, resource_id)}
    result["internet_reachable"] = any(e["reachable"] for e in result["exposures"])
    if rtype == "ec2_instance":
        result["egress"] = egress_profile(env, res)
    return result


def port_label(port: int) -> str:
    return SENSITIVE_PORTS.get(port, str(port))


__all__ = ["DATABASE_PORTS"]
