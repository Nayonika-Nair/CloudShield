"""Read-only inventory views over a loaded environment."""

from __future__ import annotations

from typing import Any

from app.engines import cost, network
from app.simulator import lifecycle
from app.simulator.env import Environment, relationships

_SUMMARY_FIELDS = {
    "ec2_instance": ["instance_type", "role", "os", "private_ip", "public_ip", "subnet_id", "profile"],
    "ebs_volume": ["size_gb", "volume_type", "encrypted", "attached_to", "backup_policy", "az"],
    "snapshot": ["volume_id", "size_gb", "managed_by", "encrypted"],
    "s3_bucket": ["size_gb", "encryption", "acl", "block_public_access", "purpose"],
    "rds_instance": ["engine", "instance_class", "storage_gb", "multi_az", "publicly_accessible", "storage_encrypted",
                     "backup_retention_days"],
    "security_group": ["vpc_id", "description"],
    "vpc": ["cidr"],
    "subnet": ["vpc_id", "cidr", "az", "route_table_id"],
    "route_table": ["vpc_id"],
    "internet_gateway": ["vpc_id"],
    "network_interface": ["subnet_id", "private_ip", "public_ip", "attached_to"],
    "elastic_ip": ["public_ip", "instance_id"],
    "load_balancer": ["scheme", "vpc_id"],
    "iam_user": ["console_access", "mfa_enabled", "kind"],
    "iam_role": [],
    "iam_policy": ["managed"],
}


def summarize(res: dict[str, Any], monthly: float | None = None) -> dict[str, Any]:
    t = res["type"]
    out = {"id": res["id"], "type": t, "name": res.get("name", res["id"]), "state": res.get("state"),
           "region": res.get("region"), "tags": res.get("tags", {}), "created_at": res.get("created_at"),
           "attributes": {k: res.get(k) for k in _SUMMARY_FIELDS.get(t, [])}}
    if t == "ec2_instance":
        out["attributes"]["sg_ids"] = res.get("sg_ids")
    if monthly is not None:
        out["monthly_cost"] = monthly
    return out


def listing(env: Environment, *, rtype: str | None, state: str | None, q: str | None) -> list[dict[str, Any]]:
    rate = cost.monthly_run_rate(env)["by_resource"]
    needle = (q or "").lower()
    items = []
    for res in env.all():
        if rtype and res["type"] != rtype:
            continue
        if state and res.get("state") != state:
            continue
        if needle:
            blob = f"{res['id']} {res.get('name', '')} {' '.join(f'{k}={v}' for k, v in (res.get('tags') or {}).items())}".lower()
            if needle not in blob:
                continue
        items.append(summarize(res, rate.get(res["id"], 0.0)))
    return sorted(items, key=lambda r: (r["type"], r["name"]))


def detail(env: Environment, rid: str) -> dict[str, Any]:
    rtype, res = env.find(rid)
    rels = relationships(env)
    metrics = {}
    for metric, series in env.metrics.get(rid, {}).items():
        metrics[metric] = [{"date": d, "value": v} for d, v in sorted(series.items())][-30:]
    actions = [a for a in lifecycle.catalog()
               if a["target_type"] and (rtype == a["target_type"] or (isinstance(a["target_type"], (list, tuple)) and rtype in a["target_type"]))]
    out: dict[str, Any] = {
        "resource": res, "type": rtype, "monthly_cost": cost.resource_monthly(env, res),
        "relationships_out": [{"target": t, "relation": r} for s, t, r in rels if s == rid],
        "relationships_in": [{"source": s, "relation": r} for s, t, r in rels if t == rid],
        "metrics": metrics, "actions": actions,
    }
    if rtype in ("ec2_instance", "rds_instance", "load_balancer"):
        out["reachability"] = network.explain_reachability(env, rid)
    return out
