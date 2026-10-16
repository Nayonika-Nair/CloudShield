"""Configuration drift: current state versus a saved baseline.

Drift is an *observation* that something changed. It is deliberately separate
from security findings, which assert that a condition is risky.
"""

from __future__ import annotations

import copy
from typing import Any

from app.simulator.env import Environment, diff_resources

# Fields that are usage/telemetry rather than configuration.
VOLATILE = {
    "s3_bucket": {"size_gb", "object_count"},
    "rds_instance": {"last_backup_at"},
    "iam_role": {"last_used"},
}
SECURITY_FIELDS = {
    "security_group": {"ingress", "egress"},
    "s3_bucket": {"acl", "block_public_access", "encryption", "policy_public"},
    "ebs_volume": {"encrypted", "backup_policy"},
    "rds_instance": {"publicly_accessible", "storage_encrypted", "backup_retention_days", "sg_ids", "subnet_ids"},
    "iam_user": {"policy_ids", "mfa_enabled", "access_keys"},
    "iam_role": {"policy_ids", "trust"},
    "route_table": {"routes"},
    "subnet": {"route_table_id"},
    "internet_gateway": {"state"},
    "ec2_instance": {"sg_ids", "public_ip", "iam_role"},
}


def _normalise(resources: dict[str, dict[str, dict[str, Any]]]) -> dict[str, dict[str, dict[str, Any]]]:
    out = copy.deepcopy(resources)
    for rtype, items in out.items():
        for res in items.values():
            for f in VOLATILE.get(rtype, ()):
                res.pop(f, None)
            if rtype == "iam_user":
                for k in res.get("access_keys", []):
                    k.pop("last_used", None)
        if rtype == "snapshot":  # policy-managed snapshots are expected churn
            out[rtype] = {rid: s for rid, s in items.items() if s.get("managed_by") != "backup_policy"}
    return out


def detect(env: Environment) -> dict[str, Any]:
    if env.baseline is None:
        return {"has_baseline": False, "baseline_time": None, "items": [], "summary": {"total": 0}}
    d = diff_resources(_normalise(env.baseline), _normalise(env.resources))
    items: list[dict[str, Any]] = []

    def meta(rid: str, source: dict[str, Any]) -> tuple[str, str, str]:
        for t, rs in source.items():
            if rid in rs:
                return t, rs[rid].get("name", rid), rs[rid].get("state", "")
        return "unknown", rid, ""

    cur, base = env.resources, env.baseline
    for rid in d["created"]:
        t, name, _ = meta(rid, cur)
        items.append({"resource_id": rid, "resource_type": t, "name": name, "change": "created", "fields": [],
                      "security_relevant": t in SECURITY_FIELDS})
    for rid in d["deleted"]:
        t, name, _ = meta(rid, base)
        items.append({"resource_id": rid, "resource_type": t, "name": name, "change": "deleted", "fields": [],
                      "security_relevant": t in SECURITY_FIELDS})
    for rid, changes in d["modified"].items():
        t, name, _ = meta(rid, cur)
        fields = [{"field": f, "before": c["before"], "after": c["after"],
                   "security_relevant": f in SECURITY_FIELDS.get(t, set())} for f, c in sorted(changes.items())]
        items.append({"resource_id": rid, "resource_type": t, "name": name, "change": "modified", "fields": fields,
                      "security_relevant": any(f["security_relevant"] for f in fields)})
    items.sort(key=lambda i: (not i["security_relevant"], i["change"], i["resource_id"]))
    return {
        "has_baseline": True, "baseline_time": env.baseline_time, "kind": "drift", "items": items,
        "summary": {"total": len(items), "created": len(d["created"]), "deleted": len(d["deleted"]),
                    "modified": len(d["modified"]), "security_relevant": sum(1 for i in items if i["security_relevant"])},
    }
