"""Small set of compliance-style posture checks used by dashboards and what-if comparisons."""

from __future__ import annotations

from typing import Any

from app.engines import iam, network
from app.simulator.env import Environment


def _check(cid: str, name: str, total: int, ok: int) -> dict[str, Any]:
    pct = 100.0 if total == 0 else round(ok / total * 100, 1)
    return {"id": cid, "name": name, "total": total, "compliant": ok, "pct": pct, "status": "PASS" if ok == total else "FAIL"}


def checks(env: Environment) -> list[dict[str, Any]]:
    vols = [v for v in env.of("ebs_volume")]
    buckets, dbs = env.of("s3_bucket"), env.of("rds_instance")
    enc_total = len(vols) + len(buckets) + len(dbs)
    enc_ok = (sum(v["encrypted"] for v in vols) + sum(b["encryption"] != "none" for b in buckets)
              + sum(d["storage_encrypted"] for d in dbs))
    prod_vols = [v for v in vols if v["attached_to"] and env.tag(v, "environment") == "prod"]
    prod_dbs = [d for d in dbs if env.tag(d, "environment") == "prod"]
    bk_ok = sum(1 for v in prod_vols if v["backup_policy"] != "none") + sum(1 for d in prod_dbs if d["backup_retention_days"] > 0)
    console = [u for u in env.of("iam_user") if u["console_access"]]
    public_buckets = [b for b in buckets if not b["block_public_access"] and (b["acl"] == "public-read" or b.get("policy_public"))]
    admin_ports = [e for e in network.reachable_exposures(env) if 22 in e["sensitive_ports"] or 3389 in e["sensitive_ports"] or e["all_ports"]]
    required = env.config["tags"]["required_tags"]
    taggable = env.of("ec2_instance") + vols + buckets + dbs
    tag_ok = sum(1 for r in taggable if all(t in (r.get("tags") or {}) for t in required))
    undesignated = [p for p in iam.principals(env) if iam.is_admin(env, p["id"]) and (p.get("tags") or {}).get("admin") != "designated"]
    return [
        _check("encryption_at_rest", "Storage encrypted at rest (EBS, S3, RDS)", enc_total, enc_ok),
        _check("backup_coverage", "Production volumes and databases have backups", len(prod_vols) + len(prod_dbs), bk_ok),
        _check("mfa_console_users", "Console users have MFA", len(console), sum(u["mfa_enabled"] for u in console)),
        _check("no_public_buckets", "No publicly accessible S3 buckets", len(buckets), len(buckets) - len(public_buckets)),
        _check("no_internet_admin_ports", "No SSH/RDP/all-port exposure from the internet", len(env.of("ec2_instance")) + len(dbs),
               len(env.of("ec2_instance")) + len(dbs) - len({e["resource_id"] for e in admin_ports})),
        _check("required_tags", f"Resources carry required tags ({', '.join(required)})", len(taggable), tag_ok),
        _check("no_unapproved_admins", "No unapproved wildcard administrators", len(iam.principals(env)),
               len(iam.principals(env)) - len(undesignated)),
    ]
