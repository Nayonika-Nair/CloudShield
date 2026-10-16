"""Security detection rules evaluated against the live simulated state.

Each rule reads resource configuration, the derived network exposure, the IAM
policy graph or recent metrics. A finding exists only while the underlying
condition exists, so re-running the rules after a change is a true
verification step.

The simulator does not model every real-world attack. These rules are a
documented, deliberately small set.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Callable

from app.engines import cost, iam, network
from app.simulator.catalog import DATABASE_PORTS, SENSITIVE_PORTS
from app.simulator.env import Environment, parse_iso

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHT = {"CRITICAL": 8, "HIGH": 4, "MEDIUM": 2, "LOW": 1}
TRUSTED_ADMIN_CIDR = "203.0.113.0/24"

RULES: dict[str, dict[str, str]] = {
    "NET-001": {"name": "SSH reachable from the internet", "category": "Network", "severity": "HIGH",
                "logic": "A security-group rule allows tcp/22 from 0.0.0.0/0 AND the resource is running, has a public address and sits in a subnet routed to an attached internet gateway. CRITICAL when tagged environment=prod."},
    "NET-002": {"name": "RDP reachable from the internet", "category": "Network", "severity": "HIGH",
                "logic": "Same reachability test as NET-001 for tcp/3389. CRITICAL when tagged environment=prod."},
    "NET-003": {"name": "Database or admin service reachable from the internet", "category": "Network", "severity": "HIGH",
                "logic": "A world-open rule covers a database/admin port (MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, Telnet, SMB) and the resource is reachable. CRITICAL for databases and prod resources."},
    "NET-004": {"name": "All ports open to the internet", "category": "Network", "severity": "CRITICAL",
                "logic": "A reachable resource has a rule allowing all ports/protocols from 0.0.0.0/0."},
    "NET-005": {"name": "Inconsistent or latent network exposure", "category": "Network", "severity": "LOW",
                "logic": "A world-open sensitive rule exists but the resource is not reachable (latent risk), or addressing and routing disagree (public IP in an unrouted subnet, black-hole route)."},
    "NET-006": {"name": "Private-tier subnet routed to the internet", "category": "Network", "severity": "HIGH",
                "logic": "A subnet tagged tier=private has a 0.0.0.0/0 route to an attached internet gateway."},
    "NET-008": {"name": "Suspicious outbound traffic", "category": "Network", "severity": "HIGH",
                "logic": "Average outbound traffic of the last 3 simulated days exceeds the preceding baseline by the configured factor AND the instance can currently reach the internet."},
    "S3-001": {"name": "Publicly accessible S3 bucket", "category": "Storage", "severity": "HIGH",
               "logic": "Block Public Access is off AND (ACL is public-read OR a public bucket policy exists). CRITICAL when data_classification=confidential."},
    "ENC-001": {"name": "Unencrypted EBS volume", "category": "Encryption", "severity": "MEDIUM",
                "logic": "Volume encrypted=false. HIGH when tagged environment=prod."},
    "ENC-002": {"name": "S3 bucket without default encryption", "category": "Encryption", "severity": "MEDIUM",
                "logic": "Bucket encryption=none. HIGH when data_classification=confidential."},
    "ENC-003": {"name": "Unencrypted RDS instance", "category": "Encryption", "severity": "HIGH",
                "logic": "RDS storage_encrypted=false."},
    "BKP-001": {"name": "RDS automated backups disabled", "category": "Resilience", "severity": "MEDIUM",
                "logic": "backup_retention_days=0. HIGH when tagged environment=prod."},
    "BKP-002": {"name": "Production volume without recent backup", "category": "Resilience", "severity": "MEDIUM",
                "logic": "Attached prod volume with no backup schedule whose newest snapshot is older than the backup age limit (or missing). HIGH when no snapshot exists."},
    "IAM-001": {"name": "Unapproved wildcard administrative access", "category": "Identity", "severity": "HIGH",
                "logic": "A policy grants Action '*' on Resource '*' to a user or role that is not tagged admin=designated."},
    "IAM-002": {"name": "Console user without MFA", "category": "Identity", "severity": "MEDIUM",
                "logic": "iam.mfa_required is on and a console user has MFA disabled. HIGH when the user is an administrator."},
    "IAM-003": {"name": "Stale or unused access key", "category": "Identity", "severity": "MEDIUM",
                "logic": "An active key is older than the maximum age or unused for 60+ simulated days. HIGH for administrators."},
    "IAM-004": {"name": "Risky role trust relationship", "category": "Identity", "severity": "HIGH",
                "logic": "A role trusts Principal '*' (CRITICAL) or an external account."},
    "IAM-005": {"name": "Privilege-escalation path", "category": "Identity", "severity": "HIGH",
                "logic": "A non-admin principal can reach administrative access through sts:AssumeRole, iam:PassRole+ec2:RunInstances or IAM write permissions (max 4 hops)."},
    "IAM-006": {"name": "Excessive administrative access", "category": "Identity", "severity": "MEDIUM",
                "logic": "More principals have full administrator access than iam.excessive_admin_threshold."},
    "COST-001": {"name": "Unexpected cost spike", "category": "Cost", "severity": "MEDIUM",
                 "logic": "A day's cost exceeds the 14-day trailing mean by z standard deviations AND by the configured percentage, within the last 3 simulated days. HIGH when the increase is 100% or more."},
}


def bump(severity: str) -> str:
    return SEVERITIES[min(SEVERITIES.index(severity) + 1, len(SEVERITIES) - 1)]


def op(action: str, target: str | None, params: dict[str, Any] | None = None, desc: str = "") -> dict[str, Any]:
    return {"action": action, "target_id": target, "params": params or {}, "description": desc}


def remediation(summary: str, ops: list[dict[str, Any]], risk: str, downtime: bool = False) -> dict[str, Any]:
    return {"supported": True, "summary": summary, "operations": ops, "risk": risk, "downtime": downtime}


def manual(summary: str, reason: str) -> dict[str, Any]:
    return {"supported": False, "summary": summary, "operations": [], "risk": reason, "downtime": False}


def _finding(env: Environment, rule_id: str, res: dict[str, Any] | None, *, key: str, severity: str,
             title: str, explanation: str, evidence: dict[str, Any], impact: str, recommendation: str,
             plan: dict[str, Any], severity_reason: str, resource_id: str | None = None) -> dict[str, Any]:
    meta = RULES[rule_id]
    rid = resource_id or (res["id"] if res else "account")
    return {
        "finding_key": f"{rule_id}:{key}", "rule_id": rule_id, "rule_name": meta["name"], "category": meta["category"],
        "severity": severity, "severity_reason": severity_reason, "resource_id": rid,
        "resource_type": res["type"] if res else "account", "resource_name": (res or {}).get("name", rid),
        "title": title, "explanation": explanation, "evidence": evidence, "impact": impact,
        "recommendation": recommendation, "remediation": plan, "detection_rule": meta["logic"],
    }


def _sev(env: Environment, res: dict[str, Any], base: str, *, prod_bump: bool = True, extra: str | None = None) -> tuple[str, str]:
    reason = f"base severity {base}"
    sev = base
    if prod_bump and env.tag(res, "environment") == "prod":
        sev, reason = bump(base), f"base {base} raised one level because the resource is tagged environment=prod"
    if extra:
        sev, reason = bump(sev), reason + f"; {extra}"
    return sev, reason


# ------------------------------------------------------------------- network
def rule_exposure(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for e in ctx["exposures"]:
        res = env.get(e["resource_id"])
        sg = e["security_group"]
        rule = e["rule"]
        revoke = op("sg.revoke_ingress", sg, {"protocol": rule["protocol"], "from_port": rule["from_port"],
                                              "to_port": rule["to_port"], "cidr": rule["cidr"]},
                    f"Remove the {network.describe_rule(rule)} rule from {sg}")
        plan = remediation(f"Remove the world-open rule from {sg}", [revoke],
                           "Clients that rely on this rule lose access; restrict to a trusted CIDR instead if access is still needed.")
        evidence = {"security_group": sg, "rule": rule, "reachable": e["reachable"], "steps": e["steps"],
                    "public_ip": res.get("public_ip"), "subnet": e["subnet_id"], "tags": res.get("tags", {})}
        if not e["reachable"]:
            if e["sensitive_ports"] or e["all_ports"]:
                evidence["blocked_at"] = e["blocked_at"]
                out.append(_finding(
                    env, "NET-005", res, key=f"latent:{res['id']}:{sg}:{rule['from_port']}-{rule['to_port']}",
                    severity="LOW", severity_reason="world-open rule but resource currently unreachable",
                    title=f"World-open rule on unreachable {res['id']}",
                    explanation=e["explanation"], evidence=evidence,
                    impact="The rule is a latent risk: a later routing or addressing change would expose the resource.",
                    recommendation="Remove or restrict the rule so it cannot become exploitable.", plan=plan))
            continue
        label = ", ".join(SENSITIVE_PORTS.get(p, str(p)) for p in e["sensitive_ports"])
        base = {"rule_summary": network.describe_rule(rule)}
        if e["all_ports"]:
            sev, why = _sev(env, res, "CRITICAL", prod_bump=False)
            out.append(_finding(
                env, "NET-004", res, key=f"{res['id']}:{sg}", severity=sev, severity_reason=why,
                title=f"All ports open to the internet on {res['name']}", explanation=e["explanation"], evidence={**evidence, **base},
                impact="Every service on the host can be probed and attacked from any address.",
                recommendation="Remove the all-traffic rule and allow only the ports and sources that are required.", plan=plan))
            continue
        covered = e["sensitive_ports"]
        if 22 in covered:
            sev, why = _sev(env, res, "HIGH")
            out.append(_finding(
                env, "NET-001", res, key=f"{res['id']}:{sg}", severity=sev, severity_reason=why,
                title=f"SSH is reachable from the internet on {res['name']}", explanation=e["explanation"], evidence={**evidence, **base},
                impact="Brute-force and credential-stuffing attacks can target the SSH service directly.",
                recommendation=f"Remove tcp/22 from 0.0.0.0/0 or restrict it to a trusted range such as {TRUSTED_ADMIN_CIDR}.", plan=plan))
        if 3389 in covered:
            sev, why = _sev(env, res, "HIGH")
            out.append(_finding(
                env, "NET-002", res, key=f"{res['id']}:{sg}", severity=sev, severity_reason=why,
                title=f"RDP is reachable from the internet on {res['name']}", explanation=e["explanation"], evidence={**evidence, **base},
                impact="Exposed RDP is a common ransomware entry point.",
                recommendation="Remove tcp/3389 from 0.0.0.0/0 and use a VPN or bastion with MFA.", plan=plan))
        other = [p for p in covered if p in DATABASE_PORTS or p in (23, 445)]
        if other:
            sev, why = _sev(env, res, "HIGH", prod_bump=True, extra="resource is a database" if res["type"] == "rds_instance" else None)
            if res["type"] == "rds_instance" and env.tag(res, "environment") != "prod":
                sev, why = "CRITICAL", "base HIGH raised one level because the resource is a database"
            out.append(_finding(
                env, "NET-003", res, key=f"{res['id']}:{sg}", severity=sev, severity_reason=why,
                title=f"{label or 'Service'} reachable from the internet on {res['name']}", explanation=e["explanation"],
                evidence={**evidence, **base, "ports": other}, impact="Data stores and admin services should never accept connections from the whole internet.",
                recommendation="Remove the world-open rule and connect through private networking.", plan=plan))
    return out


def rule_topology(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for issue in ctx["topology_issues"]:
        subnet = env.resources["subnet"].get(issue["subnet_id"])
        if issue["kind"] == "private_subnet_public":
            rt = env.get(issue["route_table"], "route_table")
            plan = remediation(f"Delete the 0.0.0.0/0 route from {rt['id']}",
                               [op("route.delete", rt["id"], {"destination": "0.0.0.0/0"},
                                   f"Remove the default route from {rt['name']}")],
                               "Instances in the private tier that depend on this route lose internet access.")
            out.append(_finding(
                env, "NET-006", subnet, key=subnet["id"], severity="HIGH", severity_reason="base severity HIGH",
                title=f"Private subnet {subnet['name']} is routed to the internet",
                explanation=f"Subnet {subnet['id']} is tagged tier=private but {issue['detail']}.",
                evidence={"subnet": subnet["id"], "route_table": issue["route_table"], "detail": issue["detail"]},
                impact="Anything placed in this tier can be given a public address and become reachable.",
                recommendation="Remove the internet route from the private route table.", plan=plan))
        else:
            ref = env.get(issue["resource_id"]) if issue.get("resource_id") else subnet
            out.append(_finding(
                env, "NET-005", ref, key=f"{issue['kind']}:{ref['id']}", severity="LOW",
                severity_reason="configuration inconsistency without confirmed exposure",
                title="Inconsistent network configuration", explanation=issue["detail"], evidence=issue,
                impact="Addressing and routing disagree, which usually hides a misconfiguration.",
                recommendation="Align the subnet routing with the intended public or private tier.",
                plan=manual("Review routing and addressing", "Needs a human decision about the intended design.")))
    return out


def rule_outbound(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    factor = env.thresholds["traffic_spike_factor"]
    for inst in env.of("ec2_instance"):
        if inst["state"] != "running":
            continue
        series = env.metrics.get(inst["id"], {}).get("net_out_gb", {})
        days = sorted(series)
        if len(days) < 6:
            continue
        recent, base = [series[d] for d in days[-3:]], [series[d] for d in days[:-3]][-14:]
        avg_recent, avg_base = sum(recent) / len(recent), sum(base) / len(base)
        profile = network.egress_profile(env, inst)
        if avg_base > 0 and avg_recent >= factor * avg_base and profile["open"]:
            out.append(_finding(
                env, "NET-008", inst, key=inst["id"], severity="HIGH", severity_reason="base severity HIGH",
                title=f"Suspicious outbound traffic from {inst['name']}",
                explanation=f"Outbound traffic averaged {avg_recent:.1f} GB/day over the last 3 days versus a {avg_base:.1f} GB/day baseline "
                            f"({avg_recent / avg_base:.0f}x) and the instance can reach the internet.",
                evidence={"recent_avg_gb": round(avg_recent, 2), "baseline_avg_gb": round(avg_base, 2),
                          "ratio": round(avg_recent / avg_base, 1), "threshold_factor": factor,
                          "egress": {k: profile[k] for k in ("route", "has_public_ip", "unrestricted")},
                          "daily_net_out_gb": {d: series[d] for d in days[-6:]}},
                impact="Large unexplained egress can indicate data exfiltration or a compromised host, and it adds data-transfer cost.",
                recommendation="Isolate the instance, investigate, and restrict outbound rules.",
                plan=remediation(f"Move {inst['name']} into a quarantine security group", [
                    op("ec2.isolate", inst["id"], {}, f"Replace the security groups of {inst['id']} with a no-traffic quarantine group")],
                    "The workload becomes unreachable while isolated.", downtime=True)))
    return out


# ---------------------------------------------------------------------- data
def rule_s3(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for b in env.of("s3_bucket"):
        confidential = env.tag(b, "data_classification") == "confidential"
        public = (not b["block_public_access"]) and (b["acl"] == "public-read" or b.get("policy_public"))
        if public:
            sev = "CRITICAL" if confidential else "HIGH"
            out.append(_finding(
                env, "S3-001", b, key=b["id"], severity=sev,
                severity_reason="data_classification=confidential" if confidential else "base severity HIGH",
                title=f"Bucket {b['name']} is publicly accessible",
                explanation=f"Block Public Access is off and the bucket allows public reads (ACL={b['acl']}, public policy={b.get('policy_public')}).",
                evidence={"block_public_access": b["block_public_access"], "acl": b["acl"], "policy_public": b.get("policy_public"),
                          "size_gb": b["size_gb"], "objects": b["object_count"], "tags": b["tags"]},
                impact=f"Anyone on the internet can read the {b['size_gb']:.0f} GB stored in this bucket.",
                recommendation="Enable Block Public Access and reset the ACL to private.",
                plan=remediation(f"Make {b['name']} private", [op("s3.make_private", b["id"], {}, "Enable Block Public Access, ACL private, remove public policy")],
                                 "Applications or websites that read this bucket anonymously will start receiving 403 errors.")))
        if b["encryption"] == "none":
            sev = "HIGH" if confidential else "MEDIUM"
            out.append(_finding(
                env, "ENC-002", b, key=b["id"], severity=sev, severity_reason="data_classification=confidential" if confidential else "base severity MEDIUM",
                title=f"Bucket {b['name']} has no default encryption", explanation="Default server-side encryption is not configured.",
                evidence={"encryption": b["encryption"], "tags": b["tags"], "size_gb": b["size_gb"]},
                impact="Objects are stored in clear text at rest.", recommendation="Enable default AES-256 or KMS encryption.",
                plan=remediation(f"Enable AES-256 on {b['name']}", [op("s3.enable_encryption", b["id"], {"algorithm": "AES256"}, "Enable SSE-S3")],
                                 "No application impact; existing objects are not re-encrypted.")))
    return out


def rule_encryption_backup(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for v in env.of("ebs_volume"):
        if not v["encrypted"]:
            sev, why = _sev(env, v, "MEDIUM")
            out.append(_finding(
                env, "ENC-001", v, key=v["id"], severity=sev, severity_reason=why, title=f"Volume {v['name']} is not encrypted",
                explanation=f"EBS volume {v['id']} ({v['size_gb']} GB, {v['state']}) has encryption disabled.",
                evidence={"encrypted": False, "attached_to": v["attached_to"], "tags": v["tags"]},
                impact="Data on the volume and its snapshots is readable if the media is accessed outside the instance.",
                recommendation="Enable encryption (snapshot, copy encrypted, replace in real AWS).",
                plan=remediation(f"Encrypt {v['id']}", [op("ebs.enable_encryption", v["id"], {}, "Enable EBS encryption")],
                                 "Real AWS needs a snapshot-copy-replace cycle; the simulator models it as an in-place change.")))
    for d in env.of("rds_instance"):
        if not d["storage_encrypted"]:
            sev, why = _sev(env, d, "HIGH", prod_bump=False)
            out.append(_finding(
                env, "ENC-003", d, key=d["id"], severity=sev, severity_reason=why, title=f"Database {d['name']} is not encrypted",
                explanation="RDS storage encryption is disabled.", evidence={"storage_encrypted": False, "engine": d["engine"], "tags": d["tags"]},
                impact="Database files, backups and replicas are stored unencrypted.", recommendation="Enable storage encryption.",
                plan=remediation(f"Encrypt {d['name']}", [op("rds.enable_encryption", d["id"], {}, "Enable RDS storage encryption")],
                                 "Real AWS requires snapshot restore; modelled here as an in-place change.")))
        if d["backup_retention_days"] == 0:
            sev, why = _sev(env, d, "MEDIUM")
            out.append(_finding(
                env, "BKP-001", d, key=d["id"], severity=sev, severity_reason=why, title=f"Database {d['name']} has no automated backups",
                explanation="backup_retention_days is 0, so no point-in-time recovery is possible.",
                evidence={"backup_retention_days": 0, "last_backup_at": d.get("last_backup_at"), "tags": d["tags"]},
                impact="A failure or accidental deletion cannot be recovered.", recommendation="Set the retention period to at least 7 days.",
                plan=remediation(f"Enable 7-day backups on {d['name']}", [op("rds.set_backup_retention", d["id"], {"days": 7}, "Set retention to 7 days")],
                                 "Minor performance impact during the backup window.")))
    limit = env.thresholds["backup_max_age_days"]
    snaps_by_vol: dict[str, list[dict[str, Any]]] = {}
    for s in env.of("snapshot"):
        snaps_by_vol.setdefault(s["volume_id"], []).append(s)
    for v in env.of("ebs_volume"):
        if v["attached_to"] and env.tag(v, "environment") == "prod" and v["backup_policy"] == "none":
            snaps = snaps_by_vol.get(v["id"], [])
            newest = max((parse_iso(s["created_at"]) for s in snaps), default=None)
            age = (env.sim_time - newest).days if newest else None
            if age is None or age > limit:
                sev = "HIGH" if age is None else "MEDIUM"
                out.append(_finding(
                    env, "BKP-002", v, key=v["id"], severity=sev, severity_reason="no snapshot has ever been taken" if age is None else "base severity MEDIUM",
                    title=f"Production volume {v['name']} has no recent backup",
                    explanation=f"No backup schedule is configured and the newest snapshot is {'missing' if age is None else f'{age} days old'} (limit {limit} days).",
                    evidence={"backup_policy": v["backup_policy"], "snapshot_count": len(snaps), "newest_snapshot_age_days": age, "limit_days": limit},
                    impact="Data written since the last snapshot would be lost on volume failure.",
                    recommendation="Configure a daily snapshot schedule.",
                    plan=remediation(f"Schedule daily backups for {v['id']}", [op("ebs.set_backup_policy", v["id"], {"policy": "daily"}, "Enable daily snapshots and take the first one")],
                                     "Snapshot storage adds a small monthly cost.")))
    return out


# ------------------------------------------------------------------ identity
def rule_iam(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    analysis = ctx["iam"]
    th = env.config["iam"]
    rows = {r["id"]: r for r in analysis["principals"]}
    for pid, row in rows.items():
        p = env.get(pid)
        if row["admin"] and not row["designated_admin"]:
            pols = row["admin_policies"]
            plan = remediation(f"Detach {pols[0]} from {p['name']}" if pols else "Review inline permissions",
                               [op("iam.detach_policy", pid, {"policy_id": pols[0]}, f"Detach {pols[0]}")] if pols else [],
                               "Workloads or people relying on these permissions will lose access; grant least-privilege policies first.") \
                if pols else manual("Remove wildcard permissions", "Permissions come from multiple policies.")
            out.append(_finding(
                env, "IAM-001", p, key=pid, severity="HIGH", severity_reason="base severity HIGH",
                title=f"{p['name']} has unapproved administrator access",
                explanation=f"{p['name']} holds Action '*' on Resource '*' via {', '.join(pols) or 'its policies'} but is not a designated administrator.",
                evidence={"admin_policies": pols, "designated": False, "principal_type": p["type"], "policies": p["policy_ids"]},
                impact="A compromise of this identity gives full control of the account.",
                recommendation="Replace the wildcard policy with least-privilege permissions.", plan=plan))
        if p["type"] == "iam_user":
            if th["mfa_required"] and p["console_access"] and not p["mfa_enabled"]:
                sev = "HIGH" if row["admin"] else "MEDIUM"
                out.append(_finding(
                    env, "IAM-002", p, key=pid, severity=sev, severity_reason="user is an administrator" if row["admin"] else "base severity MEDIUM",
                    title=f"{p['name']} has console access without MFA", explanation="MFA is required but not enabled for this console user.",
                    evidence={"console_access": True, "mfa_enabled": False, "admin": row["admin"]},
                    impact="A stolen or guessed password is enough to sign in.", recommendation="Enrol an MFA device.",
                    plan=remediation(f"Enable MFA for {p['name']}", [op("iam.enable_mfa", pid, {}, "Enrol a virtual MFA device")],
                                     "The user must register a device at next sign-in.")))
            for k in row["keys"]:
                if k["reasons"]:
                    sev = "HIGH" if row["admin"] else "MEDIUM"
                    out.append(_finding(
                        env, "IAM-003", p, key=f"{pid}:{k['key_id']}", severity=sev,
                        severity_reason="user is an administrator" if row["admin"] else "base severity MEDIUM",
                        title=f"Access key {k['key_id'][:8]}... of {p['name']} needs attention", explanation="; ".join(k["reasons"]).capitalize() + ".",
                        evidence=k, impact="Long-lived or forgotten credentials are a common source of leaks.",
                        recommendation="Rotate or deactivate the key.",
                        plan=remediation(f"Deactivate key {k['key_id'][:8]}...", [op("iam.deactivate_access_key", pid, {"key_id": k["key_id"]}, "Deactivate the key")],
                                         "Automation using the key will fail until a new key is issued.")))
        else:
            for risky in row["risky_trust"]:
                sev = "CRITICAL" if risky["principal"] == "*" else "HIGH"
                out.append(_finding(
                    env, "IAM-004", p, key=f"{pid}:{risky['principal']}", severity=sev,
                    severity_reason="trust policy allows any principal" if sev == "CRITICAL" else "base severity HIGH",
                    title=f"Role {p['name']} has a risky trust relationship", explanation=risky["reason"].capitalize() + ".",
                    evidence={"trust": p["trust"], "risky_principal": risky["principal"]},
                    impact="Outsiders may assume the role and use its permissions.", recommendation="Restrict the trust policy to known principals.",
                    plan=remediation(f"Restrict trust of {p['name']}", [op("iam.restrict_trust", pid, {}, "Remove wildcard and external principals")],
                                     "Legitimate external partners must be re-added with an ExternalId condition.")))
    by_target: dict[str, list[dict[str, Any]]] = {}
    for path in analysis["escalation_paths"]:
        by_target.setdefault(path["target"], []).append(path)
    for target, paths in sorted(by_target.items()):
        origins = [p["origin"] for p in paths]
        anchor = env.get(target) if env.exists(target) else None
        plan = manual("Break the escalation chain", "Choose which permission or trust link to remove; the simulator does not guess.")
        if anchor is not None:
            pols = iam.admin_policies(env, anchor)
            if pols and (anchor.get("tags") or {}).get("admin") != "designated":
                plan = remediation(f"Remove administrator access from {anchor['name']}",
                                   [op("iam.detach_policy", target, {"policy_id": pols[0]}, f"Detach {pols[0]} from {anchor['name']}")],
                                   "Removes the privileged end of every chain; the role loses its administrative permissions.")
        label = anchor["name"] if anchor else "administrator access"
        out.append(_finding(
            env, "IAM-005", anchor, key=target, severity="HIGH", severity_reason="base severity HIGH",
            title=f"{len(origins)} identit{'y' if len(origins) == 1 else 'ies'} can escalate to {label}",
            explanation="; ".join(p["description"] for p in paths[:3]) + (f"; and {len(paths) - 3} more" if len(paths) > 3 else ""),
            evidence={"origins": origins, "paths": [{"origin": p["origin"], "steps": p["steps"]} for p in paths]},
            impact="Non-admin identities can obtain full account control without being granted it directly.",
            recommendation="Remove the permission or trust link that enables the first step, or the admin rights at the end.", plan=plan,
            resource_id=target))
    th_n = th["excessive_admin_threshold"]
    admins = analysis["admin_principals"]
    if len(admins) > th_n:
        out.append(_finding(
            env, "IAM-006", None, key="account", severity="MEDIUM", severity_reason="base severity MEDIUM",
            title=f"{len(admins)} principals have full administrator access", explanation=f"The account has {len(admins)} administrators; the limit is {th_n}.",
            evidence={"administrators": admins, "threshold": th_n}, impact="A wide administrator group enlarges the blast radius of any compromise.",
            recommendation="Reduce administrators to the minimum required.",
            plan=manual("Reduce administrators", "Deciding who keeps admin rights is a policy decision.")))
    return out


def rule_cost(env: Environment, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for a in ctx["cost_anomalies"]:
        if not a["active"] or a["scope"] != "total":
            continue
        sev = "HIGH" if a["increase_pct"] >= 100 else "MEDIUM"
        out.append(_finding(
            env, "COST-001", None, key="total", severity=sev,
            severity_reason="increase of 100% or more" if sev == "HIGH" else "base severity MEDIUM",
            title=f"Daily cost jumped {a['increase_pct']:.0f}% above baseline",
            explanation=f"On {a['date']} the account cost ${a['value']:.2f} versus a ${a['baseline_mean']:.2f} baseline (z={a['zscore']}).",
            evidence=a, impact="Unplanned spend and, possibly, unauthorised resource use.",
            recommendation="Review the top contributing resources and stop anything not expected.",
            plan=manual("Investigate the contributing resources", "Whether the spend is legitimate requires human judgement.")))
    return out


RULE_FUNCS: list[Callable[[Environment, dict[str, Any]], list[dict[str, Any]]]] = [
    rule_exposure, rule_topology, rule_outbound, rule_s3, rule_encryption_backup, rule_iam, rule_cost]


def build_context(env: Environment) -> dict[str, Any]:
    return {"exposures": network.exposures(env), "topology_issues": network.topology_issues(env),
            "iam": iam.analyze(env), "cost_anomalies": cost.detect_anomalies(env)}


def evaluate(env: Environment, ctx: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run every rule. Pure: does not modify the environment."""
    ctx = ctx or build_context(env)
    findings: dict[str, dict[str, Any]] = {}
    for fn in RULE_FUNCS:
        for f in fn(env, ctx):
            findings.setdefault(f["finding_key"], f)
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    return sorted(findings.values(), key=lambda f: (order[f["severity"]], f["rule_id"], f["resource_id"]))


def score(findings: list[dict[str, Any]]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s: 0 for s in reversed(SEVERITIES)}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


def rules_catalog() -> list[dict[str, Any]]:
    return [{"rule_id": k, **v} for k, v in RULES.items()]
