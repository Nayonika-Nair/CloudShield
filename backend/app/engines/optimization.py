"""Cost optimisation recommendations backed by metrics and the simulated price list."""

from __future__ import annotations

from typing import Any

from app.engines import cost
from app.engines.security import manual, op, remediation
from app.simulator import billing
from app.simulator.catalog import EC2_FAMILIES, EC2_TYPES, MONTH_DAYS, RDS_CLASSES
from app.simulator.env import Environment, parse_iso

MIN_POINTS = 5


def stats(env: Environment, rid: str, metric: str, window: int, since: str | None = None) -> dict[str, float] | None:
    """Window statistics; points before ``since`` (a resize) are ignored because they describe the old size."""
    cutoff = since[:10] if since else None
    pts = [v for d, v in env.metric_series(rid, metric, window) if cutoff is None or d >= cutoff]
    if len(pts) < MIN_POINTS:
        return None
    return {"avg": round(sum(pts) / len(pts), 2), "max": round(max(pts), 2), "min": round(min(pts), 2), "days": len(pts)}


def _priority(savings: float) -> str:
    return "HIGH" if savings >= 100 else "MEDIUM" if savings >= 20 else "LOW"


def _rec(rule_id: str, rtype_title: str, res: dict[str, Any], *, key: str | None = None, title: str, reason: str,
         evidence: dict[str, Any], current: float, savings: float, assumptions: list[str], risk: str,
         action: str, plan: dict[str, Any], confidence: float) -> dict[str, Any]:
    return {
        "rec_key": f"{rule_id}:{key or res['id']}", "rule_id": rule_id, "category": "COST", "type": rtype_title,
        "title": title, "resource_id": res["id"], "resource_type": res["type"], "resource_name": res.get("name", res["id"]),
        "reason": reason, "evidence": evidence, "current_monthly_cost": round(current, 2),
        "estimated_monthly_savings": round(max(savings, 0.0), 2), "assumptions": assumptions, "risk": risk,
        "recommended_action": action, "remediation": plan, "priority": _priority(savings), "confidence": confidence,
        "savings_basis": "ESTIMATED",
    }


def _smaller_type(env: Environment, inst: dict[str, Any], avg: float, mx: float, mem_avg: float | None) -> str | None:
    family = inst["instance_type"].split(".")[0]
    ladder = EC2_FAMILIES.get(family, [])
    if inst["instance_type"] not in ladder:
        return None
    vcpu_old, mem_old, _ = EC2_TYPES[inst["instance_type"]]
    best = None
    for cand in ladder[: ladder.index(inst["instance_type"])]:
        vcpu, mem, _ = EC2_TYPES[cand]
        if avg * vcpu_old / vcpu <= 60 and mx * vcpu_old / vcpu <= 80 and (mem_avg is None or mem_avg * mem_old / mem <= 80):
            if best is None or billing.ec2_hourly(env, cand) < billing.ec2_hourly(env, best):
                best = cand
    return best


def recommend(env: Environment, anomalies: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    th = env.thresholds
    window = th["metric_window_days"]
    recs: list[dict[str, Any]] = []
    rate = cost.monthly_run_rate(env)["by_resource"]

    for inst in env.of("ec2_instance"):
        if inst["state"] != "running":
            continue
        since = inst.get("config_changed_at")
        cpu, net = stats(env, inst["id"], "cpu", window, since), stats(env, inst["id"], "net_out_gb", window, since)
        if cpu is None:
            continue
        mem = stats(env, inst["id"], "mem", window, since)
        compute = billing.ec2_hourly(env, inst["instance_type"]) * 24 * MONTH_DAYS
        running_cost = sum(cost.resource_daily_run_rate(env, inst).values()) * MONTH_DAYS  # compute + data transfer
        evidence = {"cpu_avg_pct": cpu["avg"], "cpu_max_pct": cpu["max"], "net_out_avg_gb": net["avg"] if net else None,
                    "days_observed": cpu["days"], "instance_type": inst["instance_type"]}
        if cpu["avg"] < th["idle_cpu_avg_pct"] and cpu["max"] < th["idle_cpu_max_pct"] and (net is None or net["avg"] < 2.0):
            recs.append(_rec(
                "OPT-001", "Idle instance", inst, title=f"Stop idle instance {inst['name']}",
                reason=f"CPU averaged {cpu['avg']}% (max {cpu['max']}%) over {cpu['days']} days, below the idle thresholds "
                       f"({th['idle_cpu_avg_pct']}% avg / {th['idle_cpu_max_pct']}% max).",
                evidence=evidence, current=rate.get(inst["id"], compute), savings=running_cost,
                assumptions=["Savings equal the instance's compute charge (24h x simulated hourly price x 30 days) plus its data-transfer charge.",
                             "Attached EBS volumes keep being billed while the instance is stopped."],
                risk="The workload becomes unavailable until restarted; restart takes seconds in the simulator.",
                action="Stop the instance (or terminate it if it is confirmed unused).",
                plan=remediation(f"Stop {inst['name']}", [op("ec2.stop", inst["id"], {}, "Stop the idle instance")],
                                 "Services on this host go offline.", downtime=True), confidence=0.9))
            continue
        if cpu["avg"] < th["underutilized_cpu_avg_pct"] and cpu["max"] < th["underutilized_cpu_max_pct"]:
            target = _smaller_type(env, inst, cpu["avg"], cpu["max"], mem["avg"] if mem else None)
            if target:
                old_price, new_price = billing.ec2_hourly(env, inst["instance_type"]), billing.ec2_hourly(env, target)
                savings = (old_price - new_price) * 24 * MONTH_DAYS
                vold, vnew = EC2_TYPES[inst["instance_type"]][0], EC2_TYPES[target][0]
                evidence.update(proposed_type=target, projected_cpu_avg_pct=round(cpu["avg"] * vold / vnew, 1),
                                projected_cpu_max_pct=round(cpu["max"] * vold / vnew, 1))
                recs.append(_rec(
                    "OPT-002", "Oversized instance", inst, title=f"Right-size {inst['name']} to {target}",
                    reason=f"CPU averaged {cpu['avg']}% (max {cpu['max']}%) on {inst['instance_type']}; {target} would run at about "
                           f"{evidence['projected_cpu_avg_pct']}% average and {evidence['projected_cpu_max_pct']}% peak.",
                    evidence=evidence, current=rate.get(inst["id"], compute), savings=savings,
                    assumptions=["Workload is constant, so CPU scales with the inverse of vCPU count.",
                                 "Target must keep projected average CPU <= 60%, peak <= 80% and memory <= 80%."],
                    risk="Requires a stop/start cycle (a short outage) and leaves less headroom for growth.",
                    action=f"Stop, change type to {target}, start.",
                    plan=remediation(f"Resize {inst['name']} to {target}", [
                        op("ec2.stop", inst["id"], {}, "Stop (required before resize)"),
                        op("ec2.change_type", inst["id"], {"instance_type": target}, f"Change type to {target}"),
                        op("ec2.start", inst["id"], {}, "Start the instance again")],
                        "Short outage while the instance restarts.", downtime=True), confidence=0.8))

    snaps_by_vol: dict[str, list[dict[str, Any]]] = {}
    for s in env.of("snapshot"):
        snaps_by_vol.setdefault(s["volume_id"], []).append(s)

    for vol in env.of("ebs_volume"):
        if vol["state"] == "available":
            monthly = billing.fixed_daily(env, vol)["EBS"] * MONTH_DAYS
            snaps = snaps_by_vol.get(vol["id"], [])
            age = (env.sim_time - parse_iso(vol["created_at"])).days
            snap_cost = vol["size_gb"] * float(env.pricing["snapshot_gb_month"])
            ops = [op("ebs.delete", vol["id"], {}, "Delete the volume")]
            note = "A snapshot already exists, so the data remains recoverable."
            savings = monthly
            if not snaps:
                ops.insert(0, op("snapshot.create", vol["id"], {}, "Take a safety snapshot first"))
                note = "A safety snapshot is taken first because no snapshot exists; its storage cost reduces the savings."
                savings = monthly - snap_cost
            recs.append(_rec(
                "OPT-003", "Unattached volume", vol, title=f"Delete unattached volume {vol['name']}",
                reason=f"Volume is not attached to any instance (created {age} days ago) but is still billed.",
                evidence={"state": vol["state"], "size_gb": vol["size_gb"], "age_days": age, "snapshots": len(snaps)},
                current=monthly, savings=savings, assumptions=[note, "Savings = size x simulated gp price per GB-month."],
                risk="Deleting is irreversible; data is only recoverable from a snapshot.",
                action="Snapshot if needed, then delete the volume.",
                plan=remediation(f"Delete {vol['name']}", ops, "Irreversible deletion of the volume."), confidence=0.85))

    old_days = th["old_snapshot_days"]
    for snap in env.of("snapshot"):
        if snap["managed_by"] != "manual":
            continue
        age = (env.sim_time - parse_iso(snap["created_at"])).days
        if age <= old_days:
            continue
        siblings = [s for s in snaps_by_vol.get(snap["volume_id"], []) if s["id"] != snap["id"]
                    and parse_iso(s["created_at"]) > parse_iso(snap["created_at"])]
        source_gone = not env.exists(snap["volume_id"])
        if not siblings and not source_gone:
            continue
        monthly = billing.fixed_daily(env, snap)["Snapshots"] * MONTH_DAYS
        recs.append(_rec(
            "OPT-004", "Old snapshot", snap, title=f"Delete superseded snapshot {snap['id']}",
            reason=f"Snapshot is {age} days old (limit {old_days}) and {'its source volume no longer exists' if source_gone else f'{len(siblings)} newer snapshot(s) of the same volume exist'}.",
            evidence={"age_days": age, "volume_id": snap["volume_id"], "newer_snapshots": len(siblings), "source_exists": not source_gone},
            current=monthly, savings=monthly, assumptions=["Savings = full snapshot size x simulated snapshot price (no incremental discount modelled)."],
            risk="Point-in-time recovery to that date is lost.", action="Delete the snapshot.",
            plan=remediation(f"Delete {snap['id']}", [op("snapshot.delete", snap["id"], {}, "Delete the old snapshot")], "Irreversible."),
            confidence=0.8))

    for eip in env.of("elastic_ip"):
        inst = env.resources["ec2_instance"].get(eip.get("instance_id") or "")
        if inst and inst["state"] == "running":
            continue
        monthly = billing.fixed_daily(env, eip)["Elastic IP"] * MONTH_DAYS
        recs.append(_rec(
            "OPT-005", "Unused Elastic IP", eip, title=f"Release unused Elastic IP {eip['public_ip']}",
            reason="The address is not associated with a running instance, so it is billed as idle.",
            evidence={"associated_with": eip.get("instance_id"), "state": eip["state"]}, current=monthly, savings=monthly,
            assumptions=["Idle Elastic IPs are billed hourly at the simulated idle rate."],
            risk="The public address is lost and cannot be recovered.", action="Release the address.",
            plan=remediation(f"Release {eip['public_ip']}",
                             ([op("eip.disassociate", eip["id"], {}, "Disassociate from the stopped instance")] if eip.get("instance_id") else [])
                             + [op("eip.release", eip["id"], {}, "Release the address")], "Address cannot be reclaimed."), confidence=0.9))

    for db in env.of("rds_instance"):
        if db["state"] != "available":
            continue
        since = db.get("config_changed_at")
        cpu, mem = stats(env, db["id"], "cpu", window, since), stats(env, db["id"], "mem", window, since)
        if cpu is None or not (cpu["avg"] < 15 and cpu["max"] < 40):
            continue
        vold, memold, _ = RDS_CLASSES[db["instance_class"]]
        best = None
        for cls, (vc, mm, price) in RDS_CLASSES.items():
            if cls == db["instance_class"] or price >= billing.rds_hourly(env, db["instance_class"]):
                continue
            if cpu["avg"] * vold / vc <= 60 and cpu["max"] * vold / vc <= 80 and (mem is None or mem["avg"] * memold / mm <= 80):
                if best is None or price < billing.rds_hourly(env, best):
                    best = cls
        if not best:
            continue
        factor = 2 if db["multi_az"] else 1
        savings = (billing.rds_hourly(env, db["instance_class"]) - billing.rds_hourly(env, best)) * 24 * MONTH_DAYS * factor
        recs.append(_rec(
            "OPT-006", "Overprovisioned database", db, title=f"Downsize {db['name']} to {best}",
            reason=f"Database CPU averaged {cpu['avg']}% (max {cpu['max']}%) on {db['instance_class']}.",
            evidence={"cpu_avg_pct": cpu["avg"], "cpu_max_pct": cpu["max"], "days_observed": cpu["days"], "proposed_class": best,
                      "multi_az": db["multi_az"]},
            current=rate.get(db["id"], 0), savings=savings,
            assumptions=["Multi-AZ doubles the instance charge; the saving is doubled accordingly." if db["multi_az"] else "Single-AZ deployment.",
                         "Projected CPU <= 60% and memory <= 80% on the target class."],
            risk="A class change causes a brief failover/restart and reduces headroom.", action=f"Modify the instance class to {best}.",
            plan=remediation(f"Resize {db['name']} to {best}", [op("rds.modify", db["id"], {"instance_class": best}, f"Change class to {best}")],
                             "Short outage during the modification.", downtime=True), confidence=0.75))

    for inst in env.of("ec2_instance"):
        if inst["state"] == "stopped" and inst.get("stopped_at"):
            days = (env.sim_time - parse_iso(inst["stopped_at"])).days
            if days >= 30:
                vols = [env.resources["ebs_volume"][v] for v in inst["volume_ids"] if v in env.resources["ebs_volume"]]
                root = next((v for v in vols if v.get("device") == "/dev/xvda"), None)
                monthly = sum(billing.fixed_daily(env, v)["EBS"] * MONTH_DAYS for v in vols)
                savings = billing.fixed_daily(env, root)["EBS"] * MONTH_DAYS if root else 0
                recs.append(_rec(
                    "OPT-007", "Long-stopped instance", inst, title=f"Terminate {inst['name']} (stopped {days} days)",
                    reason=f"The instance has been stopped for {days} days but its {len(vols)} volume(s) are still billed.",
                    evidence={"stopped_days": days, "volumes": [v["id"] for v in vols]}, current=monthly, savings=savings,
                    assumptions=["Termination deletes the root volume; data volumes are detached and keep billing until deleted."],
                    risk="Termination is irreversible - snapshot first if the data may be needed.", action="Snapshot, then terminate.",
                    plan=remediation(f"Terminate {inst['name']}", [op("ec2.terminate", inst["id"], {}, "Terminate the stopped instance")],
                                     "Irreversible."), confidence=0.7))

    for lb in env.of("load_balancer"):
        live_targets = [t for t in lb["targets"] if env.exists(t) and env.resources["ec2_instance"][t]["state"] == "running"]
        if not live_targets:
            monthly = billing.fixed_daily(env, lb)["Load Balancing"] * MONTH_DAYS
            recs.append(_rec(
                "OPT-008", "Idle load balancer", lb, title=f"Delete idle load balancer {lb['name']}",
                reason="No running targets are registered, so the balancer forwards no traffic but is billed hourly.",
                evidence={"targets": lb["targets"], "running_targets": 0}, current=monthly, savings=monthly,
                assumptions=["Hourly + LCU charge at simulated rates for the whole month."],
                risk="DNS records pointing at the balancer will break.", action="Delete the load balancer.",
                plan=remediation(f"Delete {lb['name']}", [op("lb.delete", lb["id"], {}, "Delete the load balancer")], "Irreversible."),
                confidence=0.85))

    seen_resources = {r["resource_id"] for r in recs}
    for a in anomalies if anomalies is not None else cost.detect_anomalies(env):
        if not a["active"] or a["scope"] != "total":
            continue
        for c in a["top_contributors"][:3]:
            if not env.exists(c["resource_id"]) or c["resource_id"] in seen_resources:
                continue
            res = env.get(c["resource_id"])
            monthly = cost.resource_monthly(env, res)
            recs.append(_rec(
                "OPT-009", "Unexpected cost growth", res, title=f"Investigate cost growth of {res.get('name', res['id'])}",
                reason=f"Cost of this resource rose ${c['increase']:.2f}/day above its baseline on {a['date']}.",
                evidence={"anomaly_date": a["date"], "daily_cost": c["cost"], "baseline_daily_cost": c["baseline"]},
                current=monthly, savings=c["increase"] * MONTH_DAYS,
                assumptions=["Savings are the cost that would be avoided if the increase is not business-justified."],
                risk="Stopping a legitimate workload causes an outage.", action="Confirm ownership and purpose; stop or resize if unneeded.",
                plan=manual("Investigate the resource", "Needs a human to confirm whether the spend is expected."), confidence=0.6))
    return sorted(recs, key=lambda r: -r["estimated_monthly_savings"])


def total_savings(recs: list[dict[str, Any]]) -> float:
    """Sum of estimates, de-duplicated per resource so overlapping advice is not double counted."""
    best: dict[str, float] = {}
    for r in recs:
        best[r["resource_id"]] = max(best.get(r["resource_id"], 0.0), r["estimated_monthly_savings"])
    return round(sum(best.values()), 2)
