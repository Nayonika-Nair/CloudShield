"""Controlled simulated time.

Time only moves when :func:`advance` is called explicitly (or by the optional
auto-advance task). Every metric and cost value is a pure function of the
seed, the resource state and the day, so results are reproducible and do not
depend on how a period was split into steps.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from typing import Any

from app.simulator import billing
from app.simulator import builders as b
from app.simulator.catalog import EC2_TYPES, RDS_CLASSES
from app.simulator.env import Environment, SimError, iso, parse_iso, unit

MAX_ADVANCE_DAYS = 90


def _day(value: str | None) -> date | None:
    return parse_iso(value).date() if value else None


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _noise(env: Environment, rid: str, key: str, day: str, amp: float) -> float:
    return 1.0 + (unit(env.seed, rid, key, day) - 0.5) * 2 * amp


def instance_state_on(inst: dict[str, Any], day: date, historical: bool) -> str | None:
    created = _day(inst["created_at"])
    if created and day < created:
        return None
    term = _day(inst.get("terminated_at"))
    if term and day >= term:
        return None
    if not historical:
        return None if inst["state"] == "terminated" else inst["state"]
    stopped = _day(inst.get("stopped_at"))
    if stopped and day >= stopped:
        return "stopped"
    return "stopped" if inst["state"] == "stopped" and not stopped else "running"


def _exists_on(res: dict[str, Any], day: date) -> bool:
    created = _day(res.get("created_at"))
    return created is None or day >= created


def compute_day(env: Environment, day: date, *, historical: bool, egress: dict[str, bool],
                today: date | None = None) -> float:
    """Record metrics and costs for one simulated day. Returns the day's total cost."""
    ds = day.isoformat()
    ref = today or env.today
    total = 0.0

    def charge(rid: str, amounts: dict[str, float]) -> None:
        nonlocal total
        for service, amount in amounts.items():
            if amount > 0:
                env.record_cost(rid, service, ds, amount)
                total += amount

    for inst in env.of("ec2_instance"):
        state = instance_state_on(inst, day, historical)
        if state is None:
            continue
        rid = inst["id"]
        out_gb = 0.0
        if state == "running":
            vcpus = EC2_TYPES[inst["instance_type"]][0]
            weekend = 0.85 if day.weekday() >= 5 and inst["profile"] in ("normal", "busy") else 1.0
            cpu = _clamp(inst["workload_vcpu"] / vcpus * 100 * weekend * _noise(env, rid, "cpu", ds, 0.15), 0.2, 99.0)
            mem = _clamp(inst["mem_pct_base"] * _noise(env, rid, "mem", ds, 0.10), 1.0, 99.0)
            mult = inst.get("traffic_multiplier", 1.0) if egress.get(rid, False) else 1.0
            out_gb = inst["net_out_gb_base"] * _noise(env, rid, "out", ds, 0.25) * mult
            in_gb = inst["net_in_gb_base"] * _noise(env, rid, "in", ds, 0.25)
            env.record_metric(rid, "cpu", ds, cpu)
            env.record_metric(rid, "mem", ds, mem)
            env.record_metric(rid, "net_in_gb", ds, in_gb)
            env.record_metric(rid, "net_out_gb", ds, out_gb)
        amounts = billing.fixed_daily(env, inst, state=state)
        dt = billing.data_transfer_daily(env, out_gb)
        charge(rid, amounts)
        if dt > 0:
            charge(rid, {"Data Transfer": dt})

    for vol in env.of("ebs_volume"):
        if not _exists_on(vol, day):
            continue
        age = (ref - day).days if historical else 0
        used = _clamp(vol["used_pct_base"] - age * 0.02, 1, 99)
        env.record_metric(vol["id"], "used_pct", ds, used)
        charge(vol["id"], billing.fixed_daily(env, vol))

    for snap in env.of("snapshot"):
        if _exists_on(snap, day):
            charge(snap["id"], billing.fixed_daily(env, snap))

    for bucket in env.of("s3_bucket"):
        if not _exists_on(bucket, day):
            continue
        size = bucket["size_gb"]
        if historical:
            size = max(0.1, size - bucket["growth_gb_per_day"] * (ref - day).days)
        env.record_metric(bucket["id"], "storage_gb", ds, size)
        env.record_metric(bucket["id"], "requests", ds, bucket["requests_per_day_base"] * _noise(env, bucket["id"], "req", ds, 0.3))
        charge(bucket["id"], billing.fixed_daily(env, bucket, size_gb=size))

    for db in env.of("rds_instance"):
        if db["state"] != "available" or not _exists_on(db, day):
            continue
        vcpus = RDS_CLASSES[db["instance_class"]][0]
        cpu = _clamp(db["workload_vcpu"] / vcpus * 100 * _noise(env, db["id"], "cpu", ds, 0.15), 0.2, 99.0)
        env.record_metric(db["id"], "cpu", ds, cpu)
        env.record_metric(db["id"], "mem", ds, _clamp(db["mem_pct_base"] * _noise(env, db["id"], "mem", ds, 0.1), 1, 99))
        env.record_metric(db["id"], "connections", ds, db["conn_base"] * _noise(env, db["id"], "conn", ds, 0.3))
        st = db["storage_used_pct_base"] + (0 if historical else 0)
        env.record_metric(db["id"], "storage_used_pct", ds, _clamp(st - ((ref - day).days * 0.02 if historical else 0), 1, 99))
        charge(db["id"], billing.fixed_daily(env, db))

    for eip in env.of("elastic_ip"):
        if _exists_on(eip, day):
            charge(eip["id"], billing.fixed_daily(env, eip))
    for lb in env.of("load_balancer"):
        if _exists_on(lb, day):
            charge(lb["id"], billing.fixed_daily(env, lb))
    return total


def _egress_map(env: Environment) -> dict[str, bool]:
    from app.engines.network import egress_open

    return {i["id"]: egress_open(env, i) for i in env.of("ec2_instance") if i["state"] == "running"}


def backfill(env: Environment, days: int) -> None:
    """Generate ``days`` of history ending the day before ``sim_time``."""
    if days <= 0:
        return
    egress = _egress_map(env)
    for back in range(days, 0, -1):
        compute_day(env, env.today - timedelta(days=back), historical=True, egress=egress)


def _auto_actions(env: Environment, day: date) -> dict[str, int]:
    """Policy-driven side effects that happen at the start of a simulated day."""
    made = expired = 0
    day_dt = datetime.combine(day, time(0, 0))
    snaps_by_volume: dict[str, list[dict[str, Any]]] = {}
    for snap in env.of("snapshot"):
        if snap["managed_by"] == "backup_policy":
            snaps_by_volume.setdefault(snap["volume_id"], []).append(snap)
    for vol in env.of("ebs_volume"):
        policy = vol.get("backup_policy", "none")
        if policy == "none" or not vol.get("attached_to"):
            continue
        existing = snaps_by_volume.get(vol["id"], [])
        last = max((_day(s["created_at"]) for s in existing), default=None)
        interval = 1 if policy == "daily" else 7
        if last is None or (day - last).days >= interval:
            b.build_snapshot(env, vol, managed_by="backup_policy", created_at=day_dt)
            made += 1
        keep_days = 14 if policy == "daily" else 35
        for snap in existing:
            if (day - _day(snap["created_at"])).days > keep_days:
                env.remove(snap["id"])
                expired += 1
    for db in env.of("rds_instance"):
        if db["state"] == "available" and db["backup_retention_days"] > 0:
            db["last_backup_at"] = iso(day_dt + timedelta(hours=3))
    for user in env.of("iam_user"):
        for key in user["access_keys"]:
            if key["status"] == "active" and key.get("usage") == "active":
                key["last_used"] = iso(day_dt)
    for bucket in env.of("s3_bucket"):
        bucket["size_gb"] = round(bucket["size_gb"] + bucket["growth_gb_per_day"], 2)
        bucket["object_count"] = int(bucket["size_gb"] * 800)
    return {"snapshots_created": made, "snapshots_expired": expired}


def advance(env: Environment, days: int = 1) -> dict[str, Any]:
    """Move simulated time forward by whole days, accruing metrics and billing."""
    if not isinstance(days, int) or isinstance(days, bool) or days < 1 or days > MAX_ADVANCE_DAYS:
        raise SimError(f"days must be an integer between 1 and {MAX_ADVANCE_DAYS}", "invalid_parameter", 422)
    start = env.sim_time
    totals = {"snapshots_created": 0, "snapshots_expired": 0}
    cost = 0.0
    for _ in range(days):
        day = env.today
        actions = _auto_actions(env, day)
        for k, v in actions.items():
            totals[k] += v
        egress = _egress_map(env)
        cost += compute_day(env, day, historical=False, egress=egress)
        env.sim_time = env.sim_time + timedelta(days=1)
    return {"from": iso(start), "to": iso(env.sim_time), "days": days, "cost_accrued": round(cost, 2), **totals}
