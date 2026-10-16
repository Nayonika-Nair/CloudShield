"""Persistence of a simulated :class:`Environment` in the relational database."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from app.sim_models import (
    SimCostDaily, SimEnvironment, SimMetric, SimRelationship, SimResource, utcnow,
)
from app.simulator.env import RESOURCE_TYPES, Environment, SimError, iso, parse_iso, relationships

_BATCH = 2000


def _hash(data: dict[str, Any]) -> str:
    return hashlib.sha1(json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _bulk(db: Session, model: Any, rows: list[dict[str, Any]]) -> None:
    for i in range(0, len(rows), _BATCH):
        db.execute(insert(model), rows[i:i + _BATCH])


def active_row(db: Session) -> SimEnvironment | None:
    return db.execute(
        select(SimEnvironment).where(SimEnvironment.status == "ACTIVE").order_by(SimEnvironment.id.desc())
    ).scalars().first()


def require_active_row(db: Session) -> SimEnvironment:
    row = active_row(db)
    if row is None:
        raise SimError("No simulated environment exists yet. Generate one first.", "no_environment", 404)
    return row


def _sync_resources(db: Session, row: SimEnvironment, env: Environment) -> None:
    existing = {r.resource_id: r for r in db.execute(
        select(SimResource).where(SimResource.environment_id == row.id)).scalars()}
    seen: set[str] = set()
    for res in env.all():
        rid = res["id"]
        seen.add(rid)
        h = _hash(res)
        rec = existing.get(rid)
        if rec is None:
            db.add(SimResource(environment_id=row.id, resource_id=rid, resource_type=res["type"],
                               name=res.get("name", rid), state=res.get("state"), region=res.get("region"),
                               data=res, data_hash=h))
        elif rec.data_hash != h:
            rec.data, rec.data_hash = res, h
            rec.name, rec.state = res.get("name", rid), res.get("state")
    for rid, rec in existing.items():
        if rid not in seen:
            db.delete(rec)
    db.execute(delete(SimRelationship).where(SimRelationship.environment_id == row.id))
    _bulk(db, SimRelationship, [{"environment_id": row.id, "source_id": s, "target_id": t, "relation": r}
                                for s, t, r in relationships(env)])


def _flush_history(db: Session, row: SimEnvironment, env: Environment) -> None:
    _bulk(db, SimMetric, [{"environment_id": row.id, "resource_id": rid, "metric": m,
                           "metric_date": date.fromisoformat(d), "value": v}
                          for rid, m, d, v in env.new_metric_rows])
    _bulk(db, SimCostDaily, [{"environment_id": row.id, "resource_id": rid, "service": svc,
                              "cost_date": date.fromisoformat(d), "amount": amt}
                             for rid, svc, d, amt in env.new_cost_rows])
    env.new_metric_rows.clear()
    env.new_cost_rows.clear()


def create_environment(db: Session, env: Environment, name: str | None = None) -> SimEnvironment:
    """Persist a freshly generated environment and archive the previously active one."""
    for old in db.execute(select(SimEnvironment).where(SimEnvironment.status == "ACTIVE")).scalars():
        old.status, old.archived_at = "ARCHIVED", utcnow()
    cfg = env.config
    row = SimEnvironment(
        name=name or cfg["name"], seed=cfg["seed"], status="ACTIVE", account_id=cfg["account_id"],
        account_name=cfg["account_name"], region=cfg["region"], config=cfg, sim_time=env.sim_time,
        state_version=1, id_counters=env.id_counters, baseline=env.baseline, baseline_time=env.baseline_time,
        fingerprint=env.fingerprint(include_history=False),
    )
    db.add(row)
    db.flush()
    _sync_resources(db, row, env)
    _flush_history(db, row, env)
    return row


def load(db: Session, row: SimEnvironment, *, history: bool = True) -> Environment:
    env = Environment(json.loads(json.dumps(row.config)), row.sim_time)
    for rec in db.execute(select(SimResource).where(SimResource.environment_id == row.id)).scalars():
        env.resources[rec.resource_type][rec.resource_id] = json.loads(json.dumps(rec.data))
    env.reindex()
    env.id_counters = dict(row.id_counters or {})
    env.baseline = row.baseline
    env.baseline_time = row.baseline_time
    if history:
        for rid, metric, d, value in db.execute(
                select(SimMetric.resource_id, SimMetric.metric, SimMetric.metric_date, SimMetric.value)
                .where(SimMetric.environment_id == row.id)):
            env.metrics.setdefault(rid, {}).setdefault(metric, {})[d.isoformat()] = value
        for rid, svc, d, amt in db.execute(
                select(SimCostDaily.resource_id, SimCostDaily.service, SimCostDaily.cost_date, SimCostDaily.amount)
                .where(SimCostDaily.environment_id == row.id)):
            env.daily_costs.setdefault(d.isoformat(), {}).setdefault(rid, {})[svc] = amt
    return env


def save(db: Session, row: SimEnvironment, env: Environment, expected_version: int) -> None:
    """Write the environment back using optimistic locking on ``state_version``."""
    res = db.execute(update(SimEnvironment)
                     .where(SimEnvironment.id == row.id, SimEnvironment.state_version == expected_version)
                     .values(state_version=expected_version + 1))
    if res.rowcount != 1:
        raise SimError("The environment was modified by another request. Reload and retry.", "conflict", 409)
    _sync_resources(db, row, env)
    _flush_history(db, row, env)
    db.expire(row)
    row = db.get(SimEnvironment, row.id)
    row.sim_time = env.sim_time
    row.id_counters = dict(env.id_counters)
    row.baseline = env.baseline
    row.baseline_time = env.baseline_time
    row.fingerprint = env.fingerprint(include_history=False)


def inventory_counts(env: Environment) -> dict[str, int]:
    return {t: env.count(t) for t in RESOURCE_TYPES}


def describe(row: SimEnvironment, env: Environment | None = None) -> dict[str, Any]:
    out = {
        "id": row.id, "name": row.name, "status": row.status, "seed": row.seed, "account_id": row.account_id,
        "account_name": row.account_name, "region": row.region, "sim_time": iso(row.sim_time),
        "state_version": row.state_version, "created_at": row.created_at.isoformat(),
        "archived_at": row.archived_at.isoformat() if row.archived_at else None,
        "fingerprint": row.fingerprint, "baseline_time": row.baseline_time,
    }
    if env is not None:
        out["counts"] = inventory_counts(env)
    return out


__all__ = ["parse_iso", "datetime"]
