"""Application services that coordinate the simulator, engines, database and audit trail."""

from __future__ import annotations

import copy
from datetime import timedelta
from typing import Any, Callable

from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.engines import analysis, cost, drift, iam, network, remediation as rem_engine, whatif
from app.services import audit, env_store
from app.services.scan import finding_dict, rec_dict, run_scan, scan_dict
from app.sim_models import (
    SimEnvironment, SimFinding, SimRecommendation, SimRemediation, SimScan, SimScenarioExecution, SimWhatIf, utcnow,
)
from app.simulator import lifecycle, scenarios, timeengine
from app.simulator.config import SimConfig, preset_config
from app.simulator.env import Environment, SimError, diff_resources, iso
from app.simulator.generator import generate_environment


# ------------------------------------------------------------------ helpers
def _validation_error(exc: ValidationError) -> SimError:
    parts = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"])
        parts.append(f"{loc}: {err['msg']}")
    return SimError("Invalid configuration - " + "; ".join(parts), "invalid_configuration", 422)


def get_state(db: Session, *, history: bool = False) -> tuple[SimEnvironment, Environment]:
    row = env_store.require_active_row(db)
    return row, env_store.load(db, row, history=history)


def mutate(db: Session, actor: str | None, audit_action: str, fn: Callable[[Environment], Any], *,
           target_type: str | None = None, target_id: str | None = None, details: dict[str, Any] | None = None,
           history: bool = False,
           on_success: Callable[[SimEnvironment, Environment, Any, dict[str, Any]], None] | None = None,
           ) -> tuple[SimEnvironment, Environment, Any, dict[str, Any]]:
    """Run ``fn`` on the active environment as one audited, transactional state change."""
    row = env_store.require_active_row(db)
    env = env_store.load(db, row, history=history)
    version = row.state_version
    before = env.snapshot_resources()
    try:
        result = fn(env)
        diff = diff_resources(before, env.resources)
        env_store.save(db, row, env, version)
    except SimError as exc:
        db.rollback()
        row = db.get(SimEnvironment, row.id)
        audit.record(db, env_row=row, actor=actor, action=audit_action, target_type=target_type, target_id=target_id,
                     outcome="REJECTED", details={**(details or {}), "error": exc.message, "code": exc.code})
        db.commit()
        raise
    row = db.get(SimEnvironment, row.id)
    b, a = audit.before_after(diff, before, env.resources)
    detail = {**(details or {})}
    if isinstance(result, dict):
        for k in ("message", "messages", "targets", "from", "to", "days", "cost_accrued"):
            if k in result:
                detail[k] = result[k]
    audit.record(db, env_row=row, actor=actor, action=audit_action, target_type=target_type, target_id=target_id,
                 before=b or None, after=a or None, details=detail)
    if on_success:
        on_success(row, env, result, diff)
    db.commit()
    return row, env, result, diff


# -------------------------------------------------------------- environment
def generate(db: Session, actor: str | None, config: dict[str, Any] | None, *, preset: str | None = None,
             name: str | None = None) -> dict[str, Any]:
    try:
        cfg = preset_config(preset, **(config or {})) if preset else SimConfig.model_validate(config or {})
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    except ValueError as exc:
        raise SimError(str(exc), "invalid_configuration", 422) from exc
    env = generate_environment(cfg)
    row = env_store.create_environment(db, env, name)
    audit.record(db, env_row=row, actor=actor, action="ENVIRONMENT_GENERATED", target_type="environment",
                 target_id=str(row.id), details={"seed": cfg.seed, "preset": cfg.preset, "region": cfg.region,
                                                 "counts": env_store.inventory_counts(env),
                                                 "fingerprint": env.fingerprint(include_history=False)[:16]})
    scan, _ = run_scan(db, row, env, trigger="environment_generated", actor=actor)
    db.commit()
    return {"environment": env_store.describe(row, env), "initial_scan": scan_dict(scan)}


def regenerate(db: Session, actor: str | None) -> dict[str, Any]:
    row = env_store.require_active_row(db)
    result = generate(db, actor, copy.deepcopy(row.config), name=row.name)
    new_row = env_store.require_active_row(db)
    audit.record(db, env_row=new_row, actor=actor, action="ENVIRONMENT_RESET", target_type="environment",
                 target_id=str(new_row.id), details={"previous_environment_id": row.id})
    db.commit()
    return result


def update_config(db: Session, actor: str | None, patch: dict[str, Any]) -> dict[str, Any]:
    allowed = {"pricing", "thresholds"}
    bad = set(patch) - allowed
    if bad:
        raise SimError(f"Only {sorted(allowed)} can be changed on a live environment; regenerate to change {sorted(bad)}",
                       "invalid_configuration", 422)
    row = env_store.require_active_row(db)
    merged = copy.deepcopy(row.config)
    for section, values in patch.items():
        if not isinstance(values, dict):
            raise SimError(f"'{section}' must be an object", "invalid_configuration", 422)
        merged[section].update(values)
    try:
        SimConfig.model_validate(merged)
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    old = {s: copy.deepcopy(row.config[s]) for s in patch}
    version = row.state_version
    row.config = merged
    audit.record(db, env_row=row, actor=actor, action="CONFIG_CHANGED", target_type="environment", target_id=str(row.id),
                 before={s: old[s] for s in patch}, after={s: merged[s] for s in patch})
    from sqlalchemy import update
    db.execute(update(SimEnvironment).where(SimEnvironment.id == row.id).values(state_version=version + 1))
    db.commit()
    return env_store.describe(db.get(SimEnvironment, row.id))


def environment_summary(db: Session) -> dict[str, Any]:
    row, env = get_state(db)
    out = env_store.describe(row, env)
    out["config"] = row.config
    return out


# ------------------------------------------------------------------- actions
def run_action(db: Session, actor: str | None, action: str, target_id: str | None, params: dict[str, Any]) -> dict[str, Any]:
    spec = lifecycle.OPS.get(action)
    target_type = spec.target_type if spec and isinstance(spec.target_type, str) else None
    row, env, result, diff = mutate(
        db, actor, f"ACTION:{action}", lambda e: lifecycle.execute(e, action, target_id, params),
        target_type=target_type, target_id=target_id, details={"params": params})
    return {"result": result, "changes": diff, "state_version": row.state_version}


def advance_time(db: Session, actor: str | None, days: int) -> dict[str, Any]:
    row, env, result, _ = mutate(db, actor, "TIME_ADVANCED", lambda e: timeengine.advance(e, days),
                                 target_type="environment", details={"days": days})
    return {"advance": result, "sim_time": iso(env.sim_time), "state_version": row.state_version}


# ----------------------------------------------------------------- scenarios
def trigger_scenario(db: Session, actor: str | None, name: str, params: dict[str, Any], advance_days: int = 0) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    def fn(env: Environment) -> dict[str, Any]:
        res = scenarios.trigger(env, name, params)
        if advance_days:
            res["time"] = timeengine.advance(env, advance_days)
        return res

    def done(row: SimEnvironment, env: Environment, res: dict[str, Any], diff: dict[str, Any]) -> None:
        ex = SimScenarioExecution(
            environment_id=row.id, scenario=name, params=params, status="ACTIVE", actor=actor, triggered_sim=row.sim_time,
            result={"targets": res["targets"], "messages": res["messages"], "needs_time": res.get("needs_time", False),
                    "time": res.get("time")}, before=res["before"], changes=res["changes"])
        db.add(ex)
        db.flush()
        captured["id"] = ex.id

    row, env, res, _ = mutate(db, actor, "SCENARIO_TRIGGERED", fn, target_type="scenario", target_id=name,
                              details={"params": params, "advance_days": advance_days}, on_success=done)
    return {"execution_id": captured["id"], "scenario": name, "targets": res["targets"], "messages": res["messages"],
            "needs_time": res.get("needs_time", False), "sim_time": iso(env.sim_time),
            "note": "State changed. Run a scan to see the resulting findings."}


def revert_scenario(db: Session, actor: str | None, execution_id: int) -> dict[str, Any]:
    ex = db.get(SimScenarioExecution, execution_id)
    if ex is None:
        raise SimError(f"Scenario execution {execution_id} not found", "not_found", 404)
    if ex.status == "REVERTED":
        raise SimError("This scenario execution was already reverted", "invalid_state", 409)

    def fn(env: Environment) -> dict[str, Any]:
        return {"messages": scenarios.revert(env, ex.before, ex.changes)}

    def done(row: SimEnvironment, env: Environment, res: Any, diff: dict[str, Any]) -> None:
        ex.status, ex.reverted_at = "REVERTED", utcnow()

    _, _, res, _ = mutate(db, actor, "SCENARIO_REVERTED", fn, target_type="scenario", target_id=ex.scenario,
                          details={"execution_id": execution_id}, on_success=done)
    return {"execution_id": execution_id, "status": "REVERTED", "messages": res["messages"]}


def execution_dict(e: SimScenarioExecution) -> dict[str, Any]:
    return {"id": e.id, "scenario": e.scenario, "params": e.params, "status": e.status, "actor": e.actor,
            "triggered_at": e.triggered_at.isoformat(), "triggered_sim": e.triggered_sim.isoformat(),
            "targets": e.result.get("targets", []), "messages": e.result.get("messages", []),
            "reverted_at": e.reverted_at.isoformat() if e.reverted_at else None}


# --------------------------------------------------------------------- scans
def scan_now(db: Session, actor: str | None) -> dict[str, Any]:
    row, env = get_state(db, history=True)
    scan, result = run_scan(db, row, env, trigger="manual", actor=actor)
    db.commit()
    return {"scan": scan_dict(scan), "findings_open": len(result["findings"])}


def compare_scans(db: Session, a: int, b: int) -> dict[str, Any]:
    sa, sb = db.get(SimScan, a), db.get(SimScan, b)
    if sa is None or sb is None:
        raise SimError("Both scans must exist", "not_found", 404)
    ka, kb = set(sa.finding_keys), set(sb.finding_keys)
    rows = {f.finding_key: f for f in db.execute(select(SimFinding).where(
        SimFinding.environment_id == sb.environment_id)).scalars()}
    slim = lambda k: {"finding_key": k, "title": rows[k].title if k in rows else k,  # noqa: E731
                      "severity": rows[k].severity if k in rows else None}
    return {"from": scan_dict(sa), "to": scan_dict(sb), "resolved": [slim(k) for k in sorted(ka - kb)],
            "introduced": [slim(k) for k in sorted(kb - ka)], "unchanged": len(ka & kb),
            "score_delta": sb.security_score - sa.security_score,
            "run_rate_delta": round(sb.monthly_run_rate - sa.monthly_run_rate, 2)}


# --------------------------------------------------------------- remediation
def _locate(db: Session, row: SimEnvironment, kind: str, item_id: int) -> SimFinding | SimRecommendation:
    model = {"finding": SimFinding, "recommendation": SimRecommendation}.get(kind)
    if model is None:
        raise SimError("kind must be 'finding' or 'recommendation'", "invalid_parameter", 422)
    item = db.get(model, item_id)
    if item is None or item.environment_id != row.id:
        raise SimError(f"{kind} {item_id} not found in the active environment", "not_found", 404)
    return item


def _fresh_item(kind: str, item: Any, result: dict[str, Any]) -> dict[str, Any]:
    key = item.finding_key if kind == "finding" else item.rec_key
    pool = result["findings"] if kind == "finding" else result["recommendations"]
    fresh = next((x for x in pool if x.get("finding_key", x.get("rec_key")) == key), None)
    if fresh is None:
        raise SimError("This condition is no longer present in the current state. Run a new scan.", "stale", 409)
    return fresh


def preview_remediation(db: Session, actor: str | None, kind: str, item_id: int) -> dict[str, Any]:
    row, env = get_state(db, history=True)
    item = _locate(db, row, kind, item_id)
    if item.status not in ("OPEN",):
        raise SimError(f"This {kind} is {item.status} and cannot be remediated", "invalid_state", 409)
    result = analysis.analyze(env)
    fresh = _fresh_item(kind, item, result)
    plan = rem_engine.build_plan(fresh)
    if not plan["supported"]:
        return {"kind": kind, "id": item_id, "plan": plan, "supported": False, "preview": None,
                "message": "No automated remediation is available. " + plan["risk"]}
    preview = whatif.simulate(env, plan["operations"])
    run = SimWhatIf(environment_id=row.id, actor=actor, title=f"Preview: {fresh['title']}"[:200],
                    changes=plan["operations"], result=preview, baseline_fingerprint=env.fingerprint(),
                    state_version=row.state_version, status="SIMULATED")
    db.add(run)
    db.flush()
    if kind == "recommendation":
        item.simulated, item.whatif_id = True, run.id
    audit.record(db, env_row=row, actor=actor, action="REMEDIATION_PREVIEWED", target_type=kind, target_id=str(item_id),
                 details={"plan_hash": plan["plan_hash"], "whatif_id": run.id, "baseline_unchanged": preview["baseline_unchanged"]})
    db.commit()
    return {"kind": kind, "id": item_id, "supported": True, "plan": plan, "preview": preview, "whatif_id": run.id,
            "status": "PROPOSED", "message": "Proposed only - nothing has been changed. Apply requires explicit confirmation."}


def apply_remediation(db: Session, actor: str | None, kind: str, item_id: int, plan_hash: str, confirm: bool) -> dict[str, Any]:
    if confirm is not True:
        raise SimError("Explicit confirmation is required (confirm=true)", "confirmation_required", 422)
    row, env = get_state(db, history=True)
    item = _locate(db, row, kind, item_id)
    if item.status != "OPEN":
        raise SimError(f"This {kind} is {item.status} and cannot be remediated", "invalid_state", 409)
    result = analysis.analyze(env)
    fresh = _fresh_item(kind, item, result)
    plan = rem_engine.build_plan(fresh)
    if not plan["supported"]:
        raise SimError("No automated remediation is available for this item", "unsupported", 422)
    if plan["plan_hash"] != plan_hash:
        raise SimError("The proposed plan changed since it was previewed. Preview it again.", "plan_changed", 409)
    version, before = row.state_version, env.snapshot_resources()
    key = fresh.get("finding_key", fresh.get("rec_key"))
    last_scan = db.execute(select(func.max(SimScan.id)).where(SimScan.environment_id == row.id)).scalar()
    try:
        results = rem_engine.run_operations(env, plan["operations"])
        diff = diff_resources(before, env.resources)
        env_store.save(db, row, env, version)
    except SimError as exc:
        db.rollback()
        row = db.get(SimEnvironment, row.id)
        failed = SimRemediation(environment_id=row.id, target_kind=kind, target_id=item_id, target_key=key, plan=plan,
                                plan_hash=plan_hash, status="FAILED", verification="PENDING", actor=actor,
                                executed_sim=row.sim_time, message=exc.message)
        db.add(failed)
        audit.record(db, env_row=row, actor=actor, action="REMEDIATION_FAILED", target_type=kind, target_id=str(item_id),
                     outcome="REJECTED", details={"error": exc.message, "plan_hash": plan_hash})
        db.commit()
        raise
    row = db.get(SimEnvironment, row.id)
    b, a = audit.before_after(diff, before, env.resources)
    cost_before, score_before = result["monthly_run_rate"], result["security_score"]
    record = SimRemediation(
        environment_id=row.id, target_kind=kind, target_id=item_id, target_key=key, plan=plan, plan_hash=plan_hash,
        status="EXECUTED", verification="PENDING", actor=actor, executed_sim=row.sim_time,
        results=[{"action": r["action"], "target_id": r["target_id"], "message": r["message"]} for r in results],
        before=b, after=a, scan_before_id=last_scan, cost_before=cost_before, score_before=score_before,
        message="; ".join(r["message"] for r in results))
    db.add(record)
    db.flush()
    audit.record(db, env_row=row, actor=actor, action="REMEDIATION_APPLIED", target_type=kind, target_id=str(item_id),
                 before=b or None, after=a or None,
                 details={"remediation_id": record.id, "plan_hash": plan_hash, "summary": plan["summary"]})
    if kind == "recommendation":
        item.status, item.applied_at, item.remediation_id = "APPLIED", utcnow(), record.id
    # Verification: re-run the full analysis against the changed state.
    db.refresh(row)
    scan, after = run_scan(db, row, env, trigger="remediation_verification", actor=actor, remediation_id=record.id)
    still_present = key in {x.get("finding_key", x.get("rec_key")) for x in
                            (after["findings"] if kind == "finding" else after["recommendations"])}
    record.scan_after_id = scan.id
    record.cost_after, record.score_after = after["monthly_run_rate"], after["security_score"]
    record.verification = "NOT_RESOLVED" if still_present else "VERIFIED"
    record.realized_monthly_savings = round(cost_before - after["monthly_run_rate"], 2)
    if kind == "recommendation" and not still_present:
        item.realized_monthly_savings = record.realized_monthly_savings
    audit.record(db, env_row=row, actor=actor, action="REMEDIATION_VERIFIED", target_type=kind, target_id=str(item_id),
                 outcome="SUCCESS" if not still_present else "FAILURE",
                 details={"remediation_id": record.id, "verification": record.verification, "scan_id": scan.id,
                          "score": f"{score_before} -> {after['security_score']}",
                          "run_rate": f"{cost_before} -> {after['monthly_run_rate']}"})
    db.commit()
    return {"status": "EXECUTED", "verification": record.verification, "remediation": remediation_dict(record),
            "verification_scan": scan_dict(scan),
            "message": ("Executed in the simulated environment and verified: the condition is no longer detected."
                        if not still_present else "Executed, but the condition is STILL detected - not resolved.")}


def remediation_dict(r: SimRemediation) -> dict[str, Any]:
    return {
        "id": r.id, "target_kind": r.target_kind, "target_id": r.target_id, "target_key": r.target_key, "plan": r.plan,
        "plan_hash": r.plan_hash, "status": r.status, "verification": r.verification, "actor": r.actor,
        "executed_at": r.executed_at.isoformat(), "executed_sim": r.executed_sim.isoformat(), "results": r.results,
        "before": r.before, "after": r.after, "scan_before_id": r.scan_before_id, "scan_after_id": r.scan_after_id,
        "cost_before": r.cost_before, "cost_after": r.cost_after, "score_before": r.score_before,
        "score_after": r.score_after, "realized_monthly_savings": r.realized_monthly_savings, "message": r.message,
        "savings_basis": "VERIFIED (simulated environment)" if r.verification == "VERIFIED" else "NOT VERIFIED",
    }


# ------------------------------------------------------------------- what-if
def run_whatif(db: Session, actor: str | None, changes: list[dict[str, Any]], title: str | None) -> dict[str, Any]:
    row, env = get_state(db, history=True)
    result = whatif.simulate(env, changes)
    run = SimWhatIf(environment_id=row.id, actor=actor, title=title, changes=result["changes"], result=result,
                    baseline_fingerprint=env.fingerprint(), state_version=row.state_version, status="SIMULATED")
    db.add(run)
    db.flush()
    audit.record(db, env_row=row, actor=actor, action="WHATIF_EXECUTED", target_type="whatif", target_id=str(run.id),
                 details={"changes": len(result["changes"]), "baseline_unchanged": result["baseline_unchanged"],
                          "cost_delta": result["cost"]["delta_monthly"], "score_delta": result["security"]["score_delta"]})
    db.commit()
    return whatif_dict(run)


def whatif_dict(w: SimWhatIf) -> dict[str, Any]:
    return {"id": w.id, "title": w.title, "status": w.status, "created_at": w.created_at.isoformat(), "actor": w.actor,
            "state_version": w.state_version, "applied_at": w.applied_at.isoformat() if w.applied_at else None,
            "changes": w.changes, "result": w.result}


def apply_whatif(db: Session, actor: str | None, whatif_id: int, confirm: bool) -> dict[str, Any]:
    if confirm is not True:
        raise SimError("Explicit confirmation is required (confirm=true)", "confirmation_required", 422)
    w = db.get(SimWhatIf, whatif_id)
    row = env_store.require_active_row(db)
    if w is None or w.environment_id != row.id:
        raise SimError(f"What-if {whatif_id} not found in the active environment", "not_found", 404)
    if w.status == "APPLIED":
        raise SimError("This what-if was already applied", "invalid_state", 409)
    ops = rem_engine.normalise_ops(w.changes)

    def done(r: SimEnvironment, env: Environment, res: Any, diff: dict[str, Any]) -> None:
        w.status, w.applied_at = "APPLIED", utcnow()

    row, env, res, diff = mutate(db, actor, "WHATIF_APPLIED", lambda e: rem_engine.run_operations(e, ops),
                                 target_type="whatif", target_id=str(whatif_id), details={"changes": ops},
                                 history=True, on_success=done)
    return {"status": "APPLIED", "whatif_id": whatif_id, "changes": diff,
            "message": "Applied to the simulated environment. Run a scan to refresh findings."}


# ----------------------------------------------------------------------- drift
def drift_report(db: Session) -> dict[str, Any]:
    _, env = get_state(db)
    return drift.detect(env)


def set_baseline(db: Session, actor: str | None) -> dict[str, Any]:
    def fn(env: Environment) -> dict[str, Any]:
        env.baseline, env.baseline_time = env.snapshot_resources(), iso(env.sim_time)
        return {"message": "Baseline captured", "baseline_time": env.baseline_time}

    _, _, res, _ = mutate(db, actor, "BASELINE_CAPTURED", fn, target_type="environment")
    return res


# ------------------------------------------------------------------- dashboards
def dashboard(db: Session) -> dict[str, Any]:
    row, env = get_state(db, history=True)
    latest = db.execute(select(SimScan).where(SimScan.environment_id == row.id).order_by(SimScan.id.desc())).scalars().first()
    open_findings = db.execute(select(SimFinding.severity, func.count()).where(
        SimFinding.environment_id == row.id, SimFinding.status == "OPEN").group_by(SimFinding.severity)).all()
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    sev.update({s: c for s, c in open_findings})
    recs = db.execute(select(SimRecommendation).where(SimRecommendation.environment_id == row.id,
                                                      SimRecommendation.status.in_(["OPEN", "APPLIED"]))).scalars().all()
    verified = db.execute(select(func.coalesce(func.sum(SimRecommendation.realized_monthly_savings), 0.0)).where(
        SimRecommendation.environment_id == row.id, SimRecommendation.status == "VERIFIED")).scalar()
    summary = cost.summary(env)
    anomalies = [a for a in cost.detect_anomalies(env) if a["active"]]
    top = db.execute(select(SimFinding).where(SimFinding.environment_id == row.id, SimFinding.status == "OPEN")).scalars().all()
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    top = sorted(top, key=lambda f: (order[f.severity], f.rule_id))[:6]
    hist = cost.history(env, 30)
    return {
        "environment": env_store.describe(row, env),
        "latest_scan": scan_dict(latest) if latest else None,
        "stale": bool(latest and latest.state_version != row.state_version),
        "security": {"score": latest.security_score if latest else None, "severity_counts": sev,
                     "open_findings": sum(sev.values())},
        "cost": {"monthly_run_rate": summary["monthly_run_rate"], "by_service": summary["by_service"],
                 "last_30_days_total": summary["last_30_days_total"], "history": hist,
                 "anomalies": anomalies, "pricing_note": summary["pricing_note"]},
        "recommendations": {"open": len([r for r in recs if r.status == "OPEN"]),
                            "estimated_monthly_savings": round(sum(r.estimated_monthly_savings for r in recs if r.status == "OPEN"
                                                                   and r.remediation.get("supported")), 2),
                            "verified_monthly_savings": round(float(verified or 0), 2)},
        "compliance": latest.compliance if latest else [],
        "top_findings": [finding_dict(f) for f in top],
        "exposed_resources": len(network.risky_exposure_ids(env)),
        "admin_principals": len(iam.analyze(env)["admin_principals"]),
    }


def pageify(items: list[Any], page: int, page_size: int) -> dict[str, Any]:
    total = len(items)
    start = (page - 1) * page_size
    return {"total": total, "page": page, "page_size": page_size, "items": items[start:start + page_size]}


__all__ = ["timedelta"]
