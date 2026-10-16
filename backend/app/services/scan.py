"""Scans: run all analyses, then reconcile findings and recommendations with history."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines import analysis
from app.services import audit
from app.sim_models import SimEnvironment, SimFinding, SimRecommendation, SimScan, utcnow
from app.simulator.env import Environment


def finding_dict(f: SimFinding) -> dict[str, Any]:
    return {
        "id": f.id, "finding_key": f.finding_key, "rule_id": f.rule_id, "rule_name": f.rule_name, "category": f.category,
        "severity": f.severity, "severity_reason": f.severity_reason, "resource_id": f.resource_id,
        "resource_type": f.resource_type, "resource_name": f.resource_name, "title": f.title,
        "explanation": f.explanation, "evidence": f.evidence, "impact": f.impact, "recommendation": f.recommendation,
        "detection_rule": f.detection_rule, "remediation": f.remediation, "status": f.status, "resolution": f.resolution,
        "first_seen_sim": f.first_seen_sim.isoformat(), "last_seen_sim": f.last_seen_sim.isoformat(),
        "first_seen_at": f.first_seen_at.isoformat(), "last_seen_at": f.last_seen_at.isoformat(),
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "resolved_sim": f.resolved_sim.isoformat() if f.resolved_sim else None,
        "first_scan_id": f.first_scan_id, "last_scan_id": f.last_scan_id, "resolved_scan_id": f.resolved_scan_id,
        "remediation_id": f.remediation_id,
    }


def rec_dict(r: SimRecommendation) -> dict[str, Any]:
    verified = r.status == "VERIFIED"
    return {
        "id": r.id, "rec_key": r.rec_key, "rule_id": r.rule_id, "category": r.category, "type": r.rec_type,
        "title": r.title, "resource_id": r.resource_id, "resource_type": r.resource_type,
        "resource_name": r.resource_name, "reason": r.reason, "evidence": r.evidence,
        "current_monthly_cost": r.current_monthly_cost, "estimated_monthly_savings": r.estimated_monthly_savings,
        "realized_monthly_savings": r.realized_monthly_savings,
        "savings_basis": "VERIFIED (simulated)" if verified and r.realized_monthly_savings is not None else "ESTIMATED",
        "assumptions": r.assumptions, "risk": r.risk, "recommended_action": r.recommended_action,
        "remediation": r.remediation, "priority": r.priority, "confidence": r.confidence, "status": r.status,
        "simulated": r.simulated, "whatif_id": r.whatif_id, "first_seen_sim": r.first_seen_sim.isoformat(),
        "last_seen_sim": r.last_seen_sim.isoformat(), "applied_at": r.applied_at.isoformat() if r.applied_at else None,
        "verified_at": r.verified_at.isoformat() if r.verified_at else None, "remediation_id": r.remediation_id,
    }


def run_scan(db: Session, row: SimEnvironment, env: Environment, *, trigger: str, actor: str | None,
             remediation_id: int | None = None) -> tuple[SimScan, dict[str, Any]]:
    """Analyse ``env`` and reconcile persisted findings. Caller commits."""
    result = analysis.analyze(env)
    now = utcnow()
    scan = SimScan(environment_id=row.id, trigger=trigger, state_version=row.state_version, sim_time=env.sim_time,
                   started_at=now, actor=actor)
    db.add(scan)
    db.flush()

    open_rows = {f.finding_key: f for f in db.execute(
        select(SimFinding).where(SimFinding.environment_id == row.id, SimFinding.status == "OPEN")).scalars()}
    detected = {f["finding_key"]: f for f in result["findings"]}
    new = resolved = 0
    for key, f in detected.items():
        existing = open_rows.get(key)
        if existing is None:
            db.add(SimFinding(
                environment_id=row.id, finding_key=key, rule_id=f["rule_id"], rule_name=f["rule_name"],
                category=f["category"], severity=f["severity"], severity_reason=f["severity_reason"],
                resource_id=f["resource_id"], resource_type=f["resource_type"], resource_name=f["resource_name"],
                title=f["title"], explanation=f["explanation"], impact=f["impact"], recommendation=f["recommendation"],
                detection_rule=f["detection_rule"], evidence=f["evidence"], remediation=f["remediation"],
                status="OPEN", first_seen_sim=env.sim_time, last_seen_sim=env.sim_time, first_seen_at=now,
                last_seen_at=now, first_scan_id=scan.id, last_scan_id=scan.id))
            new += 1
        else:
            existing.last_seen_sim, existing.last_seen_at, existing.last_scan_id = env.sim_time, now, scan.id
            existing.severity, existing.severity_reason = f["severity"], f["severity_reason"]
            existing.evidence, existing.explanation = f["evidence"], f["explanation"]
            existing.remediation, existing.title = f["remediation"], f["title"]
    for key, rec in open_rows.items():
        if key not in detected:
            rec.status, rec.resolved_at, rec.resolved_sim, rec.resolved_scan_id = "RESOLVED", now, env.sim_time, scan.id
            rec.resolution = "REMEDIATED" if remediation_id else "NO_LONGER_DETECTED"
            rec.remediation_id = remediation_id
            resolved += 1

    open_recs = {r.rec_key: r for r in db.execute(
        select(SimRecommendation).where(SimRecommendation.environment_id == row.id,
                                        SimRecommendation.status.in_(["OPEN", "APPLIED"]))).scalars()}
    wanted = {r["rec_key"]: r for r in result["recommendations"]}
    for key, r in wanted.items():
        existing = open_recs.get(key)
        fields = dict(
            title=r["title"], reason=r["reason"], evidence=r["evidence"], current_monthly_cost=r["current_monthly_cost"],
            estimated_monthly_savings=r["estimated_monthly_savings"], assumptions=r["assumptions"], risk=r["risk"],
            recommended_action=r["recommended_action"], remediation=r["remediation"], priority=r["priority"],
            confidence=r["confidence"], last_seen_sim=env.sim_time)
        if existing is None:
            db.add(SimRecommendation(
                environment_id=row.id, rec_key=key, rule_id=r["rule_id"], category=r["category"], rec_type=r["type"],
                resource_id=r["resource_id"], resource_type=r["resource_type"], resource_name=r["resource_name"],
                status="OPEN", first_seen_sim=env.sim_time, **fields))
        else:
            for k, v in fields.items():
                setattr(existing, k, v)
            if existing.status == "APPLIED":  # still detected after the action: not fixed
                existing.status = "OPEN"
    for key, rec in open_recs.items():
        if key not in wanted:
            if rec.status == "APPLIED":
                rec.status, rec.verified_at = "VERIFIED", now
            else:
                rec.status = "STALE"

    scan.completed_at = utcnow()
    scan.security_score = result["security_score"]
    scan.findings_open = len(detected)
    scan.new_findings, scan.resolved_findings = new, resolved
    scan.severity_counts = result["severity_counts"]
    scan.monthly_run_rate = result["monthly_run_rate"]
    scan.potential_savings = result["potential_savings"]
    scan.finding_keys = sorted(detected)
    scan.compliance = result["compliance"]
    audit.record(db, env_row=row, actor=actor, action="SCAN_COMPLETED", target_type="scan", target_id=str(scan.id),
                 details={"trigger": trigger, "findings_open": len(detected), "new": new, "resolved": resolved,
                          "security_score": scan.security_score})
    audit.record(db, env_row=row, actor=actor, action="RECOMMENDATIONS_GENERATED", target_type="scan",
                 target_id=str(scan.id), details={"count": len(wanted), "potential_savings": scan.potential_savings})
    db.flush()
    return scan, result


def scan_dict(s: SimScan) -> dict[str, Any]:
    return {
        "id": s.id, "environment_id": s.environment_id, "trigger": s.trigger, "state_version": s.state_version,
        "sim_time": s.sim_time.isoformat(), "started_at": s.started_at.isoformat(),
        "completed_at": s.completed_at.isoformat() if s.completed_at else None, "status": s.status,
        "security_score": s.security_score, "findings_open": s.findings_open, "new_findings": s.new_findings,
        "resolved_findings": s.resolved_findings, "severity_counts": s.severity_counts,
        "monthly_run_rate": s.monthly_run_rate, "potential_savings": s.potential_savings, "compliance": s.compliance,
        "actor": s.actor,
    }
