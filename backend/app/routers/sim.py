"""REST API for the Fake AWS simulator, analysis, remediation, what-if, audit and reports."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import get_current_user, require_role
from app.database import get_db
from app.engines import cost, drift, iam, network, optimization, security
from app.models import User
from app.services import audit, env_store, inventory, reporting, sim_service as svc
from app.services.scan import finding_dict, rec_dict, scan_dict
from app.sim_models import (
    SimAuditEvent, SimEnvironment, SimFinding, SimRecommendation, SimRemediation, SimSavedConfig, SimScan,
    SimScenarioExecution, SimWhatIf, utcnow,
)
from app.simulator import lifecycle, scenarios
from app.simulator.catalog import REGIONS
from app.simulator.config import SimConfig, list_presets
from app.simulator.env import SimError

router = APIRouter(prefix="/api/sim", tags=["Fake AWS Simulator"])

Admin = Depends(require_role("admin"))
Analyst = Depends(require_role("admin", "analyst"))
Authed = Depends(get_current_user)


# ------------------------------------------------------------------ schemas
class GenerateRequest(BaseModel):
    preset: Literal["clean", "typical", "neglected"] | None = None
    config: dict[str, Any] | None = None
    name: str | None = Field(None, min_length=1, max_length=64)


class ConfigPatch(BaseModel):
    pricing: dict[str, Any] | None = None
    thresholds: dict[str, Any] | None = None


class ActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    target_id: str | None = Field(None, max_length=255)
    params: dict[str, Any] = Field(default_factory=dict)


class AdvanceRequest(BaseModel):
    days: int = Field(1, ge=1, le=90)


class ScenarioRequest(BaseModel):
    params: dict[str, Any] = Field(default_factory=dict)
    advance_days: int = Field(0, ge=0, le=30)


class RemediationPreviewRequest(BaseModel):
    kind: Literal["finding", "recommendation"]
    id: int = Field(ge=1)


class RemediationApplyRequest(RemediationPreviewRequest):
    plan_hash: str = Field(min_length=8, max_length=16)
    confirm: bool = False


class ChangeItem(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    target_id: str | None = Field(None, max_length=255)
    params: dict[str, Any] = Field(default_factory=dict)


class WhatIfRequest(BaseModel):
    changes: list[ChangeItem] = Field(min_length=1, max_length=20)
    title: str | None = Field(None, max_length=200)


class ConfirmRequest(BaseModel):
    confirm: bool = False


class ReportRequest(BaseModel):
    report_type: Literal["security", "cost", "full", "verification"] = "full"


class SavedConfigRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    config: dict[str, Any]


def _page(page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)) -> tuple[int, int]:
    return page, page_size


def _env(db: Session, history: bool = False):
    return svc.get_state(db, history=history)


# --------------------------------------------------------------- environment
@router.get("/presets")
def presets(_: User = Authed):
    return {"presets": list_presets(), "scenarios": scenarios.catalog(),
            "defaults": SimConfig().to_dict(), "regions": sorted(REGIONS)}


@router.get("/environment")
def environment(db: Session = Depends(get_db), _: User = Authed):
    return svc.environment_summary(db)


@router.get("/environments")
def environments(db: Session = Depends(get_db), _: User = Authed):
    rows = db.execute(select(SimEnvironment).order_by(SimEnvironment.id.desc())).scalars().all()
    return {"items": [env_store.describe(r) for r in rows]}


@router.post("/environments", status_code=201)
def generate_environment(body: GenerateRequest, db: Session = Depends(get_db), user: User = Admin):
    return svc.generate(db, user.email, body.config, preset=body.preset, name=body.name)


@router.post("/environment/reset", status_code=201)
def reset_environment(db: Session = Depends(get_db), user: User = Admin):
    """Regenerate from the active configuration. Historical scans and audit records are kept."""
    return svc.regenerate(db, user.email)


@router.patch("/environment/config")
def patch_config(body: ConfigPatch, db: Session = Depends(get_db), user: User = Admin):
    return svc.update_config(db, user.email, body.model_dump(exclude_none=True))


@router.get("/configs")
def saved_configs(db: Session = Depends(get_db), _: User = Authed):
    rows = db.execute(select(SimSavedConfig).order_by(SimSavedConfig.name)).scalars().all()
    return {"items": [{"id": r.id, "name": r.name, "config": r.config, "updated_at": r.updated_at.isoformat()} for r in rows]}


@router.post("/configs", status_code=201)
def save_config(body: SavedConfigRequest, db: Session = Depends(get_db), user: User = Admin):
    try:
        cfg = SimConfig.model_validate(body.config).to_dict()
    except Exception as exc:  # pydantic ValidationError
        raise SimError(f"Invalid configuration: {exc}", "invalid_configuration", 422) from exc
    row = db.execute(select(SimSavedConfig).where(SimSavedConfig.name == body.name)).scalars().first()
    if row:
        row.config, row.updated_at = cfg, utcnow()
    else:
        row = SimSavedConfig(name=body.name, config=cfg)
        db.add(row)
    db.flush()
    audit.record(db, env_row=env_store.active_row(db), actor=user.email, action="SAVED_CONFIG_STORED",
                 target_type="config", target_id=body.name)
    db.commit()
    return {"id": row.id, "name": row.name, "config": row.config}


# --------------------------------------------------------------------- time
@router.get("/time")
def get_time(db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    return {"sim_time": row.sim_time.isoformat(), "state_version": row.state_version,
            "auto_advance": row.config["time"]["auto_advance"]}


@router.post("/time/advance")
def advance(body: AdvanceRequest, db: Session = Depends(get_db), user: User = Admin):
    return svc.advance_time(db, user.email, body.days)


# ----------------------------------------------------------------- resources
@router.get("/resources")
def list_resources(type: str | None = None, state: str | None = None, q: str | None = Query(None, max_length=100),
                   paging: tuple[int, int] = Depends(_page), db: Session = Depends(get_db), _: User = Authed):
    _, env = _env(db)
    data = svc.pageify(inventory.listing(env, rtype=type, state=state, q=q), *paging)
    data["counts"] = env_store.inventory_counts(env)
    return data


@router.get("/resources/{resource_id}")
def get_resource(resource_id: str, db: Session = Depends(get_db), _: User = Authed):
    row, env = _env(db, history=True)
    out = inventory.detail(env, resource_id)
    out["open_findings"] = [finding_dict(f) for f in db.execute(select(SimFinding).where(
        SimFinding.environment_id == row.id, SimFinding.resource_id == resource_id, SimFinding.status == "OPEN")).scalars()]
    out["recommendations"] = [rec_dict(r) for r in db.execute(select(SimRecommendation).where(
        SimRecommendation.environment_id == row.id, SimRecommendation.resource_id == resource_id,
        SimRecommendation.status.in_(["OPEN", "APPLIED"]))).scalars()]
    return out


@router.get("/actions")
def action_catalog(_: User = Authed):
    return {"items": lifecycle.catalog()}


@router.post("/resources/actions")
def run_action(body: ActionRequest, db: Session = Depends(get_db), user: User = Admin):
    return svc.run_action(db, user.email, body.action, body.target_id, body.params)


# ------------------------------------------------------------------ network
@router.get("/network/topology")
def topology(db: Session = Depends(get_db), _: User = Authed):
    return network.topology(_env(db)[1])


@router.get("/network/exposures")
def exposures(reachable: bool | None = None, db: Session = Depends(get_db), _: User = Authed):
    items = network.exposures(_env(db)[1])
    if reachable is not None:
        items = [e for e in items if e["reachable"] is reachable]
    return {"total": len(items), "items": items}


@router.get("/network/reachability/{resource_id}")
def reachability(resource_id: str, db: Session = Depends(get_db), _: User = Authed):
    return network.explain_reachability(_env(db)[1], resource_id)


@router.get("/network/issues")
def network_issues(db: Session = Depends(get_db), _: User = Authed):
    return {"items": network.topology_issues(_env(db)[1])}


@router.get("/iam/analysis")
def iam_analysis(db: Session = Depends(get_db), _: User = Authed):
    return iam.analyze(_env(db)[1])


@router.get("/iam/evaluate")
def iam_evaluate(principal: str, action: str, resource: str = "*", db: Session = Depends(get_db), _: User = Authed):
    return iam.evaluate(_env(db)[1], principal, action, resource)


# ------------------------------------------------------------ metrics & cost
@router.get("/metrics")
def metrics(resource_id: str, metric: str | None = None, days: int = Query(30, ge=1, le=120),
            db: Session = Depends(get_db), _: User = Authed):
    env = _env(db, history=True)[1]
    env.find(resource_id)
    series = env.metrics.get(resource_id, {})
    out = {m: [{"date": d, "value": v} for d, v in sorted(s.items())][-days:] for m, s in series.items() if not metric or m == metric}
    return {"resource_id": resource_id, "sim_time": env.sim_time.isoformat(), "metrics": out}


@router.get("/costs/summary")
def costs_summary(db: Session = Depends(get_db), _: User = Authed):
    return cost.summary(_env(db, history=True)[1])


@router.get("/costs/history")
def costs_history(days: int = Query(30, ge=1, le=120), db: Session = Depends(get_db), _: User = Authed):
    env = _env(db, history=True)[1]
    return {"currency": "USD", "pricing_note": cost.PRICING_NOTE, "items": cost.history(env, days)}


@router.get("/costs/anomalies")
def costs_anomalies(db: Session = Depends(get_db), _: User = Authed):
    items = cost.detect_anomalies(_env(db, history=True)[1])
    return {"total": len(items), "items": items}


@router.get("/costs/breakdown")
def costs_breakdown(db: Session = Depends(get_db), _: User = Authed):
    env = _env(db, history=True)[1]
    rate = cost.monthly_run_rate(env)
    by_type: dict[str, float] = {}
    for rid, amount in rate["by_resource"].items():
        t = env.find(rid)[0]
        by_type[t] = round(by_type.get(t, 0.0) + amount, 2)
    return {"monthly_run_rate": rate["total"], "by_service": rate["by_service"], "by_resource_type": by_type,
            "pricing_note": cost.PRICING_NOTE}


# ----------------------------------------------------------- scans & findings
@router.get("/rules")
def rules(_: User = Authed):
    return {"items": security.rules_catalog()}


@router.post("/scans", status_code=201)
def create_scan(db: Session = Depends(get_db), user: User = Analyst):
    return svc.scan_now(db, user.email)


@router.get("/scans")
def list_scans(paging: tuple[int, int] = Depends(_page), db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    rows = db.execute(select(SimScan).where(SimScan.environment_id == row.id).order_by(SimScan.id.desc())).scalars().all()
    return svc.pageify([scan_dict(s) for s in rows], *paging)


@router.get("/scans/compare")
def compare(a: int, b: int, db: Session = Depends(get_db), _: User = Authed):
    return svc.compare_scans(db, a, b)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), _: User = Authed):
    s = db.get(SimScan, scan_id)
    if s is None:
        raise SimError(f"Scan {scan_id} not found", "not_found", 404)
    return scan_dict(s)


@router.get("/findings")
def list_findings(status: Literal["OPEN", "RESOLVED"] | None = None,
                  severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None, category: str | None = None,
                  resource_id: str | None = None, rule_id: str | None = None, q: str | None = Query(None, max_length=100),
                  paging: tuple[int, int] = Depends(_page), db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    stmt = select(SimFinding).where(SimFinding.environment_id == row.id)
    for col, val in ((SimFinding.status, status), (SimFinding.severity, severity), (SimFinding.category, category),
                     (SimFinding.resource_id, resource_id), (SimFinding.rule_id, rule_id)):
        if val:
            stmt = stmt.where(col == val)
    if q:
        stmt = stmt.where(SimFinding.title.ilike(f"%{q}%") | SimFinding.resource_id.ilike(f"%{q}%"))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows = sorted(db.execute(stmt).scalars().all(), key=lambda f: (f.status != "OPEN", order[f.severity], -f.id))
    return svc.pageify([finding_dict(f) for f in rows], *paging)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db), _: User = Authed):
    f = db.get(SimFinding, finding_id)
    if f is None:
        raise SimError(f"Finding {finding_id} not found", "not_found", 404)
    rems = db.execute(select(SimRemediation).where(SimRemediation.target_kind == "finding",
                                                   SimRemediation.target_id == finding_id)).scalars().all()
    history = db.execute(select(SimFinding).where(SimFinding.environment_id == f.environment_id,
                                                  SimFinding.finding_key == f.finding_key).order_by(SimFinding.id)).scalars().all()
    events = db.execute(select(SimAuditEvent).where(SimAuditEvent.target_type == "finding",
                                                    SimAuditEvent.target_id == str(finding_id)).order_by(SimAuditEvent.id)).scalars().all()
    return {"finding": finding_dict(f), "remediations": [svc.remediation_dict(r) for r in rems],
            "history": [{"id": h.id, "status": h.status, "first_seen_sim": h.first_seen_sim.isoformat(),
                         "resolved_sim": h.resolved_sim.isoformat() if h.resolved_sim else None} for h in history],
            "audit": [audit.to_dict(e) for e in events]}


@router.get("/recommendations")
def list_recommendations(status: Literal["OPEN", "APPLIED", "VERIFIED", "STALE"] | None = None, priority: str | None = None,
                         paging: tuple[int, int] = Depends(_page), db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    stmt = select(SimRecommendation).where(SimRecommendation.environment_id == row.id)
    if status:
        stmt = stmt.where(SimRecommendation.status == status)
    if priority:
        stmt = stmt.where(SimRecommendation.priority == priority.upper())
    rows = sorted(db.execute(stmt).scalars().all(), key=lambda r: (r.status != "OPEN", -r.estimated_monthly_savings))
    open_rows = [r for r in rows if r.status == "OPEN" and r.remediation.get("supported")]
    page = svc.pageify([rec_dict(r) for r in rows], *paging)
    page["totals"] = {"open": len([r for r in rows if r.status == "OPEN"]),
                      "estimated_monthly_savings": optimization.total_savings([rec_dict(r) for r in open_rows]),
                      "verified_monthly_savings": round(sum(r.realized_monthly_savings or 0 for r in rows if r.status == "VERIFIED"), 2)}
    return page


# ------------------------------------------------------ scenarios & remediation
@router.get("/scenarios")
def scenario_catalog(db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    ex = db.execute(select(SimScenarioExecution).where(SimScenarioExecution.environment_id == row.id)
                    .order_by(SimScenarioExecution.id.desc())).scalars().all()
    return {"items": scenarios.catalog(), "executions": [svc.execution_dict(e) for e in ex]}


@router.post("/scenarios/{name}/trigger", status_code=201)
def trigger(name: str, body: ScenarioRequest, db: Session = Depends(get_db), user: User = Admin):
    return svc.trigger_scenario(db, user.email, name, body.params, body.advance_days)


@router.post("/scenarios/executions/{execution_id}/revert")
def revert(execution_id: int, db: Session = Depends(get_db), user: User = Admin):
    return svc.revert_scenario(db, user.email, execution_id)


@router.post("/remediation/preview")
def remediation_preview(body: RemediationPreviewRequest, db: Session = Depends(get_db), user: User = Analyst):
    return svc.preview_remediation(db, user.email, body.kind, body.id)


@router.post("/remediation/apply")
def remediation_apply(body: RemediationApplyRequest, db: Session = Depends(get_db), user: User = Analyst):
    return svc.apply_remediation(db, user.email, body.kind, body.id, body.plan_hash, body.confirm)


@router.get("/remediation")
def list_remediations(db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    rows = db.execute(select(SimRemediation).where(SimRemediation.environment_id == row.id)
                      .order_by(SimRemediation.id.desc())).scalars().all()
    return {"items": [svc.remediation_dict(r) for r in rows]}


# ------------------------------------------------------------------- what-if
@router.post("/whatif", status_code=201)
def whatif_run(body: WhatIfRequest, db: Session = Depends(get_db), user: User = Analyst):
    return svc.run_whatif(db, user.email, [c.model_dump() for c in body.changes], body.title)


@router.get("/whatif")
def whatif_list(db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    rows = db.execute(select(SimWhatIf).where(SimWhatIf.environment_id == row.id).order_by(SimWhatIf.id.desc())).scalars().all()
    return {"items": [{"id": w.id, "title": w.title, "status": w.status, "created_at": w.created_at.isoformat(),
                       "changes": len(w.changes), "cost_delta": w.result["cost"]["delta_monthly"],
                       "score_delta": w.result["security"]["score_delta"]} for w in rows]}


@router.get("/whatif/{whatif_id}")
def whatif_get(whatif_id: int, db: Session = Depends(get_db), _: User = Authed):
    w = db.get(SimWhatIf, whatif_id)
    if w is None:
        raise SimError(f"What-if {whatif_id} not found", "not_found", 404)
    return svc.whatif_dict(w)


@router.post("/whatif/{whatif_id}/apply")
def whatif_apply(whatif_id: int, body: ConfirmRequest, db: Session = Depends(get_db), user: User = Analyst):
    return svc.apply_whatif(db, user.email, whatif_id, body.confirm)


# --------------------------------------------------------- audit, drift, etc.
@router.get("/audit")
def audit_log(action: str | None = None, outcome: Literal["SUCCESS", "REJECTED", "FAILURE"] | None = None,
              target_id: str | None = None, paging: tuple[int, int] = Depends(_page),
              db: Session = Depends(get_db), _: User = Authed):
    row = env_store.require_active_row(db)
    stmt = select(SimAuditEvent).where(SimAuditEvent.environment_id == row.id)
    if action:
        stmt = stmt.where(SimAuditEvent.action.ilike(f"{action}%"))
    if outcome:
        stmt = stmt.where(SimAuditEvent.outcome == outcome)
    if target_id:
        stmt = stmt.where(SimAuditEvent.target_id == target_id)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    page, size = paging
    rows = db.execute(stmt.order_by(SimAuditEvent.id.desc()).offset((page - 1) * size).limit(size)).scalars().all()
    return {"total": total, "page": page, "page_size": size, "items": [audit.to_dict(e) for e in rows]}


@router.get("/drift")
def get_drift(db: Session = Depends(get_db), _: User = Authed):
    return svc.drift_report(db)


@router.post("/drift/baseline")
def set_baseline(db: Session = Depends(get_db), user: User = Admin):
    return svc.set_baseline(db, user.email)


@router.get("/compliance")
def get_compliance(db: Session = Depends(get_db), _: User = Authed):
    from app.engines import compliance
    return {"items": compliance.checks(_env(db)[1])}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), _: User = Authed):
    return svc.dashboard(db)


# ------------------------------------------------------------------- reports
@router.post("/reports", status_code=201)
def create_report(body: ReportRequest, db: Session = Depends(get_db), user: User = Analyst):
    report = reporting.build(db, user.email, body.report_type)
    return {"id": report["id"], "title": report["title"], "report_type": report["report_type"],
            "generated_at": report["generated_at"]}


@router.get("/reports")
def list_reports(db: Session = Depends(get_db), _: User = Authed):
    return {"items": reporting.list_reports(db)}


@router.get("/reports/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db), _: User = Authed):
    from app.sim_models import SimReport
    r = db.get(SimReport, report_id)
    if r is None:
        raise SimError(f"Report {report_id} not found", "not_found", 404)
    return {"id": r.id, "report_type": r.report_type, "title": r.title, "content": r.content}


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, format: Literal["pdf", "csv", "json"] = "pdf",
                    db: Session = Depends(get_db), _: User = Authed):
    from app.sim_models import SimReport
    r = db.get(SimReport, report_id)
    if r is None:
        raise SimError(f"Report {report_id} not found", "not_found", 404)
    renderers = {"pdf": (reporting.render_pdf, "application/pdf"), "csv": (reporting.render_csv, "text/csv"),
                 "json": (reporting.render_json, "application/json")}
    fn, media = renderers[format]
    return Response(content=fn(r.content), media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="cloudshield-report-{r.id}.{format}"'})
