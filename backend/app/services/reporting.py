"""Report generation from persisted application state (never from static sample data)."""

from __future__ import annotations

import csv
import io
from typing import Any
from xml.sax.saxutils import escape

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engines import cost, drift
from app.services import audit, env_store
from app.services.scan import finding_dict, rec_dict, scan_dict
from app.services.sim_service import get_state, remediation_dict
from app.sim_models import (
    SimAuditEvent, SimFinding, SimRecommendation, SimRemediation, SimReport, SimScan, utcnow,
)

TITLES = {"security": "Security Findings Report", "cost": "Cost Optimization Report",
          "full": "Full Infrastructure Report", "verification": "Remediation Verification Report"}
LIMITATIONS = [
    "All resources, metrics and prices come from the CloudShield Fake AWS simulator; no real AWS account was accessed.",
    "Prices are simulated and a month is 30 days. Savings marked ESTIMATED are projections; only items marked "
    "VERIFIED were confirmed by re-running the analysis after a change in the simulated environment.",
    "Detection covers the documented CloudShield rule set and does not claim to find every real-world weakness.",
    "Network exposure is a simplified reachability model (security groups, public addresses, routes, internet gateways).",
]


def build(db: Session, actor: str | None, report_type: str) -> dict[str, Any]:
    row, env = get_state(db, history=True)
    scan = db.execute(select(SimScan).where(SimScan.environment_id == row.id).order_by(SimScan.id.desc())).scalars().first()
    findings = [finding_dict(f) for f in db.execute(select(SimFinding).where(SimFinding.environment_id == row.id)
                                                    .order_by(SimFinding.id)).scalars()]
    recs = [rec_dict(r) for r in db.execute(select(SimRecommendation).where(SimRecommendation.environment_id == row.id)
                                            .order_by(SimRecommendation.id)).scalars()]
    rems = [remediation_dict(r) for r in db.execute(select(SimRemediation).where(SimRemediation.environment_id == row.id)
                                                    .order_by(SimRemediation.id)).scalars()]
    events = [audit.to_dict(e) for e in db.execute(select(SimAuditEvent).where(SimAuditEvent.environment_id == row.id)
                                                   .order_by(SimAuditEvent.id.desc()).limit(40)).scalars()]
    summary = cost.summary(env)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    open_f = sorted([f for f in findings if f["status"] == "OPEN"], key=lambda f: (order[f["severity"]], f["rule_id"]))
    resolved_f = [f for f in findings if f["status"] == "RESOLVED"]
    open_r = [r for r in recs if r["status"] == "OPEN"]
    verified_total = round(sum(r["realized_monthly_savings"] or 0 for r in recs if r["status"] == "VERIFIED"), 2)
    content: dict[str, Any] = {
        "title": TITLES[report_type], "report_type": report_type, "generated_at": utcnow().isoformat(),
        "generated_by": actor, "sim_time": env.sim_time.isoformat(),
        "environment": {**env_store.describe(row, env), "preset": row.config.get("preset"),
                        "thresholds": row.config.get("thresholds")},
        "latest_scan": scan_dict(scan) if scan else None,
        "assumptions_and_limitations": LIMITATIONS,
    }
    security = {
        "score": scan.security_score if scan else None, "severity_counts": scan.severity_counts if scan else {},
        "open_findings": open_f, "resolved_findings": resolved_f, "compliance": scan.compliance if scan else [],
    }
    costs = {
        "monthly_run_rate": summary["monthly_run_rate"], "by_service": summary["by_service"],
        "last_30_days_total": summary["last_30_days_total"], "pricing_note": summary["pricing_note"],
        "history": cost.history(env, 30), "anomalies": cost.detect_anomalies(env), "top_resources": summary["top_resources"],
        "recommendations": open_r,
        "estimated_monthly_savings": round(sum(r["estimated_monthly_savings"] for r in open_r if r["remediation"]["supported"]), 2),
        "verified_monthly_savings": verified_total,
        "applied_or_verified": [r for r in recs if r["status"] in ("APPLIED", "VERIFIED")],
    }
    if report_type in ("security", "full"):
        content["security"] = security
    if report_type in ("cost", "full"):
        content["cost"] = costs
    if report_type in ("verification", "full", "security", "cost"):
        content["remediation"] = rems
    if report_type in ("full", "verification"):
        content["audit_events"] = events
        content["drift"] = drift.detect(env)["summary"]
        content["inventory"] = env_store.inventory_counts(env)
    if report_type == "verification":
        content["security"] = security
    row_report = SimReport(environment_id=row.id, report_type=report_type, title=content["title"], sim_time=env.sim_time,
                           actor=actor, content=content)
    db.add(row_report)
    db.flush()
    audit.record(db, env_row=row, actor=actor, action="REPORT_GENERATED", target_type="report", target_id=str(row_report.id),
                 details={"report_type": report_type})
    db.commit()
    return {"id": row_report.id, **{k: content[k] for k in ("title", "report_type", "generated_at")}, "content": content}


def list_reports(db: Session) -> list[dict[str, Any]]:
    row = env_store.require_active_row(db)
    rows = db.execute(select(SimReport).where(SimReport.environment_id == row.id).order_by(SimReport.id.desc())).scalars()
    return [{"id": r.id, "report_type": r.report_type, "title": r.title, "created_at": r.created_at.isoformat(),
             "sim_time": r.sim_time.isoformat(), "actor": r.actor} for r in rows]


# ------------------------------------------------------------------ renderers
def render_json(content: dict[str, Any]) -> bytes:
    import json
    return json.dumps(content, indent=2, default=str).encode()


def render_csv(content: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([content["title"]])
    w.writerow(["Generated (UTC)", content["generated_at"], "Simulated time", content["sim_time"]])
    w.writerow(["Environment", content["environment"]["name"], "Account", content["environment"]["account_id"]])
    w.writerow([])
    if "security" in content:
        w.writerow(["SECURITY FINDINGS"])
        w.writerow(["id", "status", "severity", "rule", "resource", "title", "first_seen_sim", "last_seen_sim", "resolution"])
        for f in content["security"]["open_findings"] + content["security"]["resolved_findings"]:
            w.writerow([f["id"], f["status"], f["severity"], f["rule_id"], f["resource_id"], f["title"],
                        f["first_seen_sim"], f["last_seen_sim"], f["resolution"] or ""])
        w.writerow([])
    if "cost" in content:
        w.writerow(["COST RECOMMENDATIONS (savings basis shown per row)"])
        w.writerow(["id", "status", "priority", "resource", "title", "current_monthly_usd", "estimated_monthly_savings_usd",
                    "verified_monthly_savings_usd", "basis"])
        for r in content["cost"]["recommendations"] + content["cost"]["applied_or_verified"]:
            w.writerow([r["id"], r["status"], r["priority"], r["resource_id"], r["title"], r["current_monthly_cost"],
                        r["estimated_monthly_savings"], r["realized_monthly_savings"] if r["realized_monthly_savings"] is not None else "",
                        r["savings_basis"]])
        w.writerow([])
        w.writerow(["DAILY COST HISTORY (simulated USD)"])
        w.writerow(["date", "total"] + sorted({s for h in content["cost"]["history"] for s in h["by_service"]}))
        services = sorted({s for h in content["cost"]["history"] for s in h["by_service"]})
        for h in content["cost"]["history"]:
            w.writerow([h["date"], h["total"]] + [h["by_service"].get(s, 0) for s in services])
        w.writerow([])
    if content.get("remediation"):
        w.writerow(["REMEDIATIONS"])
        w.writerow(["id", "target", "status", "verification", "score_before", "score_after", "cost_before", "cost_after", "message"])
        for r in content["remediation"]:
            w.writerow([r["id"], f"{r['target_kind']}:{r['target_key']}", r["status"], r["verification"], r["score_before"],
                        r["score_after"], r["cost_before"], r["cost_after"], r["message"]])
    return buf.getvalue().encode()


def render_pdf(content: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5)
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=18, textColor=colors.HexColor("#1f3a5f"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1f3a5f"), spaceBefore=10)
    P = lambda t, s=body: Paragraph(escape(str(t)), s)  # noqa: E731

    def table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Table:
        data = [[Paragraph(escape(str(c)), small) for c in r] for r in rows]
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c7ced9")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf4")))
        t.setStyle(TableStyle(style))
        return t

    env = content["environment"]
    out: list[Any] = [P(content["title"], h1),
                      P(f"Environment: {env['name']} | Account {env['account_id']} | Region {env['region']} | Seed {env['seed']}"),
                      P(f"Generated {content['generated_at']} UTC | Simulated time {content['sim_time']}"), Spacer(1, 6)]
    if "security" in content:
        s = content["security"]
        out += [P("Security", h2), P(f"Security score: {s['score']} / 100. Open findings by severity: {s['severity_counts']}.")]
        rows = [["Severity", "Rule", "Resource", "Finding", "First seen (sim)"]]
        rows += [[f["severity"], f["rule_id"], f["resource_id"], f["title"], f["first_seen_sim"][:10]] for f in s["open_findings"]]
        out.append(table(rows, [20, 17, 45, 75, 22]))
        if s["resolved_findings"]:
            out += [P("Resolved findings (kept for history)", h2)]
            rows = [["Severity", "Rule", "Resource", "Resolution", "Resolved (sim)"]]
            rows += [[f["severity"], f["rule_id"], f["resource_id"], f["resolution"], (f["resolved_sim"] or "")[:10]] for f in s["resolved_findings"]]
            out.append(table(rows, [20, 17, 55, 40, 42]))
        out += [P("Compliance posture", h2),
                table([["Check", "Compliant", "Total", "%", "Status"]] +
                      [[c["name"], c["compliant"], c["total"], c["pct"], c["status"]] for c in s["compliance"]], [85, 22, 18, 18, 22])]
    if "cost" in content:
        c = content["cost"]
        out += [P("Cost", h2), P(f"Projected monthly run-rate: ${c['monthly_run_rate']:,.2f} (simulated). Last 30 days billed: "
                                 f"${c['last_30_days_total']:,.2f}. {c['pricing_note']}"),
                P(f"Estimated monthly savings from open recommendations: ${c['estimated_monthly_savings']:,.2f} (ESTIMATED). "
                  f"Savings verified after applying changes in the simulator: ${c['verified_monthly_savings']:,.2f} (VERIFIED, simulated)."),
                table([["Service", "Monthly run-rate (USD)"]] + [[k, f"{v:,.2f}"] for k, v in c["by_service"].items()], [70, 50])]
        rows = [["Priority", "Resource", "Recommendation", "Current $/mo", "Est. savings $/mo", "Status"]]
        rows += [[r["priority"], r["resource_id"], r["title"], f"{r['current_monthly_cost']:.2f}",
                  f"{r['estimated_monthly_savings']:.2f}", r["status"]] for r in c["recommendations"]]
        out += [P("Recommendations", h2), table(rows, [17, 38, 62, 20, 22, 18])]
        if c["anomalies"]:
            out += [P("Cost anomalies", h2), table([["Date", "Scope", "Cost", "Baseline", "Increase %"]] +
                                                    [[a["date"], a["scope"], a["value"], a["baseline_mean"], a["increase_pct"]] for a in c["anomalies"][:10]],
                                                    [28, 40, 25, 25, 25])]
    if content.get("remediation"):
        rows = [["ID", "Target", "Status", "Verification", "Score", "Run-rate", "Actions"]]
        for r in content["remediation"]:
            rows.append([r["id"], f"{r['target_kind']} {r['target_key']}", r["status"], r["verification"],
                         f"{r['score_before']} -> {r['score_after']}", f"{r['cost_before']} -> {r['cost_after']}", r["message"] or ""])
        out += [P("Remediation and verification", h2), table(rows, [10, 40, 18, 22, 18, 25, 47])]
    if content.get("audit_events"):
        rows = [["Time (UTC)", "Actor", "Action", "Target", "Outcome"]]
        rows += [[e["timestamp"][:19], e["actor"] or "", e["action"], f"{e['target_type'] or ''} {e['target_id'] or ''}", e["outcome"]]
                 for e in content["audit_events"][:25]]
        out += [P("Recent audit events", h2), table(rows, [35, 40, 45, 40, 18])]
    out += [P("Assumptions and limitations", h2)] + [P("- " + t) for t in content["assumptions_and_limitations"]]
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm,
                      title=content["title"]).build(out)
    return buf.getvalue()


__all__ = ["PageBreak"]
