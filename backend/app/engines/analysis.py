"""Single entry point that runs every read-only analysis over an environment."""

from __future__ import annotations

from typing import Any

from app.engines import compliance, cost, network, optimization, security
from app.simulator.env import Environment


def analyze(env: Environment) -> dict[str, Any]:
    """Evaluate security, cost and compliance. Never mutates ``env``."""
    anomalies = cost.detect_anomalies(env)
    ctx = security.build_context(env)
    ctx["cost_anomalies"] = anomalies
    findings = security.evaluate(env, ctx)
    recs = optimization.recommend(env, anomalies)
    rate = cost.monthly_run_rate(env)
    return {
        "findings": findings,
        "recommendations": recs,
        "security_score": security.score(findings),
        "severity_counts": security.severity_counts(findings),
        "monthly_run_rate": rate["total"],
        "cost_by_service": rate["by_service"],
        "cost_by_resource": rate["by_resource"],
        "potential_savings": optimization.total_savings([r for r in recs if r["remediation"]["supported"]]),
        "compliance": compliance.checks(env),
        "anomalies": anomalies,
        "exposed_resources": sorted({e["resource_id"] for e in ctx["exposures"] if e["reachable"]}),
    }
