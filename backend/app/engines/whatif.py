"""What-if simulation: evaluate proposed changes on an isolated copy.

The live environment is never modified. Callers can verify that with
``baseline_unchanged`` (a fingerprint comparison taken before and after).
"""

from __future__ import annotations

from typing import Any

from app.engines import analysis, remediation
from app.simulator.env import Environment, SimError, diff_resources

LIMITATIONS = [
    "Costs use the simulated price list and steady-state run-rate; no partial-day billing is modelled.",
    "Security results come from the CloudShield rule set only and are not a complete attack-surface assessment.",
    "Availability impact is limited to operations that stop, restart, resize or delete a resource.",
]


def _dependents(env: Environment, rid: str) -> list[str]:
    deps = [lb["id"] for lb in env.of("load_balancer") if rid in lb["targets"]]
    deps += [e["id"] for e in env.of("elastic_ip") if e.get("instance_id") == rid]
    return deps


def simulate(env: Environment, changes: list[dict[str, Any]]) -> dict[str, Any]:
    ops = remediation.normalise_ops(changes)
    if not ops:
        raise SimError("Provide at least one change to simulate", "invalid_parameter", 422)
    if len(ops) > 20:
        raise SimError("At most 20 changes can be simulated at once", "invalid_parameter", 422)
    fp_before = env.fingerprint()
    base = analysis.analyze(env)
    hypo_env = env.copy()
    results = remediation.run_operations(hypo_env, ops)
    hypo = analysis.analyze(hypo_env)

    base_keys = {f["finding_key"]: f for f in base["findings"]}
    hypo_keys = {f["finding_key"]: f for f in hypo["findings"]}
    resolved = [base_keys[k] for k in base_keys if k not in hypo_keys]
    introduced = [hypo_keys[k] for k in hypo_keys if k not in base_keys]

    def slim(f: dict[str, Any]) -> dict[str, Any]:
        return {k: f[k] for k in ("finding_key", "rule_id", "severity", "title", "resource_id")}

    downtime = []
    for o, r in zip(ops, results):
        if r.get("downtime") and o.get("target_id"):
            downtime.append({"resource_id": o["target_id"], "action": o["action"], "dependents": _dependents(env, o["target_id"])})
    comp_before = {c["id"]: c for c in base["compliance"]}
    comp_rows = []
    for c in hypo["compliance"]:
        b = comp_before[c["id"]]
        comp_rows.append({"id": c["id"], "name": c["name"], "before_pct": b["pct"], "after_pct": c["pct"],
                          "delta": round(c["pct"] - b["pct"], 1), "before_status": b["status"], "after_status": c["status"]})
    cost_delta = round(hypo["monthly_run_rate"] - base["monthly_run_rate"], 2)
    result = {
        "changes": ops,
        "steps": [{"action": r["action"], "target_id": r["target_id"], "message": r["message"]} for r in results],
        "cost": {
            "baseline_monthly": base["monthly_run_rate"], "hypothetical_monthly": hypo["monthly_run_rate"],
            "delta_monthly": cost_delta, "estimated_monthly_savings": round(max(-cost_delta, 0.0), 2),
            "baseline_by_service": base["cost_by_service"], "hypothetical_by_service": hypo["cost_by_service"],
            "basis": "ESTIMATED (simulated prices, 30-day month)",
        },
        "security": {
            "score_before": base["security_score"], "score_after": hypo["security_score"],
            "score_delta": hypo["security_score"] - base["security_score"],
            "severity_before": base["severity_counts"], "severity_after": hypo["severity_counts"],
            "findings_before": len(base["findings"]), "findings_after": len(hypo["findings"]),
            "findings_resolved": [slim(f) for f in resolved], "findings_introduced": [slim(f) for f in introduced],
            "exposed_before": base["exposed_resources"], "exposed_after": hypo["exposed_resources"],
        },
        "operational": {
            "downtime": downtime, "requires_restart": bool(downtime),
            "resources_affected": sorted({o["target_id"] for o in ops if o.get("target_id")} | {c for r in results for c in r.get("created", [])}),
        },
        "compliance": comp_rows,
        "resource_diff": diff_resources(env.resources, hypo_env.resources),
        "limitations": LIMITATIONS,
    }
    result["baseline_unchanged"] = env.fingerprint() == fp_before
    return result
