"""Cost calculation, history and anomaly detection over the simulated bill.

All amounts are USD at SIMULATED prices taken from the environment's price
list. They are not live AWS prices.
"""

from __future__ import annotations

import statistics
from datetime import timedelta
from typing import Any

from app.engines import network
from app.simulator import billing
from app.simulator.catalog import MONTH_DAYS
from app.simulator.env import Environment

MIN_ABSOLUTE_INCREASE = 2.0  # USD/day; smaller moves are noise even when statistically unusual
PRICING_NOTE = "Simulated prices from the environment's price list - not live AWS prices. A month is 30 days."


def expected_net_out_gb(env: Environment, inst: dict[str, Any]) -> float:
    """Steady-state daily outbound GB implied by the *current* configuration."""
    if inst["state"] != "running":
        return 0.0
    mult = inst.get("traffic_multiplier", 1.0) if network.egress_open(env, inst) else 1.0
    return inst["net_out_gb_base"] * mult


def resource_daily_run_rate(env: Environment, res: dict[str, Any]) -> dict[str, float]:
    daily = dict(billing.fixed_daily(env, res))
    if res["type"] == "ec2_instance":
        dt = billing.data_transfer_daily(env, expected_net_out_gb(env, res))
        if dt > 0:
            daily["Data Transfer"] = dt
    return daily


def monthly_run_rate(env: Environment) -> dict[str, Any]:
    """Projected 30-day cost of the environment as currently configured."""
    by_service: dict[str, float] = {}
    by_resource: dict[str, dict[str, float]] = {}
    for res in env.all():
        if res.get("state") in ("terminated", "deleted"):
            continue
        daily = resource_daily_run_rate(env, res)
        if not daily:
            continue
        monthly = {svc: amt * MONTH_DAYS for svc, amt in daily.items()}
        by_resource[res["id"]] = monthly
        for svc, amt in monthly.items():
            by_service[svc] = by_service.get(svc, 0.0) + amt
    return {
        "total": round(sum(by_service.values()), 2),
        "by_service": {k: round(v, 2) for k, v in sorted(by_service.items(), key=lambda kv: -kv[1])},
        "by_resource": {rid: round(sum(v.values()), 2) for rid, v in by_resource.items()},
        "by_resource_service": by_resource,
    }


def resource_monthly(env: Environment, res: dict[str, Any]) -> float:
    return round(sum(resource_daily_run_rate(env, res).values()) * MONTH_DAYS, 2)


def history(env: Environment, days: int = 30) -> list[dict[str, Any]]:
    dates = sorted(env.daily_costs)[-days:]
    out = []
    for d in dates:
        by_service: dict[str, float] = {}
        for services in env.daily_costs[d].values():
            for svc, amt in services.items():
                by_service[svc] = by_service.get(svc, 0.0) + amt
        out.append({"date": d, "total": round(sum(by_service.values()), 4),
                    "by_service": {k: round(v, 4) for k, v in by_service.items()}})
    return out


def _series(rows: list[dict[str, Any]], scope: str) -> list[tuple[str, float]]:
    if scope == "total":
        return [(r["date"], r["total"]) for r in rows]
    return [(r["date"], r["by_service"].get(scope, 0.0)) for r in rows]


def _contributors(env: Environment, day: str, window: list[str]) -> list[dict[str, Any]]:
    out = []
    for rid, services in env.daily_costs.get(day, {}).items():
        today = sum(services.values())
        prior = [sum(env.daily_costs.get(d, {}).get(rid, {}).values()) for d in window]
        base = sum(prior) / len(prior) if prior else 0.0
        if today - base > 0.01:
            name = env.find(rid)[1].get("name", rid) if env.exists(rid) else rid
            out.append({"resource_id": rid, "name": name, "cost": round(today, 2),
                        "baseline": round(base, 2), "increase": round(today - base, 2)})
    return sorted(out, key=lambda c: -c["increase"])[:5]


def detect_anomalies(env: Environment, recent_days: int = 3) -> list[dict[str, Any]]:
    """Flag days whose cost exceeds mean + z*sigma of the preceding window."""
    th = env.thresholds
    rows = history(env, 120)
    if len(rows) < 8:
        return []
    services = sorted({s for r in rows for s in r["by_service"]})
    cutoff = (env.today - timedelta(days=recent_days)).isoformat()
    anomalies: list[dict[str, Any]] = []
    for scope in ["total", *services]:
        series = _series(rows, scope)
        for i in range(7, len(series)):
            day, value = series[i]
            window = [v for _, v in series[max(0, i - 14):i]]
            mean = statistics.fmean(window)
            std = max(statistics.pstdev(window), 0.05 * mean)
            if mean <= 0.5 or value - mean < MIN_ABSOLUTE_INCREASE:
                continue
            z = (value - mean) / std
            inc = (value / mean - 1) * 100
            if z >= th["anomaly_zscore"] and inc >= th["anomaly_min_increase_pct"]:
                win_dates = [d for d, _ in series[max(0, i - 14):i]]
                anomalies.append({
                    "date": day, "scope": scope, "value": round(value, 2), "baseline_mean": round(mean, 2),
                    "baseline_std": round(std, 2), "zscore": round(z, 2), "increase_pct": round(inc, 1),
                    "active": day >= cutoff, "top_contributors": _contributors(env, day, win_dates),
                })
    return sorted(anomalies, key=lambda a: (a["date"], a["scope"]), reverse=True)


def summary(env: Environment) -> dict[str, Any]:
    rate = monthly_run_rate(env)
    hist = history(env, 30)
    top = sorted(rate["by_resource"].items(), key=lambda kv: -kv[1])[:8]
    top_resources = []
    for rid, amount in top:
        res = env.find(rid)[1]
        top_resources.append({"resource_id": rid, "name": res.get("name", rid), "type": res["type"], "monthly": amount})
    return {
        "currency": "USD", "pricing_note": PRICING_NOTE, "sim_time": env.sim_time.isoformat(),
        "monthly_run_rate": rate["total"], "by_service": rate["by_service"],
        "last_30_days_total": round(sum(r["total"] for r in hist), 2), "days_of_history": len(hist),
        "top_resources": top_resources,
    }
