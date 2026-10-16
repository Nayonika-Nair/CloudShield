"""Execution of remediation plans and what-if changes through the lifecycle API."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.simulator import lifecycle
from app.simulator.env import Environment, SimError


def plan_hash(ops: list[dict[str, Any]]) -> str:
    canon = [{"action": o["action"], "target_id": o.get("target_id"), "params": o.get("params") or {}} for o in ops]
    return hashlib.sha256(json.dumps(canon, sort_keys=True).encode()).hexdigest()[:16]


def normalise_ops(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ops = []
    for c in changes:
        if not isinstance(c, dict) or "action" not in c:
            raise SimError("Each change needs an 'action'", "invalid_parameter", 422)
        ops.append({"action": c["action"], "target_id": c.get("target_id"), "params": c.get("params") or {},
                    "description": c.get("description", "")})
    return ops


def run_operations(env: Environment, ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run operations in order; on any failure restore the environment (all-or-nothing)."""
    saved_resources, saved_counters = env.snapshot_resources(), dict(env.id_counters)
    results: list[dict[str, Any]] = []
    try:
        for i, o in enumerate(ops, 1):
            try:
                results.append(lifecycle.execute(env, o["action"], o.get("target_id"), o.get("params")))
            except SimError as exc:
                raise SimError(f"Step {i} ({o['action']}) failed: {exc.message}", exc.code, exc.status) from exc
    except Exception:
        env.resources, env.id_counters = saved_resources, saved_counters
        env.reindex()
        raise
    return results


def build_plan(item: dict[str, Any]) -> dict[str, Any]:
    plan = dict(item["remediation"])
    plan["plan_hash"] = plan_hash(plan["operations"]) if plan["operations"] else None
    return plan
