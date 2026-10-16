"""Append-only audit trail. There is intentionally no update or delete helper."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.sim_models import SimAuditEvent, SimEnvironment, utcnow

_MAX_VALUE = 600


def _trim(value: Any) -> Any:
    text = str(value)
    return value if len(text) <= _MAX_VALUE else text[:_MAX_VALUE] + "..."


def before_after(diff: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> tuple[dict, dict]:
    """Compact before/after views derived from a resource diff."""
    b: dict[str, Any] = {}
    a: dict[str, Any] = {}
    for rid, fields in diff["modified"].items():
        b[rid] = {f: _trim(c["before"]) for f, c in fields.items()}
        a[rid] = {f: _trim(c["after"]) for f, c in fields.items()}
    for rid in diff["created"]:
        res = next((r[rid] for r in after.values() if rid in r), {})
        a[rid] = {"created": True, "type": res.get("type"), "name": res.get("name")}
    for rid in diff["deleted"]:
        res = next((r[rid] for r in before.values() if rid in r), {})
        b[rid] = {"deleted": True, "type": res.get("type"), "name": res.get("name")}
    return b, a


def record(db: Session, *, env_row: SimEnvironment | None, actor: str | None, action: str,
           target_type: str | None = None, target_id: str | None = None, outcome: str = "SUCCESS",
           before: dict[str, Any] | None = None, after: dict[str, Any] | None = None,
           details: dict[str, Any] | None = None) -> SimAuditEvent:
    event = SimAuditEvent(
        environment_id=env_row.id if env_row is not None else None, timestamp=utcnow(),
        sim_time=env_row.sim_time if env_row is not None else None, actor=actor, action=action,
        target_type=target_type, target_id=target_id, outcome=outcome, before=before, after=after, details=details,
    )
    db.add(event)
    db.flush()
    return event


def to_dict(e: SimAuditEvent) -> dict[str, Any]:
    return {
        "id": e.id, "environment_id": e.environment_id, "timestamp": e.timestamp.isoformat(),
        "sim_time": e.sim_time.isoformat() if e.sim_time else None, "actor": e.actor, "action": e.action,
        "target_type": e.target_type, "target_id": e.target_id, "outcome": e.outcome,
        "before": e.before, "after": e.after, "details": e.details,
    }
