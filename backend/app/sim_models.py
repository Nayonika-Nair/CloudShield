"""SQLAlchemy tables that persist the Fake AWS simulator and its analysis history.

Tables are prefixed ``sim_`` so they never collide with the original CloudShield
tables, and none of them is ever truncated by the legacy scan persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, Column, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.database import Base

Json = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class SimEnvironment(Base):
    __tablename__ = "sim_environments"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False)
    seed = Column(Integer, nullable=False)
    status = Column(String(16), nullable=False, default="ACTIVE", index=True)  # ACTIVE | ARCHIVED
    account_id = Column(String(12), nullable=False)
    account_name = Column(String(64), nullable=False)
    region = Column(String(32), nullable=False)
    config = Column(Json, nullable=False)
    sim_time = Column(DateTime, nullable=False)
    state_version = Column(Integer, nullable=False, default=1)
    id_counters = Column(Json, nullable=False, default=dict)
    baseline = Column(Json, nullable=True)
    baseline_time = Column(String(32), nullable=True)
    fingerprint = Column(String(64), nullable=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    archived_at = Column(DateTime, nullable=True)


class SimResource(Base):
    __tablename__ = "sim_resources"
    __table_args__ = (UniqueConstraint("environment_id", "resource_id", name="uq_sim_resource"),
                      Index("ix_sim_resources_env_type", "environment_id", "resource_type"))

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(String(255), nullable=False)
    resource_type = Column(String(32), nullable=False)
    name = Column(String(255), nullable=False)
    state = Column(String(32), nullable=True)
    region = Column(String(32), nullable=True)
    data = Column(Json, nullable=False)
    data_hash = Column(String(40), nullable=False)


class SimRelationship(Base):
    __tablename__ = "sim_relationships"
    __table_args__ = (Index("ix_sim_rel_env_src", "environment_id", "source_id"),)

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id", ondelete="CASCADE"), nullable=False)
    source_id = Column(String(255), nullable=False)
    target_id = Column(String(255), nullable=False)
    relation = Column(String(40), nullable=False)


class SimMetric(Base):
    __tablename__ = "sim_metrics"
    __table_args__ = (Index("ix_sim_metrics_lookup", "environment_id", "resource_id", "metric"),)

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(String(255), nullable=False)
    metric = Column(String(32), nullable=False)
    metric_date = Column(Date, nullable=False)
    value = Column(Float, nullable=False)


class SimCostDaily(Base):
    __tablename__ = "sim_cost_daily"
    __table_args__ = (Index("ix_sim_cost_env_date", "environment_id", "cost_date"),)

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id", ondelete="CASCADE"), nullable=False)
    resource_id = Column(String(255), nullable=False)
    service = Column(String(40), nullable=False)
    cost_date = Column(Date, nullable=False)
    amount = Column(Float, nullable=False)


class SimScan(Base):
    __tablename__ = "sim_scans"

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False, index=True)
    trigger = Column(String(32), nullable=False, default="manual")
    state_version = Column(Integer, nullable=False)
    sim_time = Column(DateTime, nullable=False)
    started_at = Column(DateTime, nullable=False, default=utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(16), nullable=False, default="COMPLETED")
    security_score = Column(Integer, nullable=False, default=0)
    findings_open = Column(Integer, nullable=False, default=0)
    new_findings = Column(Integer, nullable=False, default=0)
    resolved_findings = Column(Integer, nullable=False, default=0)
    severity_counts = Column(Json, nullable=False, default=dict)
    monthly_run_rate = Column(Float, nullable=False, default=0)
    potential_savings = Column(Float, nullable=False, default=0)
    finding_keys = Column(Json, nullable=False, default=list)
    compliance = Column(Json, nullable=False, default=list)
    actor = Column(String(255), nullable=True)


class SimFinding(Base):
    __tablename__ = "sim_findings"
    __table_args__ = (Index("ix_sim_findings_env_status", "environment_id", "status"),
                      Index("ix_sim_findings_key", "environment_id", "finding_key"))

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False)
    finding_key = Column(String(300), nullable=False)
    rule_id = Column(String(16), nullable=False, index=True)
    rule_name = Column(String(120), nullable=False)
    category = Column(String(32), nullable=False)
    severity = Column(String(12), nullable=False, index=True)
    severity_reason = Column(Text, nullable=False, default="")
    resource_id = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(32), nullable=False)
    resource_name = Column(String(255), nullable=False)
    title = Column(String(300), nullable=False)
    explanation = Column(Text, nullable=False)
    impact = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    detection_rule = Column(Text, nullable=False)
    evidence = Column(Json, nullable=False)
    remediation = Column(Json, nullable=False)
    status = Column(String(12), nullable=False, default="OPEN")  # OPEN | RESOLVED
    resolution = Column(String(24), nullable=True)  # REMEDIATED | NO_LONGER_DETECTED
    first_seen_sim = Column(DateTime, nullable=False)
    last_seen_sim = Column(DateTime, nullable=False)
    first_seen_at = Column(DateTime, nullable=False, default=utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_sim = Column(DateTime, nullable=True)
    first_scan_id = Column(Integer, ForeignKey("sim_scans.id"), nullable=True)
    last_scan_id = Column(Integer, ForeignKey("sim_scans.id"), nullable=True)
    resolved_scan_id = Column(Integer, ForeignKey("sim_scans.id"), nullable=True)
    remediation_id = Column(Integer, nullable=True)


class SimRecommendation(Base):
    __tablename__ = "sim_recommendations"
    __table_args__ = (Index("ix_sim_recs_env_status", "environment_id", "status"),)

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False)
    rec_key = Column(String(300), nullable=False)
    rule_id = Column(String(16), nullable=False)
    category = Column(String(16), nullable=False, default="COST")
    rec_type = Column(String(48), nullable=False)
    title = Column(String(300), nullable=False)
    resource_id = Column(String(255), nullable=False, index=True)
    resource_type = Column(String(32), nullable=False)
    resource_name = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    evidence = Column(Json, nullable=False)
    current_monthly_cost = Column(Float, nullable=False, default=0)
    estimated_monthly_savings = Column(Float, nullable=False, default=0)
    realized_monthly_savings = Column(Float, nullable=True)
    assumptions = Column(Json, nullable=False, default=list)
    risk = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    remediation = Column(Json, nullable=False)
    priority = Column(String(8), nullable=False)
    confidence = Column(Float, nullable=False, default=0)
    status = Column(String(12), nullable=False, default="OPEN")  # OPEN | APPLIED | VERIFIED | STALE
    simulated = Column(Boolean, nullable=False, default=False)
    whatif_id = Column(Integer, nullable=True)
    first_seen_sim = Column(DateTime, nullable=False)
    last_seen_sim = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    applied_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    remediation_id = Column(Integer, nullable=True)


class SimRemediation(Base):
    __tablename__ = "sim_remediations"

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False, index=True)
    target_kind = Column(String(16), nullable=False)  # finding | recommendation
    target_id = Column(Integer, nullable=False)
    target_key = Column(String(300), nullable=False)
    plan = Column(Json, nullable=False)
    plan_hash = Column(String(16), nullable=False)
    status = Column(String(12), nullable=False)  # EXECUTED | FAILED
    verification = Column(String(16), nullable=False, default="PENDING")  # PENDING | VERIFIED | NOT_RESOLVED
    actor = Column(String(255), nullable=True)
    executed_at = Column(DateTime, nullable=False, default=utcnow)
    executed_sim = Column(DateTime, nullable=False)
    results = Column(Json, nullable=False, default=list)
    before = Column(Json, nullable=False, default=dict)
    after = Column(Json, nullable=False, default=dict)
    scan_before_id = Column(Integer, nullable=True)
    scan_after_id = Column(Integer, nullable=True)
    cost_before = Column(Float, nullable=True)
    cost_after = Column(Float, nullable=True)
    score_before = Column(Integer, nullable=True)
    score_after = Column(Integer, nullable=True)
    realized_monthly_savings = Column(Float, nullable=True)
    message = Column(Text, nullable=True)


class SimAuditEvent(Base):
    __tablename__ = "sim_audit_events"
    __table_args__ = (Index("ix_sim_audit_env_time", "environment_id", "timestamp"),)

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=utcnow)
    sim_time = Column(DateTime, nullable=True)
    actor = Column(String(255), nullable=True)
    action = Column(String(64), nullable=False, index=True)
    target_type = Column(String(32), nullable=True)
    target_id = Column(String(255), nullable=True)
    outcome = Column(String(12), nullable=False, default="SUCCESS")  # SUCCESS | REJECTED | FAILURE
    before = Column(Json, nullable=True)
    after = Column(Json, nullable=True)
    details = Column(Json, nullable=True)


class SimScenarioExecution(Base):
    __tablename__ = "sim_scenario_executions"

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False, index=True)
    scenario = Column(String(48), nullable=False)
    params = Column(Json, nullable=False, default=dict)
    status = Column(String(12), nullable=False, default="ACTIVE")  # ACTIVE | REVERTED
    actor = Column(String(255), nullable=True)
    triggered_at = Column(DateTime, nullable=False, default=utcnow)
    triggered_sim = Column(DateTime, nullable=False)
    result = Column(Json, nullable=False, default=dict)
    before = Column(Json, nullable=False, default=dict)
    changes = Column(Json, nullable=False, default=dict)
    reverted_at = Column(DateTime, nullable=True)


class SimWhatIf(Base):
    __tablename__ = "sim_whatif_runs"

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    actor = Column(String(255), nullable=True)
    title = Column(String(200), nullable=True)
    changes = Column(Json, nullable=False)
    result = Column(Json, nullable=False)
    baseline_fingerprint = Column(String(64), nullable=False)
    state_version = Column(Integer, nullable=False)
    status = Column(String(12), nullable=False, default="SIMULATED")  # SIMULATED | APPLIED
    applied_at = Column(DateTime, nullable=True)


class SimReport(Base):
    __tablename__ = "sim_reports"

    id = Column(Integer, primary_key=True)
    environment_id = Column(Integer, ForeignKey("sim_environments.id"), nullable=False, index=True)
    report_type = Column(String(16), nullable=False)
    title = Column(String(200), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    sim_time = Column(DateTime, nullable=False)
    actor = Column(String(255), nullable=True)
    content = Column(Json, nullable=False)


class SimSavedConfig(Base):
    __tablename__ = "sim_saved_configs"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), nullable=False, unique=True)
    config = Column(Json, nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    updated_at = Column(DateTime, nullable=False, default=utcnow)
