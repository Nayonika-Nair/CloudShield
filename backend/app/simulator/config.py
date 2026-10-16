"""Validated configuration for the Fake AWS simulator.

A configuration plus a random seed fully determines the generated environment.
"""

from __future__ import annotations

import copy
from datetime import date
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.simulator.catalog import DEFAULT_PRICING, EC2_TYPES, RDS_CLASSES, REGIONS


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Counts(_Strict):
    vpcs: int = Field(2, ge=1, le=5)
    subnets_per_vpc: int = Field(4, ge=2, le=8)
    ec2_instances: int = Field(14, ge=0, le=200)
    unattached_volumes: int = Field(3, ge=0, le=50)
    snapshots: int = Field(8, ge=0, le=300)
    s3_buckets: int = Field(6, ge=0, le=60)
    rds_instances: int = Field(3, ge=0, le=20)
    elastic_ips: int = Field(4, ge=0, le=20)
    load_balancers: int = Field(2, ge=0, le=10)
    iam_users: int = Field(6, ge=1, le=40)
    iam_roles: int = Field(4, ge=1, le=20)

    @field_validator("subnets_per_vpc")
    @classmethod
    def _even(cls, v: int) -> int:
        if v % 2:
            raise ValueError("subnets_per_vpc must be even (half public, half private)")
        return v


class Naming(_Strict):
    org: str = Field("acme", min_length=2, max_length=16, pattern=r"^[a-z][a-z0-9-]*$")
    separator: Literal["-", "_"] = "-"


class TagPolicy(_Strict):
    owners: list[str] = Field(default_factory=lambda: ["platform-team", "web-team", "data-team"], min_length=1)
    environments: dict[str, float] = Field(default_factory=lambda: {"prod": 0.45, "staging": 0.2, "dev": 0.35})
    required_tags: list[str] = Field(default_factory=lambda: ["owner", "environment"])

    @field_validator("environments")
    @classmethod
    def _weights(cls, v: dict[str, float]) -> dict[str, float]:
        if not v or any(w < 0 for w in v.values()) or sum(v.values()) <= 0:
            raise ValueError("environment weights must be non-negative with a positive sum")
        return v


class Utilization(_Strict):
    """Share of instances / databases assigned to each CPU utilization profile."""

    idle: float = Field(0.15, ge=0, le=1)
    underutilized: float = Field(0.20, ge=0, le=1)
    normal: float = Field(0.50, ge=0, le=1)
    busy: float = Field(0.15, ge=0, le=1)

    @model_validator(mode="after")
    def _sum(self) -> "Utilization":
        total = self.idle + self.underutilized + self.normal + self.busy
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"utilization shares must sum to 1.0 (got {total:.2f})")
        return self


class SecuritySettings(_Strict):
    """Fraction of eligible resources that receive each misconfiguration."""

    public_s3_pct: float = Field(0.15, ge=0, le=1)
    open_ssh_pct: float = Field(0.20, ge=0, le=1)
    open_rdp_pct: float = Field(0.30, ge=0, le=1)
    public_rds_pct: float = Field(0.15, ge=0, le=1)
    unencrypted_pct: float = Field(0.15, ge=0, le=1)
    no_backup_pct: float = Field(0.25, ge=0, le=1)
    no_mfa_pct: float = Field(0.30, ge=0, le=1)
    stale_key_pct: float = Field(0.30, ge=0, le=1)
    wildcard_admin_pct: float = Field(0.15, ge=0, le=1)
    risky_trust_pct: float = Field(0.15, ge=0, le=1)
    untagged_pct: float = Field(0.10, ge=0, le=1)
    windows_pct: float = Field(0.15, ge=0, le=1)
    stopped_pct: float = Field(0.08, ge=0, le=1)


class IamSettings(_Strict):
    admin_users: int = Field(1, ge=0, le=10)
    mfa_required: bool = True
    access_key_max_age_days: int = Field(90, ge=7, le=730)
    excessive_admin_threshold: int = Field(2, ge=1, le=20)


class Thresholds(_Strict):
    """Detection thresholds used by the cost and security rules."""

    idle_cpu_avg_pct: float = Field(5.0, ge=0, le=50)
    idle_cpu_max_pct: float = Field(15.0, ge=0, le=100)
    underutilized_cpu_avg_pct: float = Field(20.0, ge=0, le=80)
    underutilized_cpu_max_pct: float = Field(40.0, ge=0, le=100)
    metric_window_days: int = Field(14, ge=3, le=60)
    old_snapshot_days: int = Field(90, ge=7, le=730)
    backup_max_age_days: int = Field(7, ge=1, le=60)
    anomaly_zscore: float = Field(3.0, ge=1.5, le=10)
    anomaly_min_increase_pct: float = Field(25.0, ge=5, le=500)
    traffic_spike_factor: float = Field(8.0, ge=2, le=100)


class Quotas(_Strict):
    ec2_instances: int = Field(100, ge=0, le=1000)
    ebs_volumes: int = Field(300, ge=0, le=2000)
    s3_buckets: int = Field(100, ge=0, le=1000)
    rds_instances: int = Field(40, ge=0, le=200)
    elastic_ips: int = Field(10, ge=0, le=100)
    vpcs: int = Field(5, ge=1, le=20)
    security_groups: int = Field(200, ge=0, le=1000)
    iam_users: int = Field(100, ge=0, le=1000)
    load_balancers: int = Field(20, ge=0, le=100)
    snapshots: int = Field(600, ge=0, le=5000)


class TimeSettings(_Strict):
    start_date: date = date(2026, 10, 1)
    history_days: int = Field(30, ge=0, le=90)
    auto_advance: bool = False
    auto_advance_interval_seconds: int = Field(0, ge=0, le=86400)
    days_per_tick: int = Field(1, ge=1, le=30)


class Pricing(_Strict):
    """Simulated price list. These are NOT live AWS prices."""

    ec2_hourly: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_PRICING["ec2_hourly"]))
    rds_hourly: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_PRICING["rds_hourly"]))
    ebs_gb_month: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_PRICING["ebs_gb_month"]))
    s3_gb_month: float = Field(DEFAULT_PRICING["s3_gb_month"], ge=0)
    rds_storage_gb_month: float = Field(DEFAULT_PRICING["rds_storage_gb_month"], ge=0)
    snapshot_gb_month: float = Field(DEFAULT_PRICING["snapshot_gb_month"], ge=0)
    eip_idle_hourly: float = Field(DEFAULT_PRICING["eip_idle_hourly"], ge=0)
    data_transfer_out_gb: float = Field(DEFAULT_PRICING["data_transfer_out_gb"], ge=0)
    alb_hourly: float = Field(DEFAULT_PRICING["alb_hourly"], ge=0)
    alb_lcu_hourly: float = Field(DEFAULT_PRICING["alb_lcu_hourly"], ge=0)

    @field_validator("ec2_hourly")
    @classmethod
    def _ec2(cls, v: dict[str, float]) -> dict[str, float]:
        missing = set(EC2_TYPES) - set(v)
        if missing:
            raise ValueError(f"missing EC2 prices for: {sorted(missing)}")
        if any(p < 0 for p in v.values()):
            raise ValueError("prices must be non-negative")
        return v

    @field_validator("rds_hourly")
    @classmethod
    def _rds(cls, v: dict[str, float]) -> dict[str, float]:
        missing = set(RDS_CLASSES) - set(v)
        if missing:
            raise ValueError(f"missing RDS prices for: {sorted(missing)}")
        return v


SCENARIO_NAMES = (
    "public_s3_bucket",
    "open_ssh",
    "open_rdp",
    "overly_permissive_iam",
    "missing_encryption",
    "missing_backup",
    "suspicious_outbound",
    "cost_spike",
    "excessive_admin",
    "risky_network",
)


class SimConfig(_Strict):
    name: str = Field("demo-environment", min_length=1, max_length=64)
    preset: Literal["clean", "typical", "neglected", "custom"] = "typical"
    seed: int = Field(42, ge=0, le=2**31 - 1)
    account_name: str = Field("acme-production", min_length=1, max_length=64)
    account_id: str | None = Field(None, pattern=r"^\d{12}$")
    region: str = "us-east-1"
    counts: Counts = Field(default_factory=Counts)
    naming: Naming = Field(default_factory=Naming)
    tags: TagPolicy = Field(default_factory=TagPolicy)
    utilization: Utilization = Field(default_factory=Utilization)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    iam: IamSettings = Field(default_factory=IamSettings)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    quotas: Quotas = Field(default_factory=Quotas)
    time: TimeSettings = Field(default_factory=TimeSettings)
    pricing: Pricing = Field(default_factory=Pricing)
    # scenario name -> probability (0..1) of being applied while generating
    scenario_probabilities: dict[str, float] = Field(default_factory=dict)

    @field_validator("region")
    @classmethod
    def _region(cls, v: str) -> str:
        if v not in REGIONS:
            raise ValueError(f"unsupported region '{v}'. Choose one of {sorted(REGIONS)}")
        return v

    @field_validator("scenario_probabilities")
    @classmethod
    def _scenarios(cls, v: dict[str, float]) -> dict[str, float]:
        for name, p in v.items():
            if name not in SCENARIO_NAMES:
                raise ValueError(f"unknown scenario '{name}'")
            if not 0 <= p <= 1:
                raise ValueError(f"probability for '{name}' must be within 0..1")
        return v

    @model_validator(mode="after")
    def _capacity(self) -> "SimConfig":
        c, q = self.counts, self.quotas
        if c.ec2_instances > q.ec2_instances:
            raise ValueError("counts.ec2_instances exceeds quotas.ec2_instances")
        if c.s3_buckets > q.s3_buckets:
            raise ValueError("counts.s3_buckets exceeds quotas.s3_buckets")
        if c.rds_instances > q.rds_instances:
            raise ValueError("counts.rds_instances exceeds quotas.rds_instances")
        if c.elastic_ips > q.elastic_ips:
            raise ValueError("counts.elastic_ips exceeds quotas.elastic_ips")
        if c.vpcs > q.vpcs:
            raise ValueError("counts.vpcs exceeds quotas.vpcs")
        if c.iam_users > q.iam_users:
            raise ValueError("counts.iam_users exceeds quotas.iam_users")
        if c.load_balancers > q.load_balancers:
            raise ValueError("counts.load_balancers exceeds quotas.load_balancers")
        return self

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


_ZERO_SECURITY = {k: 0.0 for k in SecuritySettings.model_fields}
_PRESET_SECURITY: dict[str, dict[str, float]] = {
    "clean": {**_ZERO_SECURITY, "windows_pct": 0.1, "stopped_pct": 0.05},
    "typical": SecuritySettings().model_dump(),
    "neglected": {
        "public_s3_pct": 0.4, "open_ssh_pct": 0.5, "open_rdp_pct": 0.7,
        "public_rds_pct": 0.4, "unencrypted_pct": 0.4, "no_backup_pct": 0.5,
        "no_mfa_pct": 0.6, "stale_key_pct": 0.6, "wildcard_admin_pct": 0.35,
        "risky_trust_pct": 0.35, "untagged_pct": 0.3, "windows_pct": 0.25,
        "stopped_pct": 0.15,
    },
}
_PRESET_UTILIZATION = {
    "clean": {"idle": 0.0, "underutilized": 0.05, "normal": 0.75, "busy": 0.20},
    "typical": {"idle": 0.15, "underutilized": 0.20, "normal": 0.50, "busy": 0.15},
    "neglected": {"idle": 0.30, "underutilized": 0.30, "normal": 0.30, "busy": 0.10},
}


def preset_config(name: str = "typical", **overrides: Any) -> SimConfig:
    """Return a validated config for a named preset, with top-level overrides."""
    if name not in _PRESET_SECURITY:
        raise ValueError(f"unknown preset '{name}'. Choose one of {sorted(_PRESET_SECURITY)}")
    data: dict[str, Any] = {
        "preset": name,
        "security": copy.deepcopy(_PRESET_SECURITY[name]),
        "utilization": copy.deepcopy(_PRESET_UTILIZATION[name]),
    }
    data.update(overrides)
    return SimConfig.model_validate(data)


def list_presets() -> list[dict[str, Any]]:
    descriptions = {
        "clean": "Hardened account with almost no misconfigurations",
        "typical": "Realistic mix of healthy and misconfigured resources",
        "neglected": "Poorly maintained account with many exposures and waste",
    }
    return [
        {"name": n, "description": descriptions[n], "config": preset_config(n).to_dict()}
        for n in ("clean", "typical", "neglected")
    ]
