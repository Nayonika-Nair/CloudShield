"""Pure pricing arithmetic. All rates come from the (simulated) price list in the config."""

from __future__ import annotations

from typing import Any

from app.simulator.catalog import MONTH_DAYS
from app.simulator.env import Environment


def ec2_hourly(env: Environment, instance_type: str) -> float:
    return float(env.pricing["ec2_hourly"][instance_type])


def rds_hourly(env: Environment, instance_class: str) -> float:
    return float(env.pricing["rds_hourly"][instance_class])


def fixed_daily(env: Environment, res: dict[str, Any], *, state: str | None = None,
                size_gb: float | None = None) -> dict[str, float]:
    """Charges that depend only on configuration (not on usage), per simulated day."""
    p = env.pricing
    t = res["type"]
    if t == "ec2_instance":
        if (state or res["state"]) == "running":
            return {"EC2": ec2_hourly(env, res["instance_type"]) * 24}
    elif t == "ebs_volume":
        return {"EBS": res["size_gb"] * float(p["ebs_gb_month"][res["volume_type"]]) / MONTH_DAYS}
    elif t == "snapshot":
        return {"Snapshots": res["size_gb"] * float(p["snapshot_gb_month"]) / MONTH_DAYS}
    elif t == "s3_bucket":
        gb = res["size_gb"] if size_gb is None else size_gb
        return {"S3": gb * float(p["s3_gb_month"]) / MONTH_DAYS}
    elif t == "rds_instance":
        if res["state"] == "available":
            compute = rds_hourly(env, res["instance_class"]) * 24 * (2 if res["multi_az"] else 1)
            storage = res["storage_gb"] * float(p["rds_storage_gb_month"]) / MONTH_DAYS
            return {"RDS": compute + storage}
    elif t == "elastic_ip":
        inst = env.resources["ec2_instance"].get(res.get("instance_id") or "")
        if not (inst and inst["state"] == "running"):
            return {"Elastic IP": float(p["eip_idle_hourly"]) * 24}
    elif t == "load_balancer":
        return {"Load Balancing": (float(p["alb_hourly"]) + float(p["alb_lcu_hourly"])) * 24}
    return {}


def data_transfer_daily(env: Environment, net_out_gb: float) -> float:
    return net_out_gb * float(env.pricing["data_transfer_out_gb"])
