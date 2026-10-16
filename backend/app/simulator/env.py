"""In-memory model of one simulated AWS account.

The :class:`Environment` is a plain-data container (JSON-serialisable dicts)
so it can be persisted, deep-copied for what-if analysis, diffed for audit and
drift, and fingerprinted to prove that a computation did not mutate it.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import date, datetime, timedelta
from typing import Any, Iterator

RESOURCE_TYPES = [
    "vpc",
    "internet_gateway",
    "route_table",
    "subnet",
    "security_group",
    "network_interface",
    "ec2_instance",
    "ebs_volume",
    "snapshot",
    "elastic_ip",
    "load_balancer",
    "rds_instance",
    "s3_bucket",
    "iam_policy",
    "iam_role",
    "iam_user",
]

ISO = "%Y-%m-%dT%H:%M:%S"


class SimError(Exception):
    """Raised for invalid simulator operations (maps to a 4xx response)."""

    def __init__(self, message: str, code: str = "invalid_operation", status: int = 409):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def iso(dt: datetime) -> str:
    return dt.strftime(ISO)


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value[:19], ISO)


def unit(seed: int, *keys: Any) -> float:
    """Stateless deterministic pseudo-random number in [0, 1)."""
    digest = hashlib.sha256(":".join(str(k) for k in (seed, *keys)).encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


class Environment:
    def __init__(self, config: dict[str, Any], sim_time: datetime):
        self.config = config
        self.sim_time = sim_time
        self.resources: dict[str, dict[str, dict[str, Any]]] = {t: {} for t in RESOURCE_TYPES}
        # resource_id -> metric -> {YYYY-MM-DD: value}
        self.metrics: dict[str, dict[str, dict[str, float]]] = {}
        # YYYY-MM-DD -> resource_id -> {service: amount}
        self.daily_costs: dict[str, dict[str, dict[str, float]]] = {}
        self.id_counters: dict[str, int] = {}
        self.baseline: dict[str, Any] | None = None
        self.baseline_time: str | None = None
        self.new_metric_rows: list[tuple[str, str, str, float]] = []
        self.new_cost_rows: list[tuple[str, str, str, float]] = []
        self._index: dict[str, str] = {}

    # ------------------------------------------------------------------ config
    @property
    def seed(self) -> int:
        return int(self.config["seed"])

    @property
    def region(self) -> str:
        return self.config["region"]

    @property
    def account_id(self) -> str:
        return self.config["account_id"]

    @property
    def pricing(self) -> dict[str, Any]:
        return self.config["pricing"]

    @property
    def thresholds(self) -> dict[str, Any]:
        return self.config["thresholds"]

    @property
    def today(self) -> date:
        return self.sim_time.date()

    # --------------------------------------------------------------- identity
    def new_id(self, prefix: str, length: int = 17) -> str:
        """Deterministic, collision-free identifier such as ``i-0a1b2c3d4e5f60718``."""
        while True:
            n = self.id_counters.get(prefix, 0) + 1
            self.id_counters[prefix] = n
            digest = hashlib.sha256(f"{self.seed}:{prefix}:{n}".encode()).hexdigest()[:length]
            rid = f"{prefix}-{digest}"
            if rid not in self._index:
                return rid

    # ------------------------------------------------------------- collection
    def add(self, rtype: str, res: dict[str, Any]) -> dict[str, Any]:
        rid = res["id"]
        if rid in self._index:
            raise SimError(f"Duplicate resource identifier '{rid}'", "duplicate_id", 409)
        res["type"] = rtype
        self.resources[rtype][rid] = res
        self._index[rid] = rtype
        return res

    def remove(self, rid: str) -> dict[str, Any]:
        rtype = self._index.pop(rid, None)
        if rtype is None:
            raise SimError(f"Resource '{rid}' not found", "not_found", 404)
        return self.resources[rtype].pop(rid)

    def reindex(self) -> None:
        self._index = {rid: t for t, items in self.resources.items() for rid in items}

    def exists(self, rid: str) -> bool:
        return rid in self._index

    def find(self, rid: str) -> tuple[str, dict[str, Any]]:
        rtype = self._index.get(rid)
        if rtype is None:
            raise SimError(f"Resource '{rid}' not found", "not_found", 404)
        return rtype, self.resources[rtype][rid]

    def get(self, rid: str, expect: str | None = None) -> dict[str, Any]:
        rtype, res = self.find(rid)
        if expect and rtype != expect:
            raise SimError(f"Resource '{rid}' is a {rtype}, expected {expect}", "wrong_type", 422)
        return res

    def of(self, rtype: str) -> list[dict[str, Any]]:
        return list(self.resources[rtype].values())

    def all(self) -> Iterator[dict[str, Any]]:
        for items in self.resources.values():
            yield from items.values()

    def count(self, rtype: str, *, exclude_states: tuple[str, ...] = ("terminated", "deleted")) -> int:
        return sum(1 for r in self.resources[rtype].values() if r.get("state") not in exclude_states)

    # ------------------------------------------------------------ history rows
    def record_metric(self, rid: str, metric: str, day: str, value: float) -> None:
        value = round(float(value), 4)
        self.metrics.setdefault(rid, {}).setdefault(metric, {})[day] = value
        self.new_metric_rows.append((rid, metric, day, value))

    def record_cost(self, rid: str, service: str, day: str, amount: float) -> None:
        amount = round(float(amount), 6)
        self.daily_costs.setdefault(day, {}).setdefault(rid, {})[service] = amount
        self.new_cost_rows.append((rid, service, day, amount))

    def metric_series(self, rid: str, metric: str, days: int, end: date | None = None) -> list[tuple[str, float]]:
        """Last ``days`` daily points strictly before ``end`` (default: sim today)."""
        end = end or self.today
        series = self.metrics.get(rid, {}).get(metric, {})
        out = []
        for i in range(days, 0, -1):
            d = (end - timedelta(days=i)).isoformat()
            if d in series:
                out.append((d, series[d]))
        return out

    # ----------------------------------------------------------------- hashing
    def fingerprint(self, *, include_history: bool = True) -> str:
        payload: dict[str, Any] = {
            "resources": self.resources,
            "sim_time": iso(self.sim_time),
            "counters": self.id_counters,
        }
        if include_history:
            payload["metrics"] = self.metrics
            payload["costs"] = self.daily_costs
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def copy(self) -> "Environment":
        """Isolated deep copy. Mutating the copy never touches this instance."""
        dup = Environment(copy.deepcopy(self.config), self.sim_time)
        dup.resources = copy.deepcopy(self.resources)
        dup.metrics = copy.deepcopy(self.metrics)
        dup.daily_costs = copy.deepcopy(self.daily_costs)
        dup.id_counters = dict(self.id_counters)
        dup.baseline = copy.deepcopy(self.baseline)
        dup.baseline_time = self.baseline_time
        dup.reindex()
        return dup

    def snapshot_resources(self) -> dict[str, dict[str, dict[str, Any]]]:
        return copy.deepcopy(self.resources)

    # ------------------------------------------------------------------ tags
    def tag(self, res: dict[str, Any], key: str, default: str | None = None) -> str | None:
        return (res.get("tags") or {}).get(key, default)


# ---------------------------------------------------------------------- diffs
def diff_resources(
    before: dict[str, dict[str, dict[str, Any]]],
    after: dict[str, dict[str, dict[str, Any]]],
    *,
    ignore: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Field-level difference between two resource snapshots."""
    created: list[str] = []
    deleted: list[str] = []
    modified: dict[str, dict[str, dict[str, Any]]] = {}
    for rtype in set(before) | set(after):
        b, a = before.get(rtype, {}), after.get(rtype, {})
        created += [rid for rid in a if rid not in b]
        deleted += [rid for rid in b if rid not in a]
        for rid in a.keys() & b.keys():
            changes = {}
            for key in set(a[rid]) | set(b[rid]):
                if key in ignore:
                    continue
                if a[rid].get(key) != b[rid].get(key):
                    changes[key] = {"before": b[rid].get(key), "after": a[rid].get(key)}
            if changes:
                modified[rid] = changes
    return {"created": sorted(created), "deleted": sorted(deleted), "modified": modified}


def diff_is_empty(d: dict[str, Any]) -> bool:
    return not (d["created"] or d["deleted"] or d["modified"])


# -------------------------------------------------------------- relationships
def relationships(env: Environment) -> list[tuple[str, str, str]]:
    """Derive explicit relationships (source, target, relation) from resource fields."""
    rel: list[tuple[str, str, str]] = []
    for s in env.of("subnet"):
        rel.append((s["id"], s["vpc_id"], "in_vpc"))
        if s.get("route_table_id"):
            rel.append((s["id"], s["route_table_id"], "uses_route_table"))
    for rt in env.of("route_table"):
        rel.append((rt["id"], rt["vpc_id"], "in_vpc"))
        for route in rt.get("routes", []):
            if route.get("target_type") == "igw":
                rel.append((rt["id"], route["target"], "routes_to"))
    for igw in env.of("internet_gateway"):
        if igw.get("vpc_id"):
            rel.append((igw["id"], igw["vpc_id"], "attached_to"))
    for sg in env.of("security_group"):
        rel.append((sg["id"], sg["vpc_id"], "in_vpc"))
    for eni in env.of("network_interface"):
        rel.append((eni["id"], eni["subnet_id"], "in_subnet"))
        for sg in eni.get("sg_ids", []):
            rel.append((eni["id"], sg, "uses_security_group"))
        if eni.get("attached_to"):
            rel.append((eni["id"], eni["attached_to"], "attached_to"))
    for i in env.of("ec2_instance"):
        rel.append((i["id"], i["subnet_id"], "in_subnet"))
        rel.append((i["id"], i["vpc_id"], "in_vpc"))
        for sg in i.get("sg_ids", []):
            rel.append((i["id"], sg, "uses_security_group"))
        if i.get("eni_id"):
            rel.append((i["id"], i["eni_id"], "has_interface"))
        if i.get("iam_role"):
            rel.append((i["id"], i["iam_role"], "assumes_role"))
    for v in env.of("ebs_volume"):
        if v.get("attached_to"):
            rel.append((v["id"], v["attached_to"], "attached_to"))
    for sn in env.of("snapshot"):
        rel.append((sn["id"], sn["volume_id"], "snapshot_of"))
    for e in env.of("elastic_ip"):
        if e.get("instance_id"):
            rel.append((e["id"], e["instance_id"], "associated_with"))
    for lb in env.of("load_balancer"):
        rel.append((lb["id"], lb["vpc_id"], "in_vpc"))
        for t in lb.get("targets", []):
            rel.append((lb["id"], t, "forwards_to"))
        for sg in lb.get("sg_ids", []):
            rel.append((lb["id"], sg, "uses_security_group"))
    for db in env.of("rds_instance"):
        rel.append((db["id"], db["vpc_id"], "in_vpc"))
        for sn in db.get("subnet_ids", []):
            rel.append((db["id"], sn, "in_subnet"))
        for sg in db.get("sg_ids", []):
            rel.append((db["id"], sg, "uses_security_group"))
    for u in env.of("iam_user"):
        for p in u.get("policy_ids", []):
            rel.append((u["id"], p, "has_policy"))
    for r in env.of("iam_role"):
        for p in r.get("policy_ids", []):
            rel.append((r["id"], p, "has_policy"))
    return rel
