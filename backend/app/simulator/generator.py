"""Deterministic environment generator.

The same configuration (including ``seed``) always produces the same
environment: identical identifiers, relationships and properties.
"""

from __future__ import annotations

import random
from datetime import datetime, time, timedelta
from typing import Any, Sequence

from app.simulator import builders as b
from app.simulator.catalog import EC2_TYPES, FIRST_NAMES, RDS_CLASSES, REGIONS, ROLE_SIZES
from app.simulator.config import SimConfig
from app.simulator.env import Environment, iso, unit

S3_PURPOSES = {
    "logs": (200, 3000), "assets": (20, 500), "backups": (500, 5000), "data-lake": (1000, 9000),
    "uploads": (10, 200), "reports": (5, 80), "archive": (300, 4000), "artifacts": (10, 300),
}
VPC_ENVS = ["prod", "dev", "staging", "prod", "dev"]
ENV_BACKUP = {"prod": "daily", "staging": "weekly", "dev": "none"}


def _pick_count(pct: float, n: int) -> int:
    if pct <= 0 or n == 0:
        return 0
    return min(n, max(1, round(pct * n)))


def _pick(rng: random.Random, items: Sequence[Any], pct: float) -> list[Any]:
    chosen = set(rng.sample(range(len(items)), _pick_count(pct, len(items))))
    return [it for i, it in enumerate(items) if i in chosen]


def _distribute(rng: random.Random, n: int, shares: dict[str, float]) -> list[str]:
    """Largest-remainder allocation of n items over the shares, shuffled."""
    raw = {k: v * n for k, v in shares.items()}
    counts = {k: int(v) for k, v in raw.items()}
    leftover = n - sum(counts.values())
    for k in sorted(raw, key=lambda k: raw[k] - counts[k], reverse=True)[:leftover]:
        counts[k] += 1
    out = [k for k, c in counts.items() for _ in range(c)]
    rng.shuffle(out)
    return out


class _Gen:
    def __init__(self, cfg: SimConfig):
        self.cfg = cfg
        data = cfg.to_dict()
        if not data["account_id"]:
            data["account_id"] = str(100_000_000_000 + int(unit(cfg.seed, "acct") * 899_999_999_999))
        start = datetime.combine(cfg.time.start_date, time(0, 0))
        self.env = Environment(data, start)
        self.rng = random.Random(f"cloudshield:{cfg.seed}")
        self.org = cfg.naming.org
        self.sep = cfg.naming.separator
        self.azs = REGIONS[cfg.region]
        self.vpcs: list[dict[str, Any]] = []
        self.vpc_env: dict[str, str] = {}
        self.public_subnets: dict[str, list[dict[str, Any]]] = {}
        self.private_subnets: dict[str, list[dict[str, Any]]] = {}
        self.sgs: dict[str, dict[str, dict[str, Any]]] = {}
        self.instances: list[dict[str, Any]] = []
        # Resources must predate the backfilled history so the bill has no artificial step-ups.
        self.min_age = cfg.time.history_days + 7

    # ------------------------------------------------------------------ utils
    def nm(self, *parts: Any) -> str:
        return self.sep.join(str(p) for p in (self.org, *parts))

    def ago(self, days: float) -> datetime:
        return self.env.sim_time - timedelta(days=days)

    def tags(self, env_tag: str, **extra: str) -> dict[str, str]:
        t = {"environment": env_tag, "owner": self.rng.choice(self.cfg.tags.owners)}
        t.update(extra)
        return t

    def weighted_env(self) -> str:
        envs = self.cfg.tags.environments
        return self.rng.choices(list(envs), weights=list(envs.values()))[0]

    # ---------------------------------------------------------------- network
    def network(self) -> None:
        env, c = self.env, self.cfg.counts
        for i in range(c.vpcs):
            envtag = VPC_ENVS[i]
            cidr_base = 10 * (i + 1)
            vpc = env.add("vpc", {
                "id": env.new_id("vpc"), "name": self.nm(envtag, "vpc"), "cidr": f"10.{cidr_base}.0.0/16",
                "state": "available", "igw_id": None, "tags": self.tags(envtag),
                "created_at": iso(self.ago(self.rng.randint(300, 800))), "region": env.region,
            })
            igw = env.add("internet_gateway", {
                "id": env.new_id("igw"), "name": self.nm(envtag, "igw"), "vpc_id": vpc["id"],
                "state": "attached", "tags": {"environment": envtag}, "created_at": vpc["created_at"],
                "region": env.region,
            })
            vpc["igw_id"] = igw["id"]
            local = {"destination": vpc["cidr"], "target_type": "local", "target": "local"}
            public_rt = env.add("route_table", {
                "id": env.new_id("rtb"), "name": self.nm(envtag, "public-rt"), "vpc_id": vpc["id"],
                "routes": [dict(local), {"destination": "0.0.0.0/0", "target_type": "igw", "target": igw["id"]}],
                "main": False, "state": "available", "tags": {"environment": envtag},
                "created_at": vpc["created_at"], "region": env.region,
            })
            private_rt = env.add("route_table", {
                "id": env.new_id("rtb"), "name": self.nm(envtag, "private-rt"), "vpc_id": vpc["id"],
                "routes": [dict(local)], "main": True, "state": "available",
                "tags": {"environment": envtag}, "created_at": vpc["created_at"], "region": env.region,
            })
            half = c.subnets_per_vpc // 2
            self.public_subnets[vpc["id"]], self.private_subnets[vpc["id"]] = [], []
            for k in range(half):
                for tier, rt, third in (("public", public_rt, k), ("private", private_rt, 100 + k)):
                    sub = env.add("subnet", {
                        "id": env.new_id("subnet"), "name": self.nm(envtag, tier, k + 1), "vpc_id": vpc["id"],
                        "cidr": f"10.{cidr_base}.{third}.0/24", "az": self.azs[k % len(self.azs)],
                        "route_table_id": rt["id"], "map_public_ip": tier == "public", "state": "available",
                        "tags": {"environment": envtag, "tier": tier}, "created_at": vpc["created_at"],
                        "region": env.region,
                    })
                    (self.public_subnets if tier == "public" else self.private_subnets)[vpc["id"]].append(sub)
            self.vpcs.append(vpc)
            self.vpc_env[vpc["id"]] = envtag
            self.security_groups(vpc, envtag)

    def security_groups(self, vpc: dict[str, Any], envtag: str) -> None:
        env = self.env
        sgs: dict[str, dict[str, Any]] = {}
        t = {"environment": envtag}
        sgs["web"] = b.build_security_group(
            env, name=self.nm(envtag, "web-sg"), vpc_id=vpc["id"], description="Public web tier", tags=t,
            created_at=self.ago(300),
            ingress=[b.rule("tcp", 80, 80, "0.0.0.0/0", description="HTTP"),
                     b.rule("tcp", 443, 443, "0.0.0.0/0", description="HTTPS")])
        sgs["bastion"] = b.build_security_group(
            env, name=self.nm(envtag, "bastion-sg"), vpc_id=vpc["id"], description="Admin access from office",
            tags=t, created_at=self.ago(300),
            ingress=[b.rule("tcp", 22, 22, "203.0.113.0/24", description="SSH from corporate range")])
        sgs["app"] = b.build_security_group(
            env, name=self.nm(envtag, "app-sg"), vpc_id=vpc["id"], description="Application tier", tags=t,
            created_at=self.ago(300),
            ingress=[b.rule("tcp", 8080, 8080, source_sg=sgs["web"]["id"], description="From web tier"),
                     b.rule("tcp", 22, 22, source_sg=sgs["bastion"]["id"], description="SSH from bastion")])
        sgs["db"] = b.build_security_group(
            env, name=self.nm(envtag, "db-sg"), vpc_id=vpc["id"], description="Database tier", tags=t,
            created_at=self.ago(300),
            ingress=[b.rule("tcp", 5432, 5432, vpc["cidr"], description="PostgreSQL from VPC"),
                     b.rule("tcp", 3306, 3306, vpc["cidr"], description="MySQL from VPC")])
        self.sgs[vpc["id"]] = sgs

    # -------------------------------------------------------------------- iam
    def iam(self) -> None:
        env, cfg = self.env, self.cfg
        acct, org = env.account_id, self.org

        def policy(name: str, actions: list[str], resources: list[str], managed: bool = True) -> None:
            env.add("iam_policy", {
                "id": f"policy:{name}", "name": name, "managed": managed, "state": "active",
                "statements": [{"effect": "Allow", "actions": actions, "resources": resources}],
                "tags": {}, "created_at": iso(self.ago(500)), "region": "global",
            })

        policy("AdministratorAccess", ["*"], ["*"])
        policy("ReadOnlyAccess", ["ec2:Describe*", "s3:Get*", "s3:List*", "rds:Describe*", "iam:Get*",
                                  "iam:List*", "cloudwatch:Get*"], ["*"])
        policy("S3AppAccess", ["s3:*"], [f"arn:aws:s3:::{org}-*"], managed=False)
        policy("EC2Operator", ["ec2:Describe*", "ec2:StartInstances", "ec2:StopInstances",
                               "ec2:RebootInstances"], ["*"], managed=False)
        policy("DeployerAssume", ["sts:AssumeRole"], [f"arn:aws:iam::{acct}:role/deploy-role"], managed=False)
        policy("DeployPassRole", ["iam:PassRole", "ec2:RunInstances"], ["*"], managed=False)

        roles = [
            ("ec2-app-role", [{"type": "Service", "value": "ec2.amazonaws.com"}], ["S3AppAccess"], {}),
            ("deploy-role", [{"type": "AWS", "value": acct}], ["EC2Operator", "DeployPassRole"], {}),
            ("readonly-role", [{"type": "AWS", "value": acct}], ["ReadOnlyAccess"], {}),
            ("admin-role", [{"type": "AWS", "value": acct}], ["AdministratorAccess"], {"admin": "designated"}),
        ]
        for k in range(max(0, cfg.counts.iam_roles - 4)):
            roles.append((f"service-role-{k + 1}", [{"type": "Service", "value": "ec2.amazonaws.com"}],
                          ["S3AppAccess"], {}))
        for name, trust, pols, tags in roles[: cfg.counts.iam_roles]:
            env.add("iam_role", {
                "id": f"role:{name}", "name": name, "trust": trust, "policy_ids": [f"policy:{p}" for p in pols],
                "state": "active", "tags": {"owner": "platform-team", **tags},
                "created_at": iso(self.ago(self.rng.randint(200, 600))), "last_used": iso(self.ago(1)),
                "region": "global",
            })

        n = cfg.counts.iam_users
        names = (FIRST_NAMES * 2)[: max(0, n)]
        admins = min(cfg.iam.admin_users, n)
        for idx, uname in enumerate(names):
            is_service = idx == n - 1 and n >= 4
            if is_service:
                uname = "svc-ci"
            if idx < admins:
                pols, tags, kind = ["AdministratorAccess"], {"admin": "designated"}, "admin"
            elif is_service:
                pols, tags, kind = ["DeployerAssume"], {}, "service"
            elif idx % 3 == 2:
                pols, tags, kind = ["ReadOnlyAccess"], {}, "readonly"
            else:
                pols, tags, kind = ["EC2Operator", "DeployerAssume", "S3AppAccess"], {}, "developer"
            keys = []
            nkeys = 1 if kind in ("developer", "service") else (1 if idx % 2 == 0 else 0)
            for kk in range(nkeys):
                age = self.rng.randint(5, 60)
                keys.append({
                    "id": f"AKIA{int(unit(env.seed, uname, kk) * 2**52):013X}"[:20],
                    "status": "active", "created_at": iso(self.ago(age)),
                    "last_used": iso(self.ago(self.rng.randint(0, 3))), "usage": "active",
                })
            env.add("iam_user", {
                "id": f"user:{uname}", "name": uname, "console_access": not is_service,
                "mfa_enabled": not is_service, "access_keys": keys,
                "policy_ids": [f"policy:{p}" for p in pols], "kind": kind, "state": "active",
                "tags": {"owner": self.rng.choice(self.cfg.tags.owners), **tags},
                "created_at": iso(self.ago(self.rng.randint(100, 700))), "region": "global",
            })

    # -------------------------------------------------------------- compute
    def compute(self) -> None:
        env, cfg = self.env, self.cfg
        n = cfg.counts.ec2_instances
        pattern = ["web"] * 3 + ["app"] * 3 + ["worker"] * 2 + ["batch", "bastion"]
        roles = []
        while len(roles) < n:
            chunk = pattern[:]
            self.rng.shuffle(chunk)
            roles += chunk
        roles = roles[:n]
        if n and "web" not in roles:
            roles[0] = "web"
        profiles = _distribute(self.rng, n, cfg.utilization.model_dump())
        counters: dict[tuple[str, str], int] = {}
        subnet_rot: dict[tuple[str, bool], int] = {}
        for i in range(n):
            vpc = self.vpcs[i % len(self.vpcs)]
            envtag = self.vpc_env[vpc["id"]] if self.rng.random() < 0.95 else self.weighted_env()
            role = roles[i]
            public = role in ("web", "bastion")
            pool = (self.public_subnets if public else self.private_subnets)[vpc["id"]]
            rot = subnet_rot.get((vpc["id"], public), 0)
            subnet_rot[(vpc["id"], public)] = rot + 1
            counters[(envtag, role)] = counters.get((envtag, role), 0) + 1
            sg_key = {"web": "web", "bastion": "bastion"}.get(role, "app")
            policy = ENV_BACKUP[envtag]
            inst = b.build_instance(
                env, name=self.nm(envtag, role, f"{counters[(envtag, role)]:02d}"),
                instance_type=self.rng.choice(ROLE_SIZES[role]), subnet_id=pool[rot % len(pool)]["id"],
                sg_ids=[self.sgs[vpc["id"]][sg_key]["id"]], role=role,
                iam_role="role:ec2-app-role" if role != "bastion" and env.exists("role:ec2-app-role") else None,
                profile=profiles[i], root_size_gb=self.rng.choice([30, 50, 100]), backup_policy=policy,
                tags=self.tags(envtag, application=role), created_at=self.ago(self.rng.randint(self.min_age, 400)),
            )
            self.instances.append(inst)
            if role in ("app", "worker") and self.rng.random() < 0.35:
                vol = b.build_volume(env, name=f"{inst['name']}-data", size_gb=self.rng.choice([100, 200, 500]),
                                     az=inst["az"], attached_to=inst["id"], device="/dev/sdf",
                                     backup_policy=policy, tags=dict(inst["tags"]),
                                     created_at=self.ago(self.rng.randint(self.min_age, 300)))
                inst["volume_ids"].append(vol["id"])
        stopped = _pick(self.rng, [i for i in self.instances if i["role"] != "web"], cfg.security.stopped_pct)
        for inst in stopped:
            inst["state"] = "stopped"
            inst["stopped_at"] = iso(self.ago(self.rng.randint(20, 90)))
            eni = env.get(inst["eni_id"])
            eni["public_ip"] = inst["public_ip"] = None
        public_inst = [i for i in self.instances if i["role"] in ("web", "bastion")]
        for inst in _pick(self.rng, public_inst, cfg.security.windows_pct):
            inst["os"] = "windows"

        # Elastic IPs: about half stay unassociated (waste).
        total = cfg.counts.elastic_ips
        attach_to = [i for i in public_inst if i["state"] == "running"][: total - total // 2]
        for k in range(total):
            inst = attach_to[k] if k < len(attach_to) else None
            ip = b.alloc_public_ip(env)
            eip = env.add("elastic_ip", {
                "id": env.new_id("eipalloc"), "name": self.nm("eip", f"{k + 1:02d}"), "public_ip": ip,
                "instance_id": inst["id"] if inst else None, "eni_id": inst["eni_id"] if inst else None,
                "state": "associated" if inst else "unassociated", "tags": {"owner": "platform-team"},
                "created_at": iso(self.ago(self.rng.randint(self.min_age, 300))), "region": env.region,
            })
            if inst:
                inst["public_ip"] = ip
                env.get(inst["eni_id"])["public_ip"] = ip
            del eip

        # unattached volumes
        for k in range(cfg.counts.unattached_volumes):
            envtag = self.weighted_env()
            b.build_volume(env, name=self.nm(envtag, "orphan", f"{k + 1:02d}"), size_gb=self.rng.choice([20, 50, 100, 300]),
                           az=self.rng.choice(self.azs), tags=self.tags(envtag),
                           created_at=self.ago(self.rng.randint(max(60, self.min_age), 400)))

        # snapshots: the full retention window of policy snapshots, plus old manual ones
        attached = [v for v in env.of("ebs_volume") if v["attached_to"]]
        for vol in attached:
            if vol["backup_policy"] == "daily":
                for k in range(14):
                    b.build_snapshot(env, vol, managed_by="backup_policy", created_at=self.ago(k + self.rng.random() * 0.9))
            elif vol["backup_policy"] == "weekly":
                for k in range(5):
                    b.build_snapshot(env, vol, managed_by="backup_policy", created_at=self.ago(k * 7 + self.rng.random() * 3))
        protected = [v for v in attached if v["backup_policy"] != "none"] or attached
        for k in range(cfg.counts.snapshots):
            if not protected:
                break
            vol = protected[k % len(protected)] if k < len(protected) else self.rng.choice(attached)
            b.build_snapshot(env, vol, managed_by="manual", created_at=self.ago(self.rng.randint(max(30, self.min_age), 420)))

    # ------------------------------------------------------------- balancers
    def load_balancers(self) -> None:
        env, cfg = self.env, self.cfg
        for k in range(cfg.counts.load_balancers):
            vpc = self.vpcs[k % len(self.vpcs)]
            envtag = self.vpc_env[vpc["id"]]
            targets = [i["id"] for i in self.instances
                       if i["vpc_id"] == vpc["id"] and i["role"] == "web" and i["state"] == "running"]
            if cfg.counts.load_balancers >= 2 and k == cfg.counts.load_balancers - 1 and cfg.utilization.idle > 0:
                targets = []
            env.add("load_balancer", {
                "id": env.new_id("alb"), "name": self.nm(envtag, "alb", f"{k + 1:02d}"), "scheme": "internet-facing",
                "vpc_id": vpc["id"], "subnet_ids": [s["id"] for s in self.public_subnets[vpc["id"]]],
                "sg_ids": [self.sgs[vpc["id"]]["web"]["id"]], "targets": targets, "listeners": [80, 443],
                "state": "active", "tags": {"environment": envtag, "owner": "web-team"},
                "created_at": iso(self.ago(self.rng.randint(max(60, self.min_age), 400))), "region": env.region,
            })

    # -------------------------------------------------------------------- rds
    def rds(self) -> None:
        env, cfg = self.env, self.cfg
        n = cfg.counts.rds_instances
        profiles = _distribute(self.rng, n, cfg.utilization.model_dump())
        by_profile = {"idle": ["db.m5.xlarge", "db.r5.large"], "underutilized": ["db.m5.large", "db.r5.large"],
                      "normal": ["db.m5.large", "db.t3.large"], "busy": ["db.t3.large", "db.t3.medium"]}
        for k in range(n):
            vpc = self.vpcs[k % len(self.vpcs)]
            envtag = self.vpc_env[vpc["id"]]
            engine, port = self.rng.choice([("postgres", 5432), ("mysql", 3306)])
            klass = self.rng.choice(by_profile[profiles[k]])
            subnets = self.private_subnets[vpc["id"]]
            primary = subnets[k % len(subnets)]
            name = self.nm(envtag, "db", f"{k + 1:02d}")
            eni = env.add("network_interface", {
                "id": env.new_id("eni"), "name": f"{name}-eni", "subnet_id": primary["id"], "vpc_id": vpc["id"],
                "private_ip": b.alloc_private_ip(env, primary), "public_ip": None,
                "sg_ids": [self.sgs[vpc["id"]]["db"]["id"]], "attached_to": name, "state": "in-use",
                "description": f"Interface of {name}", "created_at": iso(self.ago(200)), "tags": {},
                "region": env.region,
            })
            vcpus = RDS_CLASSES[klass][0]
            wl = b.workload_for(env, name, profiles[k], "app", vcpus)
            env.add("rds_instance", {
                "id": name, "name": name, "engine": engine, "engine_version": "15.4" if engine == "postgres" else "8.0.35",
                "instance_class": klass, "storage_gb": self.rng.choice([100, 200, 500]), "multi_az": envtag == "prod",
                "publicly_accessible": False, "storage_encrypted": True, "backup_retention_days": 14 if envtag == "prod" else 7,
                "last_backup_at": iso(self.ago(self.rng.random() * 0.9)), "vpc_id": vpc["id"],
                "subnet_ids": [s["id"] for s in subnets[:2]], "sg_ids": [self.sgs[vpc["id"]]["db"]["id"]],
                "eni_id": eni["id"], "port": port, "state": "available", "az": primary["az"],
                "profile": profiles[k], "workload_vcpu": wl["workload_vcpu"], "mem_pct_base": wl["mem_pct_base"],
                "storage_used_pct_base": b.between(20, 45, unit(env.seed, name, "st")) if profiles[k] in ("idle", "underutilized")
                else b.between(45, 75, unit(env.seed, name, "st")),
                "conn_base": int(b.between(5, 120, unit(env.seed, name, "conn"))),
                "tags": self.tags(envtag, application="database"),
                "created_at": iso(self.ago(self.rng.randint(max(60, self.min_age), 500))), "region": env.region,
            })

    # --------------------------------------------------------------------- s3
    def s3(self) -> None:
        env, cfg = self.env, self.cfg
        purposes = list(S3_PURPOSES)
        for k in range(cfg.counts.s3_buckets):
            purpose = purposes[k % len(purposes)]
            envtag = self.weighted_env()
            name = f"{self.nm(envtag, purpose)}{self.sep}{int(unit(env.seed, 's3', k) * 0xFFFF):04x}"
            lo, hi = S3_PURPOSES[purpose]
            size = round(lo + (hi - lo) * self.rng.random(), 1)
            env.add("s3_bucket", {
                "id": name, "name": name, "purpose": purpose, "state": "active", "block_public_access": True,
                "acl": "private", "policy_public": False, "encryption": "AES256", "versioning": purpose in ("data-lake", "backups"),
                "size_gb": size, "object_count": int(size * 800), "growth_gb_per_day": round(size * 0.003, 2),
                "requests_per_day_base": int(1000 + 90000 * self.rng.random()),
                "tags": self.tags(envtag, data_classification="confidential" if purpose in ("data-lake", "backups") else "internal"),
                "created_at": iso(self.ago(self.rng.randint(max(60, self.min_age), 700))), "region": env.region,
            })

    # ---------------------------------------------------------- misconfigure
    def misconfigure(self) -> None:
        env, s = self.env, self.cfg.security
        rng = self.rng
        for bucket in _pick(rng, env.of("s3_bucket"), s.public_s3_pct):
            bucket["block_public_access"] = False
            bucket["acl"] = "public-read"
        attached_vols = [v for v in env.of("ebs_volume") if v["attached_to"]]
        for vol in _pick(rng, attached_vols, s.unencrypted_pct):
            vol["encrypted"] = False
        for bucket in _pick(rng, [x for x in env.of("s3_bucket") if x["acl"] == "private"] or env.of("s3_bucket"),
                            s.unencrypted_pct):
            bucket["encryption"] = "none"
        for db in _pick(rng, env.of("rds_instance"), s.unencrypted_pct):
            db["storage_encrypted"] = False
        for inst in _pick(rng, [i for i in self.instances if i["role"] in ("web", "bastion") and i["state"] == "running"
                                and i["os"] == "linux"], s.open_ssh_pct):
            self._launch_wizard(inst, 22, "SSH")
        for inst in _pick(rng, [i for i in self.instances if i["os"] == "windows" and i["state"] == "running"],
                          s.open_rdp_pct):
            self._launch_wizard(inst, 3389, "RDP")
        for db in _pick(rng, env.of("rds_instance"), s.public_rds_pct):
            vpc_id = db["vpc_id"]
            public_subnet = self.public_subnets[vpc_id][0]
            db["publicly_accessible"] = True
            db["subnet_ids"] = [x["id"] for x in self.public_subnets[vpc_id][:2]]
            eni = env.get(db["eni_id"])
            eni["subnet_id"] = public_subnet["id"]
            eni["private_ip"] = b.alloc_private_ip(env, public_subnet)
            eni["public_ip"] = b.alloc_public_ip(env)
            db["az"] = public_subnet["az"]
            sg = env.get(db["sg_ids"][0])
            sg["ingress"].append(b.rule("tcp", db["port"], db["port"], "0.0.0.0/0", description="temporary access"))
        for db in _pick(rng, env.of("rds_instance"), s.no_backup_pct):
            db["backup_retention_days"] = 0
            db["last_backup_at"] = None
        prod_vols = [v for v in attached_vols if v["tags"].get("environment") == "prod" and v["backup_policy"] != "none"]
        for vol in _pick(rng, prod_vols, s.no_backup_pct):
            vol["backup_policy"] = "none"
            for snap in [x for x in env.of("snapshot") if x["volume_id"] == vol["id"] and x["managed_by"] == "backup_policy"]:
                env.remove(snap["id"])
        users = env.of("iam_user")
        for user in _pick(rng, [u for u in users if u["console_access"]], s.no_mfa_pct):
            user["mfa_enabled"] = False
        keys = [(u, k) for u in users for k in u["access_keys"]]
        for user, key in _pick(rng, keys, s.stale_key_pct):
            key["created_at"] = iso(self.ago(rng.randint(120, 400)))
            key["last_used"] = iso(self.ago(rng.randint(70, 110)))
            key["usage"] = "rare"
        eligible_roles = [r for r in env.of("iam_role") if r["tags"].get("admin") != "designated"]
        for role in _pick(rng, eligible_roles, s.wildcard_admin_pct):
            role["policy_ids"].append("policy:AdministratorAccess")
        for role in _pick(rng, [r for r in eligible_roles if r["name"] != "ec2-app-role"], s.risky_trust_pct):
            role["trust"].append({"type": "AWS", "value": rng.choice(["*", "999988887777"])})
        taggable = list(env.of("ec2_instance")) + list(env.of("ebs_volume")) + list(env.of("s3_bucket")) + list(env.of("rds_instance"))
        for res in _pick(rng, taggable, s.untagged_pct):
            res["tags"].pop("owner", None)

    def _launch_wizard(self, inst: dict[str, Any], port: int, label: str) -> None:
        env = self.env
        n = env.id_counters.get("launch-wizard", 0) + 1
        env.id_counters["launch-wizard"] = n
        sg = b.build_security_group(
            env, name=f"launch-wizard-{n}", vpc_id=inst["vpc_id"], description=f"launch-wizard-{n} created for {label}",
            ingress=[b.rule("tcp", port, port, "0.0.0.0/0", description=f"{label} from anywhere")],
            tags={"environment": inst["tags"].get("environment", "dev")}, created_at=self.ago(60))
        inst["sg_ids"].append(sg["id"])
        env.get(inst["eni_id"])["sg_ids"].append(sg["id"])


def generate_environment(config: SimConfig | dict[str, Any] | None = None) -> Environment:
    from app.simulator import scenarios, timeengine

    cfg = config if isinstance(config, SimConfig) else SimConfig.model_validate(config or {})
    gen = _Gen(cfg)
    gen.network()
    gen.iam()
    gen.compute()
    gen.load_balancers()
    gen.rds()
    gen.s3()
    gen.misconfigure()
    env = gen.env
    for name, prob in sorted(cfg.scenario_probabilities.items()):
        if prob > 0 and unit(cfg.seed, "scenario", name) < prob:
            scenarios.trigger(env, name)
    timeengine.backfill(env, cfg.time.history_days)
    env.baseline = env.snapshot_resources()
    env.baseline_time = iso(env.sim_time)
    return env


__all__ = ["generate_environment", "EC2_TYPES"]
