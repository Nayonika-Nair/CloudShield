"""Constructors shared by the generator and the lifecycle operations."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from app.simulator.catalog import EC2_TYPES, RDS_CLASSES
from app.simulator.env import Environment, SimError, iso, unit

PROFILE_CPU = {"idle": (1.0, 4.0), "underutilized": (6.0, 18.0), "normal": (30.0, 58.0), "busy": (65.0, 85.0)}
PROFILE_MEM = {"idle": (8.0, 20.0), "underutilized": (15.0, 35.0), "normal": (40.0, 65.0), "busy": (65.0, 85.0)}
NET_FACTOR = {"idle": 0.05, "underutilized": 0.5, "normal": 1.0, "busy": 1.5}
ROLE_NET_OUT = {
    "web": (5.0, 30.0), "app": (1.0, 6.0), "worker": (0.5, 3.0),
    "batch": (0.2, 2.0), "bastion": (0.05, 0.3),
}


def between(lo: float, hi: float, u: float) -> float:
    return round(lo + (hi - lo) * u, 2)


def rule(protocol: str, from_port: int, to_port: int, cidr: str | None = None,
         source_sg: str | None = None, description: str = "") -> dict[str, Any]:
    return {
        "protocol": protocol, "from_port": from_port, "to_port": to_port,
        "cidr": cidr, "source_sg": source_sg, "description": description,
    }


ALL_TRAFFIC = ("-1", 0, 65535)


def alloc_private_ip(env: Environment, subnet: dict[str, Any]) -> str:
    net = ipaddress.ip_network(subnet["cidr"])
    used = {e["private_ip"] for e in env.of("network_interface") if e["subnet_id"] == subnet["id"]}
    for host in list(net.hosts())[4:]:
        if str(host) not in used:
            return str(host)
    raise SimError(f"Subnet {subnet['id']} has no free IP addresses", "capacity", 409)


def alloc_public_ip(env: Environment) -> str:
    taken = {e.get("public_ip") for e in env.of("network_interface")} | {
        e.get("public_ip") for e in env.of("elastic_ip")}
    first_octets = (3, 13, 18, 34, 35, 44, 52, 54)
    while True:
        n = env.id_counters.get("publicip", 0) + 1
        env.id_counters["publicip"] = n
        h = int(unit(env.seed, "publicip", n) * 2**32)
        ip = f"{first_octets[h % 8]}.{(h >> 3) % 256}.{(h >> 11) % 256}.{(h >> 19) % 253 + 1}"
        if ip not in taken:
            return ip


def workload_for(env: Environment, key: str, profile: str, role: str, vcpus: int) -> dict[str, Any]:
    s = env.seed
    cpu = between(*PROFILE_CPU[profile], unit(s, key, "cpu"))
    out = round(between(*ROLE_NET_OUT.get(role, (1.0, 5.0)), unit(s, key, "net")) * NET_FACTOR[profile], 2)
    return {
        "profile": profile,
        "workload_vcpu": round(cpu / 100 * vcpus, 4),
        "mem_pct_base": between(*PROFILE_MEM[profile], unit(s, key, "mem")),
        "net_out_gb_base": out,
        "net_in_gb_base": round(out * between(0.6, 1.4, unit(s, key, "netin")), 2),
        "traffic_multiplier": 1.0,
    }


def build_security_group(env: Environment, *, name: str, vpc_id: str, description: str,
                         ingress: list[dict[str, Any]] | None = None,
                         egress: list[dict[str, Any]] | None = None,
                         tags: dict[str, str] | None = None,
                         created_at: datetime | None = None) -> dict[str, Any]:
    env.get(vpc_id, "vpc")
    sg = {
        "id": env.new_id("sg"), "name": name, "description": description, "vpc_id": vpc_id,
        "ingress": ingress or [],
        "egress": egress if egress is not None else [rule(*ALL_TRAFFIC, cidr="0.0.0.0/0", description="allow all outbound")],
        "state": "available", "tags": tags or {}, "created_at": iso(created_at or env.sim_time),
        "region": env.region,
    }
    return env.add("security_group", sg)


def build_volume(env: Environment, *, name: str, size_gb: int, az: str, volume_type: str = "gp3",
                 encrypted: bool = True, attached_to: str | None = None, device: str | None = None,
                 backup_policy: str = "none", tags: dict[str, str] | None = None,
                 created_at: datetime | None = None) -> dict[str, Any]:
    if size_gb < 1 or size_gb > 16384:
        raise SimError("Volume size must be between 1 and 16384 GiB", "invalid_parameter", 422)
    if volume_type not in env.pricing["ebs_gb_month"]:
        raise SimError(f"Unsupported volume type '{volume_type}'", "invalid_parameter", 422)
    vol = {
        "id": env.new_id("vol"), "name": name, "size_gb": size_gb, "volume_type": volume_type,
        "encrypted": encrypted, "state": "in-use" if attached_to else "available",
        "attached_to": attached_to, "device": device, "az": az, "backup_policy": backup_policy,
        "used_pct_base": between(25, 75, unit(env.seed, name, "used")),
        "tags": tags or {}, "created_at": iso(created_at or env.sim_time), "region": env.region,
    }
    return env.add("ebs_volume", vol)


def build_snapshot(env: Environment, volume: dict[str, Any], *, managed_by: str = "manual",
                   created_at: datetime | None = None) -> dict[str, Any]:
    snap = {
        "id": env.new_id("snap"), "name": f"snap-of-{volume['name']}", "volume_id": volume["id"],
        "size_gb": volume["size_gb"], "encrypted": volume["encrypted"], "managed_by": managed_by,
        "state": "completed", "tags": dict(volume.get("tags", {})),
        "created_at": iso(created_at or env.sim_time), "region": env.region,
    }
    return env.add("snapshot", snap)


def build_instance(env: Environment, *, name: str, instance_type: str, subnet_id: str,
                   sg_ids: list[str], role: str = "app", os_name: str = "linux",
                   iam_role: str | None = None, profile: str = "normal",
                   assign_public_ip: bool | None = None, root_size_gb: int = 30,
                   encrypted: bool = True, backup_policy: str = "none",
                   tags: dict[str, str] | None = None,
                   created_at: datetime | None = None,
                   state: str = "running") -> dict[str, Any]:
    if instance_type not in EC2_TYPES:
        raise SimError(f"Unsupported instance type '{instance_type}'", "invalid_parameter", 422)
    subnet = env.get(subnet_id, "subnet")
    if not sg_ids:
        raise SimError("An instance needs at least one security group", "invalid_parameter", 422)
    for sg_id in sg_ids:
        sg = env.get(sg_id, "security_group")
        if sg["vpc_id"] != subnet["vpc_id"]:
            raise SimError(f"Security group {sg_id} belongs to a different VPC than subnet {subnet_id}",
                           "invalid_relationship", 422)
    if iam_role is not None:
        env.get(iam_role, "iam_role")
    vcpus = EC2_TYPES[instance_type][0]
    iid = env.new_id("i")
    public = subnet.get("map_public_ip") if assign_public_ip is None else assign_public_ip
    eni = {
        "id": env.new_id("eni"), "name": f"{name}-eni", "subnet_id": subnet_id,
        "vpc_id": subnet["vpc_id"], "private_ip": alloc_private_ip(env, subnet),
        "public_ip": alloc_public_ip(env) if public else None, "sg_ids": list(sg_ids),
        "attached_to": iid, "state": "in-use", "description": f"Primary interface of {name}",
        "created_at": iso(created_at or env.sim_time), "tags": {}, "region": env.region,
    }
    env.add("network_interface", eni)
    inst = {
        "id": iid, "name": name, "instance_type": instance_type, "state": state, "os": os_name,
        "role": role, "vpc_id": subnet["vpc_id"], "subnet_id": subnet_id, "az": subnet["az"],
        "eni_id": eni["id"], "private_ip": eni["private_ip"], "public_ip": eni["public_ip"],
        "sg_ids": list(sg_ids), "volume_ids": [], "iam_role": iam_role,
        "ami": f"ami-{int(unit(env.seed, name, 'ami') * 2**32):08x}",
        "tags": tags or {}, "created_at": iso(created_at or env.sim_time),
        "stopped_at": None, "terminated_at": None, "region": env.region,
        **workload_for(env, name, profile, role, vcpus),
    }
    env.add("ec2_instance", inst)
    root = build_volume(env, name=f"{name}-root", size_gb=root_size_gb, az=subnet["az"],
                        encrypted=encrypted, attached_to=iid, device="/dev/xvda",
                        backup_policy=backup_policy, tags=dict(tags or {}), created_at=created_at)
    inst["volume_ids"].append(root["id"])
    return inst


def instance_vcpus(inst: dict[str, Any]) -> int:
    return EC2_TYPES[inst["instance_type"]][0]


def rds_vcpus(db: dict[str, Any]) -> int:
    return RDS_CLASSES[db["instance_class"]][0]
