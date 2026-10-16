"""Validated resource lifecycle operations for the simulated account.

Every operation checks prerequisites and relationships before changing state
and raises :class:`SimError` for impossible transitions, duplicates or invalid
references. Operations are registered in :data:`OPS`, which also feeds the
action catalog shown in the UI.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from app.simulator import builders as b
from app.simulator.catalog import EC2_TYPES, RDS_CLASSES, REGIONS
from app.simulator.env import Environment, SimError, iso

OpFn = Callable[[Environment, str | None, dict[str, Any]], dict[str, Any]]


@dataclass
class OpSpec:
    name: str
    label: str
    target_type: str | tuple[str, ...] | None
    description: str
    params: list[dict[str, Any]] = field(default_factory=list)
    risk: str = "low"
    fn: OpFn | None = None


OPS: dict[str, OpSpec] = {}


def P(name: str, kind: str = "string", required: bool = True, choices: list[Any] | None = None,
      default: Any = None, help: str = "") -> dict[str, Any]:
    return {"name": name, "type": kind, "required": required, "choices": choices, "default": default, "help": help}


def op(name: str, label: str, target_type: str | tuple[str, ...] | None, description: str,
       params: list[dict[str, Any]] | None = None, risk: str = "low"):
    def deco(fn: OpFn) -> OpFn:
        OPS[name] = OpSpec(name, label, target_type, description, params or [], risk, fn)
        return fn
    return deco


# --------------------------------------------------------------------- helpers
def _coerce(spec: dict[str, Any], value: Any) -> Any:
    kind, name = spec["type"], spec["name"]
    try:
        if kind == "int":
            if isinstance(value, bool):
                raise ValueError
            return int(value)
        if kind == "float":
            return float(value)
        if kind == "bool":
            if isinstance(value, bool):
                return value
            if str(value).lower() in ("true", "1", "yes"):
                return True
            if str(value).lower() in ("false", "0", "no"):
                return False
            raise ValueError
        if kind == "list":
            if isinstance(value, str):
                return [v.strip() for v in value.split(",") if v.strip()]
            if not isinstance(value, list):
                raise ValueError
            return value
        if kind == "dict":
            if not isinstance(value, dict):
                raise ValueError
            return value
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise ValueError
        return str(value).strip()
    except (TypeError, ValueError):
        raise SimError(f"Parameter '{name}' must be of type {kind}", "invalid_parameter", 422) from None


def _validate_params(spec: OpSpec, params: dict[str, Any]) -> dict[str, Any]:
    allowed = {p["name"] for p in spec.params}
    unknown = set(params) - allowed
    if unknown:
        raise SimError(f"Unknown parameter(s) for {spec.name}: {sorted(unknown)}", "invalid_parameter", 422)
    out: dict[str, Any] = {}
    for p in spec.params:
        if p["name"] in params and params[p["name"]] not in (None, ""):
            val = _coerce(p, params[p["name"]])
            if p["choices"] and val not in p["choices"]:
                raise SimError(f"Parameter '{p['name']}' must be one of {p['choices']}", "invalid_parameter", 422)
            out[p["name"]] = val
        elif p["required"]:
            raise SimError(f"Missing required parameter '{p['name']}'", "invalid_parameter", 422)
        elif p["default"] is not None:
            out[p["name"]] = p["default"]
    return out


def execute(env: Environment, action: str, target_id: str | None, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate and run one operation against ``env``."""
    spec = OPS.get(action)
    if spec is None:
        raise SimError(f"Unsupported action '{action}'", "unsupported_action", 422)
    clean = _validate_params(spec, params or {})
    if spec.target_type is not None:
        if not target_id:
            raise SimError(f"Action {action} requires a target resource", "invalid_parameter", 422)
        types = (spec.target_type,) if isinstance(spec.target_type, str) else spec.target_type
        rtype, res = env.find(target_id)
        if rtype not in types:
            raise SimError(f"Action {action} applies to {', '.join(types)}, not {rtype}", "wrong_type", 422)
        if res.get("state") in ("terminated", "deleted"):
            raise SimError(f"{target_id} is {res['state']}", "invalid_state", 409)
    result = spec.fn(env, target_id, clean)  # type: ignore[misc]
    return {"action": action, "target_id": target_id, "params": clean, **result}


def catalog() -> list[dict[str, Any]]:
    return [
        {"name": s.name, "label": s.label, "target_type": s.target_type, "description": s.description,
         "params": s.params, "risk": s.risk}
        for s in OPS.values()
    ]


def _quota(env: Environment, key: str, current: int, noun: str) -> None:
    limit = env.config["quotas"][key]
    if current >= limit:
        raise SimError(f"Quota exceeded: this account may have at most {limit} {noun}", "quota_exceeded", 409)


def _cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        raise SimError(f"'{value}' is not a valid CIDR block", "invalid_parameter", 422) from None


def _in_use_by(env: Environment, sg_id: str) -> list[str]:
    users = [i["id"] for i in env.of("ec2_instance") if i["state"] != "terminated" and sg_id in i["sg_ids"]]
    users += [d["id"] for d in env.of("rds_instance") if sg_id in d["sg_ids"]]
    users += [lb["id"] for lb in env.of("load_balancer") if sg_id in lb["sg_ids"]]
    return users


# ------------------------------------------------------------------------ EC2
@op("ec2.create", "Launch instance", None, "Launch a new EC2 instance with a root volume and network interface.",
    [P("subnet_id"), P("instance_type", choices=sorted(EC2_TYPES)), P("sg_ids", "list"),
     P("name", required=False), P("role", choices=["web", "app", "worker", "batch", "bastion"], required=False, default="app"),
     P("os", choices=["linux", "windows"], required=False, default="linux"),
     P("volume_size_gb", "int", False, default=30), P("assign_public_ip", "bool", False),
     P("iam_role", required=False), P("profile", choices=["idle", "underutilized", "normal", "busy"], required=False, default="normal"),
     P("tags", "dict", False)])
def ec2_create(env, _t, p):
    _quota(env, "ec2_instances", env.count("ec2_instance"), "EC2 instances")
    _quota(env, "ebs_volumes", env.count("ebs_volume"), "EBS volumes")
    n = env.id_counters.get("named-i", 0) + 1
    env.id_counters["named-i"] = n
    name = p.get("name") or f"{env.config['naming']['org']}-{p['role']}-{n:02d}"
    tags = {"environment": "dev", **p.get("tags", {})}
    inst = b.build_instance(
        env, name=name, instance_type=p["instance_type"], subnet_id=p["subnet_id"], sg_ids=p["sg_ids"],
        role=p["role"], os_name=p["os"], iam_role=p.get("iam_role"), profile=p["profile"],
        assign_public_ip=p.get("assign_public_ip"), root_size_gb=p["volume_size_gb"], tags=tags)
    return {"message": f"Launched {inst['id']} ({inst['instance_type']})", "created": [inst["id"]]}


@op("ec2.start", "Start instance", "ec2_instance", "Start a stopped instance.")
def ec2_start(env, tid, _p):
    inst = env.get(tid)
    if inst["state"] != "stopped":
        raise SimError(f"Instance {tid} is {inst['state']}; only stopped instances can be started", "invalid_state")
    inst["state"], inst["stopped_at"] = "running", None
    eni = env.get(inst["eni_id"])
    eip = next((e for e in env.of("elastic_ip") if e.get("instance_id") == tid), None)
    subnet = env.get(inst["subnet_id"])
    ip = eip["public_ip"] if eip else (b.alloc_public_ip(env) if subnet.get("map_public_ip") else None)
    inst["public_ip"] = eni["public_ip"] = ip
    return {"message": f"Started {tid}"}


@op("ec2.stop", "Stop instance", "ec2_instance", "Stop a running instance (compute billing stops, storage continues).", risk="medium")
def ec2_stop(env, tid, _p):
    inst = env.get(tid)
    if inst["state"] != "running":
        raise SimError(f"Instance {tid} is {inst['state']}; only running instances can be stopped", "invalid_state")
    inst["state"], inst["stopped_at"] = "stopped", iso(env.sim_time)
    if not any(e.get("instance_id") == tid for e in env.of("elastic_ip")):
        inst["public_ip"] = None
        env.get(inst["eni_id"])["public_ip"] = None
    return {"message": f"Stopped {tid}", "downtime": True}


@op("ec2.terminate", "Terminate instance", "ec2_instance", "Permanently terminate an instance and delete its root volume.", risk="high")
def ec2_terminate(env, tid, _p):
    inst = env.get(tid)
    inst["state"], inst["terminated_at"] = "terminated", iso(env.sim_time)
    for vid in list(inst["volume_ids"]):
        vol = env.resources["ebs_volume"].get(vid)
        if not vol:
            continue
        if vol.get("device") == "/dev/xvda":
            env.remove(vid)
        else:
            vol["state"], vol["attached_to"], vol["device"] = "available", None, None
    inst["volume_ids"] = []
    for eip in env.of("elastic_ip"):
        if eip.get("instance_id") == tid:
            eip.update(instance_id=None, eni_id=None, state="unassociated")
    for lb in env.of("load_balancer"):
        if tid in lb["targets"]:
            lb["targets"].remove(tid)
    if inst["eni_id"] in env.resources["network_interface"]:
        env.remove(inst["eni_id"])
    inst["eni_id"], inst["public_ip"] = None, None
    return {"message": f"Terminated {tid}", "downtime": True}


@op("ec2.change_type", "Change instance type", "ec2_instance",
    "Resize an instance. AWS requires the instance to be stopped first.",
    [P("instance_type", choices=sorted(EC2_TYPES))], risk="medium")
def ec2_change_type(env, tid, p):
    inst = env.get(tid)
    if inst["state"] != "stopped":
        raise SimError("The instance must be stopped before its type can be changed", "invalid_state")
    if p["instance_type"] == inst["instance_type"]:
        raise SimError(f"Instance is already of type {p['instance_type']}", "no_change")
    old = inst["instance_type"]
    inst["instance_type"] = p["instance_type"]
    inst["config_changed_at"] = iso(env.sim_time)  # metrics before this moment describe the old size
    return {"message": f"Changed {tid} from {old} to {p['instance_type']}"}


@op("ec2.set_security_groups", "Set security groups", "ec2_instance", "Replace the security groups of an instance.",
    [P("sg_ids", "list")], risk="medium")
def ec2_set_sgs(env, tid, p):
    inst = env.get(tid)
    if not p["sg_ids"]:
        raise SimError("At least one security group is required", "invalid_parameter", 422)
    for sg_id in p["sg_ids"]:
        if env.get(sg_id, "security_group")["vpc_id"] != inst["vpc_id"]:
            raise SimError(f"{sg_id} is in a different VPC than {tid}", "invalid_relationship", 422)
    inst["sg_ids"] = list(dict.fromkeys(p["sg_ids"]))
    env.get(inst["eni_id"])["sg_ids"] = list(inst["sg_ids"])
    return {"message": f"Updated security groups of {tid}"}


@op("ec2.isolate", "Isolate (quarantine) instance", "ec2_instance",
    "Move the instance to a quarantine security group that allows no traffic.", risk="high")
def ec2_isolate(env, tid, _p):
    inst = env.get(tid)
    sg = next((s for s in env.of("security_group") if s["vpc_id"] == inst["vpc_id"] and s["name"] == "quarantine"), None)
    if sg is None:
        sg = b.build_security_group(env, name="quarantine", vpc_id=inst["vpc_id"],
                                    description="No inbound or outbound traffic", egress=[],
                                    tags={"purpose": "incident-response"})
    inst["sg_ids"] = [sg["id"]]
    env.get(inst["eni_id"])["sg_ids"] = [sg["id"]]
    return {"message": f"Isolated {tid} in {sg['id']}", "downtime": True}


# ------------------------------------------------------------------------ EBS
@op("ebs.create", "Create volume", None, "Create a new, unattached EBS volume.",
    [P("size_gb", "int"), P("az"), P("volume_type", choices=["gp3", "gp2", "io1", "st1"], required=False, default="gp3"),
     P("encrypted", "bool", False, default=True), P("name", required=False)])
def ebs_create(env, _t, p):
    _quota(env, "ebs_volumes", env.count("ebs_volume"), "EBS volumes")
    if p["az"] not in REGIONS[env.region]:
        raise SimError(f"Availability zone {p['az']} is not in region {env.region}", "invalid_parameter", 422)
    n = env.id_counters.get("named-vol", 0) + 1
    env.id_counters["named-vol"] = n
    vol = b.build_volume(env, name=p.get("name") or f"volume-{n:02d}", size_gb=p["size_gb"], az=p["az"],
                         volume_type=p["volume_type"], encrypted=p["encrypted"], tags={"environment": "dev"})
    return {"message": f"Created {vol['id']}", "created": [vol["id"]]}


@op("ebs.attach", "Attach volume", "ebs_volume", "Attach an available volume to an instance in the same AZ.",
    [P("instance_id"), P("device", required=False, default="/dev/sdg")])
def ebs_attach(env, tid, p):
    vol, inst = env.get(tid), env.get(p["instance_id"], "ec2_instance")
    if vol["state"] != "available":
        raise SimError(f"Volume {tid} is {vol['state']} and cannot be attached", "invalid_state")
    if inst["state"] == "terminated":
        raise SimError("Cannot attach a volume to a terminated instance", "invalid_state")
    if vol["az"] != inst["az"]:
        raise SimError(f"Volume is in {vol['az']} but the instance is in {inst['az']}", "invalid_relationship", 422)
    used = {env.resources["ebs_volume"][v]["device"] for v in inst["volume_ids"] if v in env.resources["ebs_volume"]}
    if p["device"] in used:
        raise SimError(f"Device {p['device']} is already in use on {inst['id']}", "duplicate_device")
    vol.update(state="in-use", attached_to=inst["id"], device=p["device"])
    inst["volume_ids"].append(tid)
    return {"message": f"Attached {tid} to {inst['id']} as {p['device']}"}


@op("ebs.detach", "Detach volume", "ebs_volume", "Detach a volume from its instance.", risk="medium")
def ebs_detach(env, tid, _p):
    vol = env.get(tid)
    if vol["state"] != "in-use":
        raise SimError(f"Volume {tid} is not attached", "invalid_state")
    inst = env.get(vol["attached_to"])
    if vol["device"] == "/dev/xvda" and inst["state"] == "running":
        raise SimError("Cannot detach the root volume of a running instance", "invalid_state")
    inst["volume_ids"].remove(tid)
    vol.update(state="available", attached_to=None, device=None)
    return {"message": f"Detached {tid}"}


@op("ebs.delete", "Delete volume", "ebs_volume", "Delete an unattached volume (snapshots are retained).", risk="high")
def ebs_delete(env, tid, _p):
    vol = env.get(tid)
    if vol["state"] != "available":
        raise SimError(f"Volume {tid} is attached and cannot be deleted", "invalid_state")
    env.remove(tid)
    return {"message": f"Deleted {tid}"}


@op("ebs.enable_encryption", "Enable volume encryption", "ebs_volume",
    "Encrypt the volume (modelled as an in-place encrypt; real AWS requires snapshot-copy-restore).", risk="medium")
def ebs_encrypt(env, tid, _p):
    vol = env.get(tid)
    if vol["encrypted"]:
        raise SimError(f"Volume {tid} is already encrypted", "no_change")
    vol["encrypted"] = True
    return {"message": f"Encrypted {tid}"}


@op("ebs.set_backup_policy", "Configure volume backup", "ebs_volume", "Set the automated snapshot schedule for a volume.",
    [P("policy", choices=["daily", "weekly", "none"])])
def ebs_backup(env, tid, p):
    vol = env.get(tid)
    if p["policy"] != "none" and vol["state"] != "in-use":
        raise SimError("Backup schedules apply to attached volumes only", "invalid_state")
    if vol["backup_policy"] == p["policy"]:
        raise SimError(f"Backup policy is already '{p['policy']}'", "no_change")
    vol["backup_policy"] = p["policy"]
    msg = f"Backup policy of {tid} set to {p['policy']}"
    if p["policy"] != "none":
        _quota(env, "snapshots", env.count("snapshot"), "snapshots")
        snap = b.build_snapshot(env, vol, managed_by="backup_policy", created_at=env.sim_time)
        msg += f"; initial snapshot {snap['id']} created"
    return {"message": msg}


@op("snapshot.create", "Create snapshot", "ebs_volume", "Take a point-in-time snapshot of a volume.")
def snapshot_create(env, tid, _p):
    _quota(env, "snapshots", env.count("snapshot"), "snapshots")
    snap = b.build_snapshot(env, env.get(tid), managed_by="manual", created_at=env.sim_time)
    return {"message": f"Created {snap['id']}", "created": [snap["id"]]}


@op("snapshot.delete", "Delete snapshot", "snapshot", "Delete a snapshot.", risk="medium")
def snapshot_delete(env, tid, _p):
    env.remove(tid)
    return {"message": f"Deleted {tid}"}


# --------------------------------------------------------------------- S3
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.\-]{2,62}$")


@op("s3.create_bucket", "Create bucket", None, "Create a private, encrypted S3 bucket.", [P("name")])
def s3_create(env, _t, p):
    name = p["name"]
    if not _BUCKET.match(name):
        raise SimError("Bucket names must be 3-63 characters of lowercase letters, digits, dots and hyphens",
                       "invalid_parameter", 422)
    if env.exists(name):
        raise SimError(f"Bucket name '{name}' is already taken", "duplicate_id")
    _quota(env, "s3_buckets", env.count("s3_bucket"), "S3 buckets")
    env.add("s3_bucket", {
        "id": name, "name": name, "purpose": "custom", "state": "active", "block_public_access": True,
        "acl": "private", "policy_public": False, "encryption": "AES256", "versioning": False, "size_gb": 0.0,
        "object_count": 0, "growth_gb_per_day": 0.0, "requests_per_day_base": 0, "tags": {"environment": "dev"},
        "created_at": iso(env.sim_time), "region": env.region,
    })
    return {"message": f"Created bucket {name}", "created": [name]}


@op("s3.delete_bucket", "Delete bucket", "s3_bucket", "Delete a bucket. Non-empty buckets require force.",
    [P("force", "bool", False, default=False)], risk="high")
def s3_delete(env, tid, p):
    bucket = env.get(tid)
    if bucket["size_gb"] > 0 and not p["force"]:
        raise SimError(f"Bucket {tid} is not empty ({bucket['size_gb']} GB); pass force=true to delete", "not_empty")
    env.remove(tid)
    return {"message": f"Deleted bucket {tid}"}


@op("s3.set_public_access_block", "Set Block Public Access", "s3_bucket", "Turn S3 Block Public Access on or off.",
    [P("block", "bool")], risk="medium")
def s3_block(env, tid, p):
    bucket = env.get(tid)
    if bucket["block_public_access"] == p["block"]:
        raise SimError(f"Block Public Access is already {'on' if p['block'] else 'off'}", "no_change")
    bucket["block_public_access"] = p["block"]
    return {"message": f"Block Public Access {'enabled' if p['block'] else 'disabled'} on {tid}"}


@op("s3.set_acl", "Set bucket ACL", "s3_bucket", "Set the canned ACL of a bucket.",
    [P("acl", choices=["private", "public-read"])], risk="medium")
def s3_acl(env, tid, p):
    bucket = env.get(tid)
    if p["acl"] == "public-read" and bucket["block_public_access"]:
        raise SimError("Block Public Access is on: public ACLs are rejected", "access_denied")
    if bucket["acl"] == p["acl"]:
        raise SimError(f"ACL is already {p['acl']}", "no_change")
    bucket["acl"] = p["acl"]
    return {"message": f"ACL of {tid} set to {p['acl']}"}


@op("s3.set_public_policy", "Set public bucket policy", "s3_bucket", "Add or remove a bucket policy granting Principal '*'.",
    [P("enabled", "bool")], risk="medium")
def s3_policy(env, tid, p):
    bucket = env.get(tid)
    if p["enabled"] and bucket["block_public_access"]:
        raise SimError("Block Public Access is on: public bucket policies are rejected", "access_denied")
    bucket["policy_public"] = p["enabled"]
    return {"message": f"Public bucket policy {'added to' if p['enabled'] else 'removed from'} {tid}"}


@op("s3.make_private", "Make bucket private", "s3_bucket",
    "Enable Block Public Access, reset the ACL to private and remove public bucket policies.", risk="medium")
def s3_private(env, tid, _p):
    bucket = env.get(tid)
    bucket.update(block_public_access=True, acl="private", policy_public=False)
    return {"message": f"{tid} is now private"}


@op("s3.enable_encryption", "Enable bucket encryption", "s3_bucket", "Enable default server-side encryption.",
    [P("algorithm", choices=["AES256", "aws:kms"], required=False, default="AES256")])
def s3_encrypt(env, tid, p):
    bucket = env.get(tid)
    if bucket["encryption"] == p["algorithm"]:
        raise SimError(f"Bucket already uses {p['algorithm']}", "no_change")
    bucket["encryption"] = p["algorithm"]
    return {"message": f"Enabled {p['algorithm']} encryption on {tid}"}


@op("s3.set_versioning", "Set bucket versioning", "s3_bucket", "Enable or suspend versioning.", [P("enabled", "bool")])
def s3_versioning(env, tid, p):
    env.get(tid)["versioning"] = p["enabled"]
    return {"message": f"Versioning {'enabled' if p['enabled'] else 'suspended'} on {tid}"}


# --------------------------------------------------------- security groups
_PROTOCOLS = ["tcp", "udp", "icmp", "-1"]
_RULE_PARAMS = [P("protocol", choices=_PROTOCOLS), P("from_port", "int", False), P("to_port", "int", False),
                P("cidr", required=False), P("source_sg", required=False), P("description", required=False)]


def _make_rule(env: Environment, p: dict[str, Any]) -> dict[str, Any]:
    proto = p["protocol"]
    if proto != "-1" and ("from_port" not in p or "to_port" not in p):
        raise SimError("from_port and to_port are required unless protocol is -1", "invalid_parameter", 422)
    lo, hi = (0, 65535) if proto == "-1" else (p["from_port"], p["to_port"])
    if not (0 <= lo <= hi <= 65535):
        raise SimError("Ports must satisfy 0 <= from_port <= to_port <= 65535", "invalid_parameter", 422)
    if bool(p.get("cidr")) == bool(p.get("source_sg")):
        raise SimError("Provide exactly one of cidr or source_sg", "invalid_parameter", 422)
    if p.get("source_sg"):
        env.get(p["source_sg"], "security_group")
    return b.rule(proto, lo, hi, _cidr(p["cidr"]) if p.get("cidr") else None, p.get("source_sg"), p.get("description", ""))


def _same(a: dict[str, Any], c: dict[str, Any]) -> bool:
    return all(a[k] == c[k] for k in ("protocol", "from_port", "to_port", "cidr", "source_sg"))


@op("sg.create", "Create security group", None, "Create a security group with no inbound rules.",
    [P("vpc_id"), P("name"), P("description", required=False, default="created via CloudShield")])
def sg_create(env, _t, p):
    _quota(env, "security_groups", len(env.of("security_group")), "security groups")
    if any(s["vpc_id"] == p["vpc_id"] and s["name"] == p["name"] for s in env.of("security_group")):
        raise SimError(f"A security group named '{p['name']}' already exists in {p['vpc_id']}", "duplicate_id")
    sg = b.build_security_group(env, name=p["name"], vpc_id=p["vpc_id"], description=p["description"])
    return {"message": f"Created {sg['id']}", "created": [sg["id"]]}


@op("sg.delete", "Delete security group", "security_group", "Delete an unused security group.", risk="medium")
def sg_delete(env, tid, _p):
    users = _in_use_by(env, tid)
    if users:
        raise SimError(f"{tid} is still in use by {', '.join(users[:3])}", "in_use")
    env.remove(tid)
    return {"message": f"Deleted {tid}"}


@op("sg.authorize_ingress", "Add inbound rule", "security_group", "Add an inbound rule.", _RULE_PARAMS, risk="medium")
def sg_authorize_in(env, tid, p):
    sg = env.get(tid)
    rule = _make_rule(env, p)
    if any(_same(r, rule) for r in sg["ingress"]):
        raise SimError("An identical inbound rule already exists", "duplicate_rule")
    if len(sg["ingress"]) >= 60:
        raise SimError("A security group may have at most 60 inbound rules", "quota_exceeded")
    sg["ingress"].append(rule)
    return {"message": f"Added inbound rule {rule['protocol']}/{rule['from_port']}-{rule['to_port']} to {tid}"}


@op("sg.revoke_ingress", "Remove inbound rule", "security_group", "Remove a matching inbound rule.", _RULE_PARAMS, risk="medium")
def sg_revoke_in(env, tid, p):
    sg = env.get(tid)
    rule = _make_rule(env, p)
    for r in sg["ingress"]:
        if _same(r, rule):
            sg["ingress"].remove(r)
            return {"message": f"Removed inbound rule from {tid}"}
    raise SimError("No matching inbound rule found", "not_found", 404)


@op("sg.restrict_ingress", "Restrict inbound rule source", "security_group",
    "Change the source CIDR of an existing inbound rule (for example from 0.0.0.0/0 to a trusted range).",
    [P("protocol", choices=_PROTOCOLS), P("from_port", "int", False), P("to_port", "int", False), P("cidr"), P("new_cidr")], risk="medium")
def sg_restrict(env, tid, p):
    sg = env.get(tid)
    new_cidr = _cidr(p["new_cidr"])
    old = _make_rule(env, {k: p[k] for k in ("protocol", "from_port", "to_port", "cidr") if k in p})
    for r in sg["ingress"]:
        if _same(r, old):
            if new_cidr == r["cidr"]:
                raise SimError("The new source equals the current source", "no_change")
            r["cidr"] = new_cidr
            return {"message": f"Restricted {r['protocol']}/{r['from_port']}-{r['to_port']} on {tid} to {new_cidr}"}
    raise SimError("No matching inbound rule found", "not_found", 404)


@op("sg.authorize_egress", "Add outbound rule", "security_group", "Add an outbound rule.", _RULE_PARAMS, risk="medium")
def sg_authorize_out(env, tid, p):
    sg = env.get(tid)
    rule = _make_rule(env, p)
    if any(_same(r, rule) for r in sg["egress"]):
        raise SimError("An identical outbound rule already exists", "duplicate_rule")
    sg["egress"].append(rule)
    return {"message": f"Added outbound rule to {tid}"}


@op("sg.revoke_egress", "Remove outbound rule", "security_group", "Remove a matching outbound rule.", _RULE_PARAMS, risk="medium")
def sg_revoke_out(env, tid, p):
    sg = env.get(tid)
    rule = _make_rule(env, p)
    for r in sg["egress"]:
        if _same(r, rule):
            sg["egress"].remove(r)
            return {"message": f"Removed outbound rule from {tid}"}
    raise SimError("No matching outbound rule found", "not_found", 404)


# ------------------------------------------------------------------ network
@op("route.set", "Set route", "route_table", "Create or replace a route in a route table.",
    [P("destination"), P("target_type", choices=["igw"]), P("target")], risk="high")
def route_set(env, tid, p):
    rt = env.get(tid)
    dest = _cidr(p["destination"])
    igw = env.get(p["target"], "internet_gateway")
    if igw["vpc_id"] != rt["vpc_id"] or igw.get("state") != "attached":
        raise SimError(f"{igw['id']} is not attached to {rt['vpc_id']}", "invalid_relationship", 422)
    for r in rt["routes"]:
        if r["destination"] == dest:
            if r["target_type"] == "local":
                raise SimError("The local route cannot be replaced", "invalid_operation")
            r.update(target_type="igw", target=igw["id"])
            break
    else:
        rt["routes"].append({"destination": dest, "target_type": "igw", "target": igw["id"]})
    return {"message": f"Route {dest} -> {igw['id']} set in {tid}"}


@op("route.delete", "Delete route", "route_table", "Remove a route from a route table.",
    [P("destination")], risk="high")
def route_delete(env, tid, p):
    rt = env.get(tid)
    dest = _cidr(p["destination"])
    for r in rt["routes"]:
        if r["destination"] == dest:
            if r["target_type"] == "local":
                raise SimError("The local route cannot be deleted", "invalid_operation")
            rt["routes"].remove(r)
            return {"message": f"Deleted route {dest} from {tid}"}
    raise SimError(f"Route {dest} not found in {tid}", "not_found", 404)


@op("subnet.associate_route_table", "Associate route table", "subnet", "Associate a subnet with a route table.",
    [P("route_table_id")], risk="high")
def subnet_assoc(env, tid, p):
    subnet, rt = env.get(tid), env.get(p["route_table_id"], "route_table")
    if rt["vpc_id"] != subnet["vpc_id"]:
        raise SimError("Route table and subnet are in different VPCs", "invalid_relationship", 422)
    if subnet["route_table_id"] == rt["id"]:
        raise SimError("Subnet already uses this route table", "no_change")
    subnet["route_table_id"] = rt["id"]
    return {"message": f"Associated {tid} with {rt['id']}"}


@op("igw.detach", "Detach internet gateway", "internet_gateway", "Detach an internet gateway from its VPC.", risk="high")
def igw_detach(env, tid, _p):
    igw = env.get(tid)
    if igw["state"] != "attached":
        raise SimError("Internet gateway is already detached", "invalid_state")
    igw["state"] = "detached"
    env.get(igw["vpc_id"])["igw_id"] = None
    return {"message": f"Detached {tid}"}


@op("igw.attach", "Attach internet gateway", "internet_gateway", "Re-attach an internet gateway to its VPC.", risk="high")
def igw_attach(env, tid, _p):
    igw = env.get(tid)
    if igw["state"] == "attached":
        raise SimError("Internet gateway is already attached", "invalid_state")
    vpc = env.get(igw["vpc_id"])
    if vpc["igw_id"]:
        raise SimError("The VPC already has an internet gateway attached", "invalid_state")
    igw["state"], vpc["igw_id"] = "attached", igw["id"]
    return {"message": f"Attached {tid}"}


@op("eip.allocate", "Allocate Elastic IP", None, "Allocate a new Elastic IP address.")
def eip_allocate(env, _t, _p):
    _quota(env, "elastic_ips", len(env.of("elastic_ip")), "Elastic IP addresses")
    n = env.id_counters.get("named-eip", 0) + 1
    env.id_counters["named-eip"] = n
    eip = env.add("elastic_ip", {
        "id": env.new_id("eipalloc"), "name": f"eip-new-{n:02d}", "public_ip": b.alloc_public_ip(env),
        "instance_id": None, "eni_id": None, "state": "unassociated", "tags": {}, "created_at": iso(env.sim_time),
        "region": env.region,
    })
    return {"message": f"Allocated {eip['public_ip']}", "created": [eip["id"]]}


@op("eip.associate", "Associate Elastic IP", "elastic_ip", "Associate an Elastic IP with an instance.", [P("instance_id")])
def eip_assoc(env, tid, p):
    eip, inst = env.get(tid), env.get(p["instance_id"], "ec2_instance")
    if eip["instance_id"]:
        raise SimError(f"{tid} is already associated with {eip['instance_id']}", "invalid_state")
    if inst["state"] == "terminated":
        raise SimError("Cannot associate an address with a terminated instance", "invalid_state")
    eip.update(instance_id=inst["id"], eni_id=inst["eni_id"], state="associated")
    inst["public_ip"] = eip["public_ip"]
    env.get(inst["eni_id"])["public_ip"] = eip["public_ip"]
    return {"message": f"Associated {eip['public_ip']} with {inst['id']}"}


@op("eip.disassociate", "Disassociate Elastic IP", "elastic_ip", "Disassociate an Elastic IP from its instance.", risk="medium")
def eip_disassoc(env, tid, _p):
    eip = env.get(tid)
    if not eip["instance_id"]:
        raise SimError(f"{tid} is not associated", "invalid_state")
    inst = env.resources["ec2_instance"].get(eip["instance_id"])
    if inst:
        inst["public_ip"] = None
        env.get(inst["eni_id"])["public_ip"] = None
    eip.update(instance_id=None, eni_id=None, state="unassociated")
    return {"message": f"Disassociated {tid}"}


@op("eip.release", "Release Elastic IP", "elastic_ip", "Release an unassociated Elastic IP address.", risk="medium")
def eip_release(env, tid, _p):
    if env.get(tid)["instance_id"]:
        raise SimError("Disassociate the address before releasing it", "in_use")
    env.remove(tid)
    return {"message": f"Released {tid}"}


@op("lb.delete", "Delete load balancer", "load_balancer", "Delete a load balancer.", risk="high")
def lb_delete(env, tid, _p):
    env.remove(tid)
    return {"message": f"Deleted {tid}"}


# --------------------------------------------------------------------- RDS
@op("rds.create", "Create database", None, "Create an RDS instance in the private subnets of a VPC.",
    [P("name"), P("vpc_id"), P("engine", choices=["postgres", "mysql"]), P("instance_class", choices=sorted(RDS_CLASSES)),
     P("storage_gb", "int", False, default=100), P("multi_az", "bool", False, default=False),
     P("backup_retention_days", "int", False, default=7), P("encrypted", "bool", False, default=True)])
def rds_create(env, _t, p):
    _quota(env, "rds_instances", env.count("rds_instance"), "RDS instances")
    if env.exists(p["name"]):
        raise SimError(f"Identifier '{p['name']}' already exists", "duplicate_id")
    if not 0 <= p["backup_retention_days"] <= 35:
        raise SimError("backup_retention_days must be between 0 and 35", "invalid_parameter", 422)
    if p["storage_gb"] < 20:
        raise SimError("storage_gb must be at least 20", "invalid_parameter", 422)
    env.get(p["vpc_id"], "vpc")
    private = [s for s in env.of("subnet") if s["vpc_id"] == p["vpc_id"] and s["tags"].get("tier") == "private"]
    dbsg = next((s for s in env.of("security_group") if s["vpc_id"] == p["vpc_id"] and s["name"].endswith("db-sg")), None)
    if len(private) < 2 or dbsg is None:
        raise SimError("The VPC needs two private subnets and a database security group", "invalid_relationship", 422)
    port = 5432 if p["engine"] == "postgres" else 3306
    eni = env.add("network_interface", {
        "id": env.new_id("eni"), "name": f"{p['name']}-eni", "subnet_id": private[0]["id"], "vpc_id": p["vpc_id"],
        "private_ip": b.alloc_private_ip(env, private[0]), "public_ip": None, "sg_ids": [dbsg["id"]],
        "attached_to": p["name"], "state": "in-use", "description": f"Interface of {p['name']}",
        "created_at": iso(env.sim_time), "tags": {}, "region": env.region})
    vcpus = RDS_CLASSES[p["instance_class"]][0]
    wl = b.workload_for(env, p["name"], "normal", "app", vcpus)
    env.add("rds_instance", {
        "id": p["name"], "name": p["name"], "engine": p["engine"], "engine_version": "15.4" if p["engine"] == "postgres" else "8.0.35",
        "instance_class": p["instance_class"], "storage_gb": p["storage_gb"], "multi_az": p["multi_az"],
        "publicly_accessible": False, "storage_encrypted": p["encrypted"], "backup_retention_days": p["backup_retention_days"],
        "last_backup_at": iso(env.sim_time) if p["backup_retention_days"] else None, "vpc_id": p["vpc_id"],
        "subnet_ids": [s["id"] for s in private[:2]], "sg_ids": [dbsg["id"]], "eni_id": eni["id"], "port": port,
        "state": "available", "az": private[0]["az"], "profile": "normal", "workload_vcpu": wl["workload_vcpu"],
        "mem_pct_base": wl["mem_pct_base"], "storage_used_pct_base": 30.0, "conn_base": 20,
        "tags": {"environment": "dev", "owner": "platform-team"}, "created_at": iso(env.sim_time), "region": env.region})
    return {"message": f"Created database {p['name']}", "created": [p["name"]]}


@op("rds.modify", "Modify database", "rds_instance", "Change the instance class, Multi-AZ setting or allocated storage.",
    [P("instance_class", choices=sorted(RDS_CLASSES), required=False), P("multi_az", "bool", False),
     P("storage_gb", "int", False)], risk="medium")
def rds_modify(env, tid, p):
    db = env.get(tid)
    if not p:
        raise SimError("Provide at least one setting to modify", "invalid_parameter", 422)
    changed = []
    if "instance_class" in p and p["instance_class"] != db["instance_class"]:
        db["instance_class"] = p["instance_class"]
        db["config_changed_at"] = iso(env.sim_time)
        changed.append(f"class={p['instance_class']}")
    if "multi_az" in p and p["multi_az"] != db["multi_az"]:
        db["multi_az"] = p["multi_az"]
        changed.append(f"multi_az={p['multi_az']}")
    if "storage_gb" in p:
        if p["storage_gb"] < db["storage_gb"]:
            raise SimError("Allocated storage cannot be reduced", "invalid_parameter", 422)
        if p["storage_gb"] != db["storage_gb"]:
            db["storage_gb"] = p["storage_gb"]
            changed.append(f"storage={p['storage_gb']}GB")
    if not changed:
        raise SimError("No change: the database already has these settings", "no_change")
    return {"message": f"Modified {tid}: {', '.join(changed)}", "downtime": "instance_class" in p}


@op("rds.make_private", "Make database private", "rds_instance",
    "Turn off public access, move the database to private subnets and remove world-open rules for its port.", risk="medium")
def rds_private(env, tid, _p):
    db = env.get(tid)
    private = [s for s in env.of("subnet") if s["vpc_id"] == db["vpc_id"] and s["tags"].get("tier") == "private"]
    if not private:
        raise SimError("No private subnets available in the VPC", "invalid_relationship", 422)
    db["publicly_accessible"] = False
    db["subnet_ids"] = [s["id"] for s in private[:2]]
    eni = env.get(db["eni_id"])
    if eni["subnet_id"] not in {s["id"] for s in private}:
        eni["subnet_id"] = private[0]["id"]
        eni["private_ip"] = b.alloc_private_ip(env, private[0])
        db["az"] = private[0]["az"]
    eni["public_ip"] = None
    removed = 0
    for sg_id in db["sg_ids"]:
        sg = env.get(sg_id)
        keep = [r for r in sg["ingress"] if not (r.get("cidr") in ("0.0.0.0/0", "::/0") and r["from_port"] <= db["port"] <= r["to_port"])]
        removed += len(sg["ingress"]) - len(keep)
        sg["ingress"] = keep
    return {"message": f"{tid} is now private ({removed} world-open rule(s) removed)"}


@op("rds.enable_encryption", "Enable database encryption", "rds_instance",
    "Encrypt database storage (modelled as an in-place change; real AWS needs snapshot-restore).", risk="medium")
def rds_encrypt(env, tid, _p):
    db = env.get(tid)
    if db["storage_encrypted"]:
        raise SimError(f"{tid} is already encrypted", "no_change")
    db["storage_encrypted"] = True
    return {"message": f"Encrypted {tid}"}


@op("rds.set_backup_retention", "Configure database backups", "rds_instance", "Set automated backup retention (0 disables backups).",
    [P("days", "int")])
def rds_backup(env, tid, p):
    db = env.get(tid)
    if not 0 <= p["days"] <= 35:
        raise SimError("days must be between 0 and 35", "invalid_parameter", 422)
    if db["backup_retention_days"] == p["days"]:
        raise SimError(f"Backup retention is already {p['days']} days", "no_change")
    db["backup_retention_days"] = p["days"]
    db["last_backup_at"] = iso(env.sim_time) if p["days"] > 0 else None
    return {"message": f"Backup retention of {tid} set to {p['days']} days"}


@op("rds.delete", "Delete database", "rds_instance", "Delete a database instance.", risk="high")
def rds_delete(env, tid, _p):
    db = env.get(tid)
    if db["eni_id"] in env.resources["network_interface"]:
        env.remove(db["eni_id"])
    env.remove(tid)
    return {"message": f"Deleted database {tid}", "downtime": True}


# ----------------------------------------------------------------------- IAM
_PRINCIPALS = ("iam_user", "iam_role")


@op("iam.create_policy", "Create IAM policy", None, "Create a customer-managed policy with one statement.",
    [P("name"), P("effect", choices=["Allow", "Deny"]), P("actions", "list"), P("resources", "list")])
def iam_create_policy(env, _t, p):
    pid = f"policy:{p['name']}"
    if not re.match(r"^[A-Za-z0-9+=,.@_-]{1,64}$", p["name"]):
        raise SimError("Invalid policy name", "invalid_parameter", 422)
    if env.exists(pid):
        raise SimError(f"Policy '{p['name']}' already exists", "duplicate_id")
    if not p["actions"] or not p["resources"]:
        raise SimError("Provide at least one action and one resource", "invalid_parameter", 422)
    env.add("iam_policy", {"id": pid, "name": p["name"], "managed": False, "state": "active",
                           "statements": [{"effect": p["effect"], "actions": p["actions"], "resources": p["resources"]}],
                           "tags": {}, "created_at": iso(env.sim_time), "region": "global"})
    return {"message": f"Created {pid}", "created": [pid]}


@op("iam.attach_policy", "Attach policy", _PRINCIPALS, "Attach an IAM policy to a user or role.", [P("policy_id")], risk="high")
def iam_attach(env, tid, p):
    principal, pol = env.get(tid), env.get(p["policy_id"], "iam_policy")
    if pol["id"] in principal["policy_ids"]:
        raise SimError(f"{pol['name']} is already attached to {tid}", "duplicate_rule")
    principal["policy_ids"].append(pol["id"])
    return {"message": f"Attached {pol['name']} to {tid}"}


@op("iam.detach_policy", "Detach policy", _PRINCIPALS, "Detach an IAM policy from a user or role.", [P("policy_id")], risk="high")
def iam_detach(env, tid, p):
    principal = env.get(tid)
    if p["policy_id"] not in principal["policy_ids"]:
        raise SimError(f"{p['policy_id']} is not attached to {tid}", "not_found", 404)
    principal["policy_ids"].remove(p["policy_id"])
    return {"message": f"Detached {p['policy_id']} from {tid}"}


@op("iam.enable_mfa", "Enable MFA", "iam_user", "Enrol a virtual MFA device for the user.")
def iam_mfa(env, tid, _p):
    user = env.get(tid)
    if user["mfa_enabled"]:
        raise SimError(f"{tid} already has MFA enabled", "no_change")
    if not user["console_access"]:
        raise SimError("MFA applies to users with console access", "invalid_state")
    user["mfa_enabled"] = True
    return {"message": f"MFA enabled for {tid}"}


@op("iam.deactivate_access_key", "Deactivate access key", "iam_user", "Deactivate one access key.",
    [P("key_id")], risk="medium")
def iam_deact(env, tid, p):
    user = env.get(tid)
    for key in user["access_keys"]:
        if key["id"] == p["key_id"]:
            if key["status"] == "inactive":
                raise SimError("Access key is already inactive", "no_change")
            key["status"] = "inactive"
            return {"message": f"Deactivated access key {key['id']} of {tid}"}
    raise SimError(f"Access key {p['key_id']} not found for {tid}", "not_found", 404)


@op("iam.delete_access_key", "Delete access key", "iam_user", "Delete one access key.", [P("key_id")], risk="high")
def iam_delkey(env, tid, p):
    user = env.get(tid)
    for key in user["access_keys"]:
        if key["id"] == p["key_id"]:
            user["access_keys"].remove(key)
            return {"message": f"Deleted access key {key['id']} of {tid}"}
    raise SimError(f"Access key {p['key_id']} not found for {tid}", "not_found", 404)


@op("iam.restrict_trust", "Restrict role trust policy", "iam_role",
    "Remove wildcard or external-account principals from a role's trust policy.", risk="medium")
def iam_trust(env, tid, _p):
    role = env.get(tid)
    keep = [t for t in role["trust"] if not (t["type"] == "AWS" and (t["value"] == "*" or
                                                                    (t["value"].isdigit() and t["value"] != env.account_id)))]
    if len(keep) == len(role["trust"]):
        raise SimError("The trust policy has no wildcard or external principals", "no_change")
    if not keep:
        raise SimError("Removing these principals would leave the role with no trust relationship", "invalid_operation")
    role["trust"] = keep
    return {"message": f"Restricted trust policy of {tid}"}


@op("iam.create_user", "Create IAM user", None, "Create an IAM user.", [P("name"), P("console_access", "bool", False, default=True)])
def iam_create_user(env, _t, p):
    uid = f"user:{p['name']}"
    _quota(env, "iam_users", len(env.of("iam_user")), "IAM users")
    if not re.match(r"^[A-Za-z0-9+=,.@_-]{1,64}$", p["name"]):
        raise SimError("Invalid user name", "invalid_parameter", 422)
    if env.exists(uid):
        raise SimError(f"User '{p['name']}' already exists", "duplicate_id")
    env.add("iam_user", {"id": uid, "name": p["name"], "console_access": p["console_access"], "mfa_enabled": False,
                         "access_keys": [], "policy_ids": [], "kind": "developer", "state": "active",
                         "tags": {"owner": "platform-team"}, "created_at": iso(env.sim_time), "region": "global"})
    return {"message": f"Created {uid}", "created": [uid]}


@op("iam.delete_user", "Delete IAM user", "iam_user", "Delete an IAM user.", risk="high")
def iam_delete_user(env, tid, _p):
    env.remove(tid)
    return {"message": f"Deleted {tid}"}


# ------------------------------------------------------------------- tagging
_TAGGABLE = ("ec2_instance", "ebs_volume", "snapshot", "s3_bucket", "rds_instance", "security_group", "vpc", "subnet",
             "load_balancer", "elastic_ip", "iam_user", "iam_role")


@op("tags.set", "Set tags", _TAGGABLE, "Add or update tags on a resource.", [P("tags", "dict")])
def tags_set(env, tid, p):
    res = env.get(tid)
    for k, v in p["tags"].items():
        if not isinstance(k, str) or not k or len(k) > 128 or not isinstance(v, str) or len(v) > 256:
            raise SimError("Tag keys and values must be non-empty strings within AWS length limits", "invalid_parameter", 422)
    if len({**res.get("tags", {}), **p["tags"]}) > 50:
        raise SimError("A resource may have at most 50 tags", "quota_exceeded")
    res.setdefault("tags", {}).update(p["tags"])
    return {"message": f"Updated tags of {tid}"}


@op("tags.remove", "Remove tags", _TAGGABLE, "Remove tags from a resource.", [P("keys", "list")])
def tags_remove(env, tid, p):
    res = env.get(tid)
    missing = [k for k in p["keys"] if k not in res.get("tags", {})]
    if missing:
        raise SimError(f"Tags not present: {missing}", "not_found", 404)
    for k in p["keys"]:
        res["tags"].pop(k)
    return {"message": f"Removed tags from {tid}"}
