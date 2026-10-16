"""Simplified IAM model: policy evaluation, trust, and privilege escalation paths."""

from __future__ import annotations

from collections import deque
from fnmatch import fnmatchcase
from typing import Any, Iterator

from app.simulator.env import Environment, parse_iso

PRINCIPAL_TYPES = ("iam_user", "iam_role")
IAM_WRITE_ACTIONS = ("iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:PutUserPolicy",
                     "iam:PutRolePolicy", "iam:CreatePolicyVersion", "iam:UpdateAssumeRolePolicy")
ADMIN = "ADMIN"  # virtual node: full administrative control


def arn(env: Environment, principal: dict[str, Any]) -> str:
    kind = "user" if principal["type"] == "iam_user" else "role"
    return f"arn:aws:iam::{env.account_id}:{kind}/{principal['name']}"


def _action_match(patterns: list[str], action: str) -> bool:
    return any(fnmatchcase(action.lower(), p.lower()) for p in patterns)


def _resource_match(patterns: list[str], resource: str) -> bool:
    if resource == "*":
        return "*" in patterns
    return any(fnmatchcase(resource, p) for p in patterns)


def statements(env: Environment, principal: dict[str, Any]) -> Iterator[tuple[dict[str, Any], dict[str, Any]]]:
    for pid in principal.get("policy_ids", []):
        policy = env.resources["iam_policy"].get(pid)
        if policy:
            for st in policy["statements"]:
                yield policy, st


def evaluate(env: Environment, principal_id: str, action: str, resource: str = "*") -> dict[str, Any]:
    """Explicit deny > allow > implicit deny, with the matching statement for explanation."""
    principal = env.get(principal_id)
    allow = None
    for policy, st in statements(env, principal):
        if _action_match(st["actions"], action) and _resource_match(st["resources"], resource):
            if st["effect"] == "Deny":
                return {"decision": "DENY", "policy": policy["id"], "statement": st}
            if allow is None:
                allow = {"decision": "ALLOW", "policy": policy["id"], "statement": st}
    return allow or {"decision": "IMPLICIT_DENY", "policy": None, "statement": None}


def allowed(env: Environment, principal_id: str, action: str, resource: str = "*") -> bool:
    return evaluate(env, principal_id, action, resource)["decision"] == "ALLOW"


def is_admin(env: Environment, principal_id: str) -> bool:
    return allowed(env, principal_id, "*", "*")


def admin_policies(env: Environment, principal: dict[str, Any]) -> list[str]:
    """Policy ids that, by themselves, grant Action '*' on Resource '*'."""
    out = []
    for policy, st in statements(env, principal):
        if st["effect"] == "Allow" and "*" in st["actions"] and "*" in st["resources"] and policy["id"] not in out:
            out.append(policy["id"])
    return out


def principals(env: Environment) -> list[dict[str, Any]]:
    return env.of("iam_user") + env.of("iam_role")


def trust_match(env: Environment, role: dict[str, Any], principal: dict[str, Any]) -> tuple[bool, bool]:
    """(trusted, needs_identity_permission) for ``principal`` assuming ``role``.

    An explicit principal or wildcard in the trust policy suffices on its own; a
    trust on the account root additionally requires an identity-based allow.
    """
    via_root = False
    for t in role["trust"]:
        if t["type"] != "AWS":
            continue
        if t["value"] == "*" or t["value"] == principal["id"] or t["value"] == arn(env, principal):
            return True, False
        if t["value"] == env.account_id:
            via_root = True
    return (True, True) if via_root else (False, False)


def can_assume(env: Environment, principal: dict[str, Any], role: dict[str, Any]) -> bool:
    trusted, needs_identity = trust_match(env, role, principal)
    if not trusted:
        return False
    return (not needs_identity) or allowed(env, principal["id"], "sts:AssumeRole", arn(env, role))


def _age_days(env: Environment, value: str | None) -> int | None:
    return (env.sim_time - parse_iso(value)).days if value else None


def key_report(env: Environment, user: dict[str, Any]) -> list[dict[str, Any]]:
    max_age = env.config["iam"]["access_key_max_age_days"]
    out = []
    for key in user["access_keys"]:
        age, unused = _age_days(env, key["created_at"]), _age_days(env, key.get("last_used"))
        reasons = []
        if key["status"] == "active" and age is not None and age > max_age:
            reasons.append(f"active key is {age} days old (limit {max_age})")
        if key["status"] == "active" and unused is not None and unused >= 60:
            reasons.append(f"active key unused for {unused} days")
        out.append({"key_id": key["id"], "status": key["status"], "age_days": age, "unused_days": unused,
                    "reasons": reasons})
    return out


def risky_trusts(env: Environment, role: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for t in role["trust"]:
        if t["type"] != "AWS":
            continue
        if t["value"] == "*":
            out.append({"principal": "*", "reason": "any AWS principal in any account can assume this role"})
        elif t["value"].isdigit() and t["value"] != env.account_id:
            out.append({"principal": t["value"], "reason": f"external account {t['value']} is trusted without an ExternalId condition"})
    return out


def escalation_edges(env: Environment) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    roles = env.of("iam_role")
    ec2_roles = [r for r in roles if any(t["type"] == "Service" and t["value"] == "ec2.amazonaws.com" for t in r["trust"])]
    for p in principals(env):
        for role in roles:
            if role["id"] != p["id"] and can_assume(env, p, role):
                edges.append({"source": p["id"], "target": role["id"], "via": "sts:AssumeRole"})
        if allowed(env, p["id"], "iam:PassRole", "*") and allowed(env, p["id"], "ec2:RunInstances", "*"):
            for role in ec2_roles:
                if role["id"] != p["id"]:
                    edges.append({"source": p["id"], "target": role["id"], "via": "iam:PassRole + ec2:RunInstances"})
        for action in IAM_WRITE_ACTIONS:
            if allowed(env, p["id"], action, "*"):
                edges.append({"source": p["id"], "target": ADMIN, "via": action})
                break
    return edges


def escalation_paths(env: Environment) -> list[dict[str, Any]]:
    """Shortest path from every non-admin principal to administrative access."""
    edges = escalation_edges(env)
    adj: dict[str, list[dict[str, Any]]] = {}
    for e in edges:
        adj.setdefault(e["source"], []).append(e)
    admins = {p["id"] for p in principals(env) if is_admin(env, p["id"])}
    paths = []
    for origin in sorted(p["id"] for p in principals(env)):
        if origin in admins:
            continue
        queue = deque([(origin, [])])
        seen = {origin}
        found = None
        while queue and found is None:
            node, trail = queue.popleft()
            if len(trail) >= 4:
                continue
            for e in adj.get(node, []):
                nxt = e["target"]
                if nxt in seen:
                    continue
                step = trail + [e]
                if nxt in admins or nxt == ADMIN:
                    found = step
                    break
                seen.add(nxt)
                queue.append((nxt, step))
        if found:
            paths.append({"origin": origin, "target": found[-1]["target"], "steps": found,
                          "description": " -> ".join([origin] + [f"{s['target']} ({s['via']})" for s in found])})
    return paths


def analyze(env: Environment) -> dict[str, Any]:
    admin_ids = [p["id"] for p in principals(env) if is_admin(env, p["id"])]
    rows = []
    for p in principals(env):
        row = {"id": p["id"], "name": p["name"], "type": p["type"], "admin": p["id"] in admin_ids,
               "designated_admin": (p.get("tags") or {}).get("admin") == "designated",
               "policies": p["policy_ids"], "admin_policies": admin_policies(env, p)}
        if p["type"] == "iam_user":
            row.update(console_access=p["console_access"], mfa_enabled=p["mfa_enabled"],
                       keys=key_report(env, p), kind=p.get("kind"))
        else:
            row.update(trust=p["trust"], risky_trust=risky_trusts(env, p))
        rows.append(row)
    paths = escalation_paths(env)
    nodes = [{"id": r["id"], "label": r["name"], "type": r["type"], "admin": r["admin"],
              "mfa": r.get("mfa_enabled")} for r in rows]
    edges = escalation_edges(env)
    if any(e["target"] == ADMIN for e in edges):
        nodes.append({"id": ADMIN, "label": "Administrative control", "type": "virtual", "admin": True, "mfa": None})
    path_edges = {(s["source"], s["target"]) for p in paths for s in p["steps"]}
    for e in edges:
        e["on_escalation_path"] = (e["source"], e["target"]) in path_edges
    return {
        "principals": rows,
        "admin_principals": admin_ids,
        "escalation_paths": paths,
        "graph": {"nodes": nodes, "edges": edges},
        "summary": {
            "users": len(env.of("iam_user")), "roles": len(env.of("iam_role")), "admins": len(admin_ids),
            "users_without_mfa": sum(1 for r in rows if r["type"] == "iam_user" and r["console_access"] and not r["mfa_enabled"]),
            "risky_trusts": sum(len(r.get("risky_trust", [])) for r in rows),
            "escalation_paths": len(paths),
        },
    }
