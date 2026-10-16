"""Static checks for docker-compose.yml and the Dockerfiles (Docker itself may be unavailable)."""
import re
import sys
from pathlib import Path

import yaml

root = Path(__file__).resolve().parents[1]
compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
svc = compose["services"]
print("services:", ", ".join(svc))
problems = []
for name, s in svc.items():
    print(f"- {name}: " + ("image " + s["image"] if "image" in s else "build " + s["build"]) + (f", ports {s.get('ports')}" if s.get("ports") else ""))
    if "healthcheck" in s:
        print(f"    healthcheck: {s['healthcheck']['test'][0]} (interval {s['healthcheck']['interval']})")
    for dep, cond in (s.get("depends_on") or {}).items():
        print(f"    depends_on {dep}: {cond['condition']}")
        if dep not in svc:
            problems.append(f"{name} depends on unknown service {dep}")
print("volumes:", list(compose.get("volumes", {})))
for name in ("backend", "frontend"):
    ctx = root / svc[name]["build"].lstrip("./")
    df = (ctx / "Dockerfile").read_text(encoding="utf-8")
    print(f"{name}/Dockerfile: base {re.search(r'^FROM (.+)$', df, re.M).group(1)}, {len(df.splitlines())} lines")
    for m in re.finditer(r"^COPY (\S+)", df, re.M):
        src = m.group(1)
        if src != "." and not (ctx / src).exists():
            problems.append(f"{name}: COPY source {src} missing")
env = (root / ".env.example").read_text(encoding="utf-8")
needed = set(re.findall(r"\$\{([A-Z_]+)(?::[?-][^}]*)?\}", (root / "docker-compose.yml").read_text(encoding="utf-8")))
missing = sorted(n for n in needed if n not in env)
print("compose variables:", ", ".join(sorted(needed)))
print("missing from .env.example:", missing or "none")
problems += [f"{m} not in .env.example" for m in missing]
print("RESULT:", "OK - static checks passed (image build NOT executed)" if not problems else "PROBLEMS: " + "; ".join(problems))
sys.exit(1 if problems else 0)
