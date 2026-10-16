"""Regression tests: behaviour that existed before the simulator was added must keep working.

The legacy label-based engines and mock provider are intentionally unchanged. These tests pin their
observable behaviour (authentication, dashboard, inventory, security, cost, recommendations, reports
persistence and the original API routes).
"""

import pytest

from app.cost_engine import analyze_costs, calculate_savings_percentage
from app.models import (
    CloudResource, CostOpportunity, CostRecord, Recommendation, Scan, SecurityFinding, User,
)
from app.persistence import save_scan_results
from app.providers import get_cloud_provider
from app.providers.mock_provider import MockCloudProvider
from app.recommendation_engine import build_recommendation_summary, generate_recommendations
from app.scan_service import normalize_resource, run_complete_scan
from app.security_engine import build_scan_summary, calculate_security_score, check_resource, run_security_scan


# ----------------------------------------------------------------- authentication
def test_register_login_and_me_flow(client):
    r = client.post("/api/auth/register", json={"email": "reg@example.com", "password": "longpassword1"})
    assert r.status_code == 201 and r.json()["email"] == "reg@example.com" and "password_hash" not in r.json()
    dup = client.post("/api/auth/register", json={"email": "reg@example.com", "password": "longpassword1"})
    assert dup.status_code == 400 and "already exists" in dup.json()["detail"]
    login = client.post("/api/auth/login", json={"email": "reg@example.com", "password": "longpassword1"})
    assert login.status_code == 200 and login.json()["token_type"] == "bearer"
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {login.json()['access_token']}"})
    assert me.json()["email"] == "reg@example.com"


@pytest.mark.parametrize("payload", [
    {"email": "reg@example.com", "password": "wrong-password"},
    {"email": "nobody@example.com", "password": "whatever123"},
])
def test_login_rejects_bad_credentials_with_same_message(client, payload):
    client.post("/api/auth/register", json={"email": "reg@example.com", "password": "longpassword1"})
    r = client.post("/api/auth/login", json=payload)
    assert r.status_code == 401 and r.json()["detail"] == "Incorrect email or password."


@pytest.mark.parametrize("payload", [
    {"email": "not-an-email", "password": "longpassword1"},
    {"email": "ok@example.com", "password": "short"},
    {"email": "ok@example.com"},
])
def test_register_validation(client, payload):
    assert client.post("/api/auth/register", json=payload).status_code == 422


def test_passwords_are_stored_hashed(client, db):
    client.post("/api/auth/register", json={"email": "hash@example.com", "password": "longpassword1"})
    stored = db.query(User).filter(User.email == "hash@example.com").one().password_hash
    assert stored != "longpassword1" and stored.startswith("$2")


# ------------------------------------------------------------- mock provider/engines
def test_mock_provider_inventory_is_unchanged():
    p = MockCloudProvider()
    assert len(p.get_all_resources()) == 15
    assert p.get_provider_info() == {"provider": "Mock Cloud", "mode": "DEMO", "aws_enabled": False, "credentials_required": False}
    assert sum(c["amount"] for c in p.get_cost_data()) == 1120.0


def test_provider_factory_defaults_to_mock_and_refuses_real_aws(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    assert isinstance(get_cloud_provider(), MockCloudProvider)
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setenv("AWS_ENABLED", "true")
    with pytest.raises(RuntimeError):
        get_cloud_provider()


def test_complete_scan_baseline_values():
    result = run_complete_scan()
    assert len(result["resources"]) == 15
    assert result["security"]["security_score"] == 96 and result["security"]["total_findings"] == 2
    assert sorted(f["title"] for f in result["findings"]) == ["Inactive cloud resource", "Publicly exposed cloud resource"]
    assert result["costs"]["monthly_cost"] == 1120.0 and result["costs"]["potential_monthly_savings"] == 192.0
    assert result["costs"]["opportunity_count"] == 4
    assert result["recommendation_summary"] == {"total": 5, "critical": 0, "high": 2, "medium": 3, "low": 0, "security": 2, "cost": 3}


def test_security_engine_rules_still_behave():
    exposed = check_resource({"resource_id": "x", "name": "n", "resource_type": "EC2", "status": "Running", "security_state": "Public"})
    assert [f["title"] for f in exposed] == ["Publicly exposed cloud resource"]
    sg = check_resource({"resource_id": "sg", "name": "sg", "resource_type": "SECURITY_GROUP", "status": "Active", "security_state": "ANYWHERE"})
    assert {f["severity"] for f in sg} == {"CRITICAL"}
    assert check_resource({"resource_id": "u", "name": "u", "resource_type": "IAM_USER", "status": "Active", "security_state": "NO_MFA"})[0]["title"] == "IAM user without MFA"
    assert check_resource({"resource_id": "ok", "name": "ok", "resource_type": "EC2", "status": "Running", "security_state": "Healthy"}) == []
    assert calculate_security_score([], []) == 100
    findings = [{"severity": "CRITICAL"}] * 5
    assert calculate_security_score([{}], findings) == 0
    assert build_scan_summary([{}] * 10, [{"severity": "HIGH"}])["security_score"] == 96
    assert run_security_scan([]) == []


def test_cost_engine_rules_still_behave():
    out = analyze_costs([{"resource_id": "i", "name": "dev-box", "resource_type": "EC2", "status": "Stopped"}],
                        [{"service": "EC2", "amount": 700.0}])
    titles = {o["title"] for o in out["opportunities"]}
    assert titles == {"Review inactive resource", "Review development resource", "Optimize EC2 spending"}
    assert out["monthly_cost"] == 700.0 and out["potential_monthly_savings"] == 60.0 + 35.0 + 70.0
    assert calculate_savings_percentage(0, 10) == 0.0 and calculate_savings_percentage(100, 250) == 100.0


def test_recommendation_engine_sorts_deduplicates_and_summarises():
    findings = [{"title": "A", "severity": "HIGH"}, {"title": "A", "severity": "HIGH"}, {"title": "B", "severity": "CRITICAL"}]
    recs = generate_recommendations(findings, [{"title": "C", "priority": "LOW"}])
    assert [r["title"] for r in recs] == ["B", "A", "C"]
    assert build_recommendation_summary(recs)["total"] == 3
    assert normalize_resource({})["resource_type"] == "UNKNOWN"


# --------------------------------------------------------------------- legacy routes
@pytest.mark.parametrize("path,keys", [
    ("/api/provider", {"provider", "mode"}),
    ("/api/inventory", {"total_resources", "resources_by_type", "resources"}),
    ("/api/security", {"security", "findings"}),
    ("/api/costs", {"monthly_cost", "service_costs", "opportunities", "potential_monthly_savings"}),
    ("/api/recommendations", {"recommendations", "summary"}),
    ("/api/dashboard", {"provider", "total_resources", "security_score", "total_findings", "critical_findings", "monthly_cost",
                        "potential_monthly_savings", "recommendations_count", "resources_by_type", "service_costs"}),
])
def test_original_api_routes_keep_their_contract(client, path, keys):
    r = client.get(path)
    assert r.status_code == 200
    assert keys <= set(r.json())


def test_dashboard_values_match_scan_baseline(client):
    d = client.get("/api/dashboard").json()
    assert d["total_resources"] == 15 and d["security_score"] == 96 and d["monthly_cost"] == 1120.0
    assert d["resources_by_type"] == {"EC2": 3, "S3": 3, "IAM": 3, "SECURITY_GROUP": 3, "EBS": 3}


# ----------------------------------------------------------------------- persistence
def test_legacy_scan_persists_snapshot_and_history(client, db):
    assert client.get("/api/scan").status_code == 200
    assert client.get("/api/scan").status_code == 200
    assert db.query(CloudResource).count() == 15
    assert db.query(SecurityFinding).count() == 2
    assert db.query(CostRecord).count() == 5 and db.query(CostOpportunity).count() == 4 and db.query(Recommendation).count() == 5
    assert db.query(Scan).count() == 2  # scan history accumulates while the snapshot tables are replaced


def test_legacy_scan_does_not_touch_simulator_history(sim):
    c, h = sim
    from app.database import SessionLocal
    from app.sim_models import SimFinding, SimScan
    with SessionLocal() as db:
        before = (db.query(SimScan).count(), db.query(SimFinding).count())
    assert c.get("/api/scan").status_code == 200
    with SessionLocal() as db:
        assert (db.query(SimScan).count(), db.query(SimFinding).count()) == before


def test_save_scan_results_is_transactional(db, monkeypatch):
    result = run_complete_scan()
    save_scan_results(db, result)
    assert db.query(Scan).count() == 1
    result["resources"].append({"resource_id": "boom"})  # missing keys -> KeyError before commit
    with pytest.raises(KeyError):
        save_scan_results(db, result)
    db.rollback()
    assert db.query(Scan).count() == 1 and db.query(CloudResource).count() == 15


def test_legacy_openapi_paths_still_exist(client):
    paths = client.get("/openapi.json").json()["paths"]
    for p in ("/api/auth/register", "/api/auth/login", "/api/provider", "/api/inventory", "/api/security", "/api/costs",
              "/api/recommendations", "/api/scan", "/api/dashboard"):
        assert p in paths


def test_schema_upgrade_adds_role_column_to_existing_users_table(tmp_path, monkeypatch):
    """A database created before RBAC (no users.role) is upgraded in place on startup."""
    from sqlalchemy import create_engine, inspect, text
    import app.main as main

    legacy = create_engine(f"sqlite:///{(tmp_path / 'old.db').as_posix()}")
    with legacy.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(255) NOT NULL, "
                          "password_hash VARCHAR(255) NOT NULL, created_at DATETIME NOT NULL)"))
        conn.execute(text("INSERT INTO users (email, password_hash, created_at) VALUES ('a@example.com', 'x', '2026-01-01')"))
    monkeypatch.setattr(main, "engine", legacy)
    main.ensure_schema()
    assert "role" in {c["name"] for c in inspect(legacy).get_columns("users")}
    with legacy.connect() as conn:
        assert conn.execute(text("SELECT role FROM users")).scalar() == "viewer"
