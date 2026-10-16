"""End-to-end workflow over the real HTTP stack (FastAPI app + database), mirroring the demo script.

Configure -> Provision -> Observe -> Analyze -> Detect -> Simulate -> Remediate -> Verify -> Compare -> Report
"""

from tests.helpers import first


def test_complete_cloudshield_workflow(client):
    # 1-2. start the application and authenticate
    assert client.get("/health").json()["status"] == "ok"
    login = client.post("/api/auth/login", json={"email": "admin@example.com", "password": "Admin-pass-1"})
    assert login.status_code == 200
    h = {"Authorization": f"Bearer {login.json()['access_token']}"}

    # 3-4. configure and generate a deterministic environment
    cfg = {"preset": "typical", "config": {"seed": 2026, "counts": {"ec2_instances": 12, "s3_buckets": 5}}}
    gen = client.post("/api/sim/environments", headers=h, json=cfg)
    assert gen.status_code == 201
    env = gen.json()["environment"]
    assert env["counts"]["ec2_instance"] == 12 and env["counts"]["s3_bucket"] == 5

    # 5. view resources
    resources = client.get("/api/sim/resources?page_size=200", headers=h).json()
    assert resources["total"] == sum(env["counts"].values())

    # 6-7. security analysis, cost and recommendations
    dash = client.get("/api/sim/dashboard", headers=h).json()
    score_before = dash["security"]["score"]
    assert dash["security"]["open_findings"] > 0 and dash["cost"]["monthly_run_rate"] > 0
    recs = client.get("/api/sim/recommendations?status=OPEN", headers=h).json()
    assert recs["totals"]["estimated_monthly_savings"] > 0

    # 8-10. trigger a scenario, confirm state changed, scan and inspect findings
    client.post("/api/sim/environments", headers=h, json={"preset": "clean", "config": {"seed": 5}})  # quiet baseline
    scenario = client.post("/api/sim/scenarios/public_s3_bucket/trigger", headers=h, json={}).json()
    bucket = scenario["targets"][0]
    live = client.get(f"/api/sim/resources/{bucket}", headers=h).json()["resource"]
    assert live["acl"] == "public-read" and live["block_public_access"] is False
    scan = client.post("/api/sim/scans", headers=h).json()["scan"]
    assert scan["new_findings"] == 1
    finding = first(client.get("/api/sim/findings?status=OPEN", headers=h).json()["items"], rule_id="S3-001")
    assert finding["resource_id"] == bucket and finding["evidence"]["acl"] == "public-read"
    score_with_issue = scan["security_score"]

    # 11-12. apply remediation with confirmation, verify state and re-run analysis
    preview = client.post("/api/sim/remediation/preview", headers=h, json={"kind": "finding", "id": finding["id"]}).json()
    applied = client.post("/api/sim/remediation/apply", headers=h, json={
        "kind": "finding", "id": finding["id"], "plan_hash": preview["plan"]["plan_hash"], "confirm": True}).json()
    assert applied["verification"] == "VERIFIED"
    after = client.get(f"/api/sim/resources/{bucket}", headers=h).json()["resource"]
    assert after["acl"] == "private" and after["block_public_access"] is True
    assert applied["verification_scan"]["security_score"] > score_with_issue
    assert client.post("/api/sim/scans", headers=h).json()["scan"]["resolved_findings"] == 0   # nothing left to resolve
    assert client.get(f"/api/sim/findings/{finding['id']}", headers=h).json()["finding"]["status"] == "RESOLVED"

    # 13-14. what-if on the baseline, which must not change it
    inst = first(client.get("/api/sim/resources?type=ec2_instance&state=running", headers=h).json()["items"], state="running")
    env_before = client.get("/api/sim/environment", headers=h).json()
    what = client.post("/api/sim/whatif", headers=h, json={"changes": [{"action": "ec2.stop", "target_id": inst["id"]}]}).json()
    assert what["result"]["baseline_unchanged"] is True
    env_after = client.get("/api/sim/environment", headers=h).json()
    assert (env_after["fingerprint"], env_after["state_version"]) == (env_before["fingerprint"], env_before["state_version"])

    # 15. audit history shows each step in order
    actions = [e["action"] for e in reversed(client.get("/api/sim/audit?page_size=200", headers=h).json()["items"])]
    order = ["ENVIRONMENT_GENERATED", "SCENARIO_TRIGGERED", "SCAN_COMPLETED", "REMEDIATION_PREVIEWED", "REMEDIATION_APPLIED",
             "REMEDIATION_VERIFIED", "WHATIF_EXECUTED"]
    positions = [actions.index(a, actions.index("SCENARIO_TRIGGERED") if a != "ENVIRONMENT_GENERATED" else 0) for a in order]
    assert positions == sorted(positions)

    # 16. generate a report from the real state
    rid = client.post("/api/sim/reports", headers=h, json={"report_type": "verification"}).json()["id"]
    pdf = client.get(f"/api/sim/reports/{rid}/download?format=pdf", headers=h)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    content = client.get(f"/api/sim/reports/{rid}", headers=h).json()["content"]
    assert content["remediation"][0]["verification"] == "VERIFIED" and content["security"]["resolved_findings"][0]["resolution"] == "REMEDIATED"
    assert score_before is not None
