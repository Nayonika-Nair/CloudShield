"""Drive the real CloudShield UI end to end (Playwright + Chrome) and capture genuine screenshots.

The walkthrough follows the demo script: sign in -> configure and generate -> inspect -> trigger a scenario ->
scan -> explain a finding -> preview, apply and verify a remediation -> cost anomaly and recommendation ->
what-if (baseline unchanged) -> audit, drift -> report. Every assertion below must hold or the run fails,
so the screenshots are only produced from a working application.

Usage:
    python scripts/ui_walkthrough.py --base http://127.0.0.1:8010 --out docs/screenshots \
        --admin admin@cloudshield.example.com:Demo-Admin-2026 --viewer viewer@cloudshield.example.com:Demo-Viewer-2026
"""

import argparse
import json
import re
import sys
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]


class Recorder:
    def __init__(self, out: Path, page: Page):
        self.out, self.page, self.items = out, page, []

    def shot(self, category: str, name: str, title: str, purpose: str, *, full=False, locator=None, keep_toast=False):
        folder = self.out / category
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{name}.png"
        page = self.page
        if not keep_toast:
            page.evaluate("document.querySelectorAll('.toast').forEach((t) => t.remove())")
        page.wait_for_timeout(450)
        if locator is not None:
            page.set_viewport_size({"width": 1440, "height": 1700})   # let tall dialogs and drawers show in full
            page.wait_for_timeout(350)
            locator.screenshot(path=str(path))
            page.set_viewport_size({"width": 1440, "height": 900})
        elif full:
            height = page.evaluate("Math.max(document.querySelector('.main').scrollHeight, 900)")
            page.set_viewport_size({"width": 1440, "height": min(int(height) + 4, 3400)})
            page.wait_for_timeout(450)
            page.screenshot(path=str(path))
            page.set_viewport_size({"width": 1440, "height": 900})
        else:
            page.screenshot(path=str(path))
        page.wait_for_timeout(200)
        self.items.append({"file": path.relative_to(ROOT).as_posix(), "category": category, "title": title, "purpose": purpose})
        print("  captured", path.relative_to(ROOT).as_posix())


def goto(page: Page, view: str):
    page.evaluate(f"location.hash = '#/{view}'")
    page.wait_for_selector(f"#sec-{view}:not(.hidden)")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(500)


def toast_text(page: Page) -> str:
    page.wait_for_selector(".toast", timeout=15000)
    return page.locator(".toast").last.inner_text()


def login(page: Page, base: str, email: str, password: str):
    page.goto(base + "/")
    page.fill("#login-email", email)
    page.fill("#login-password", password)
    page.click("#login-submit")
    page.wait_for_selector("#view-app:not(.hidden)", timeout=20000)
    page.wait_for_load_state("networkidle")


def run(base: str, out: Path, admin: tuple[str, str], viewer: tuple[str, str]):
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        ctx = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
        page = ctx.new_page()
        page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
        page.on("console", lambda m: problems.append(f"console.error: {m.text}") if m.type == "error" and "401" not in m.text else None)
        rec = Recorder(out, page)

        # ------------------------------------------------------------------ authentication
        print("1. authentication")
        page.goto(base + "/")
        rec.shot("application", "01-login", "Sign-in screen", "Login view; credentials are validated by the API, not hard-coded in the page.")
        page.fill("#login-email", admin[0])
        page.fill("#login-password", "definitely-wrong-password")
        page.click("#login-submit")
        expect(page.locator("#login-error")).to_contain_text("Incorrect email or password")
        rec.shot("application", "02-login-rejected", "Rejected sign-in", "A wrong password is refused with a generic message (HTTP 401).")
        page.fill("#login-password", admin[1])
        page.click("#login-submit")
        page.wait_for_selector("#view-app:not(.hidden)")
        page.wait_for_load_state("networkidle")
        expect(page.locator("#user-role")).to_have_text("admin")
        rec.shot("application", "03-dashboard", "Dashboard (default environment)", "KPIs, security posture, cost trend, cost by service and compliance derived from the persisted simulated environment.")

        # ------------------------------------------------------------------ simulator configuration
        print("2. simulator configuration and generation")
        goto(page, "simulator")
        rec.shot("simulator", "01-configuration", "Simulator configuration", "Seed, region, resource counts, utilization, misconfiguration rates, quotas, time, pricing and scenario probabilities.")
        page.select_option("#preset-select", "clean")
        page.wait_for_timeout(900)
        page.fill("#cfg-counts_ec2_instances", "16")
        page.fill("#cfg-seed", "2026")
        page.fill("#cfg-name", "demo-clean-2026")
        page.locator("#config-form fieldset").nth(3).scroll_into_view_if_needed()
        rec.shot("simulator", "02-configuration-security-rates", "Misconfiguration rates and scenario probabilities", "Clean preset: misconfiguration rates are zero, so no flaw exists until a scenario creates it.")
        page.locator("#generate-btn").scroll_into_view_if_needed()
        page.click("#generate-btn")
        page.wait_for_selector(".modal")
        rec.shot("simulator", "03-generate-confirm", "Generate confirmation", "Generation archives (does not delete) the previous environment and its history.")
        page.get_by_role("button", name="Generate", exact=True).click()
        page.wait_for_function("document.querySelector('.toast') && /generated/.test(document.querySelector('.toast').innerText)", timeout=30000)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(800)
        page.evaluate("window.scrollTo(0,0); document.querySelector('.main').scrollTo(0,0)")
        rec.shot("simulator", "04-environment-generated", "Environment generated", "Active environment panel shows the seed, simulated clock, fingerprint and resulting resource counts (16 EC2 instances).")
        expect(page.locator("text=16 ec2 instance")).to_be_visible()
        page.click("[data-action=sim-tab][data-tab=environments]")
        page.wait_for_timeout(700)
        expect(page.locator("tbody tr")).to_have_count(2)
        rec.shot("simulator", "05-environments-history", "Environment history", "The earlier environment is ARCHIVED, not erased; scans and audit history remain.")

        # ------------------------------------------------------------------ inventory, topology, IAM
        print("3. inventory, topology, IAM")
        goto(page, "inventory")
        rec.shot("simulator", "06-inventory", "Resource inventory", "Paginated inventory of every simulated resource with state, key attributes, environment and monthly cost.")
        page.click("button[data-action=inv-type][data-type=ec2_instance]")
        page.wait_for_timeout(700)
        page.locator("tr[data-action=inv-open]").first.click()
        page.wait_for_selector(".drawer")
        page.wait_for_timeout(900)
        rec.shot("simulator", "07-resource-detail", "Resource detail drawer", "Per-resource properties, tags, metrics, relationships, network reachability explanation and the validated operations available.")
        page.keyboard.press("Escape")
        goto(page, "topology")
        rec.shot("simulator", "08-network-topology-clean", "Network topology (no exposure)", "VPCs, public/private subnets, internet gateways, instances, databases and security groups. Nothing is exposed on a sensitive port.", full=True)
        goto(page, "iam")
        rec.shot("simulator", "09-iam-analysis", "IAM identity analysis", "Principals, admin detection, MFA and access-key status, trust relationships and the escalation graph.", full=True)

        # ------------------------------------------------------------------ baseline scan (clean)
        print("4. baseline scan")
        goto(page, "security")
        rec.shot("security", "01-findings-clean", "Findings on the clean environment", "Before any scenario: no critical or high findings are detected.")

        # ------------------------------------------------------------------ scenario -> scan -> evidence
        print("5. scenario, scan and evidence")
        goto(page, "simulator")
        page.click("[data-action=sim-tab][data-tab=time]")
        page.wait_for_selector("[data-action=scenario-trigger]")
        rec.shot("simulator", "10-time-and-scenarios", "Simulated time and scenarios", "Manual clock controls and the ten scenarios; each changes state and names the rules expected to detect it.", full=True)
        page.click("[data-action=scenario-trigger][data-name=open_ssh]")
        text = toast_text(page)
        assert "Open Ssh triggered" in text or "triggered" in text, text
        page.wait_for_timeout(1200)
        expect(page.locator(".stale-chip")).to_be_visible()
        rec.shot("simulator", "11-scenario-triggered", "Scenario applied", "State changed (a world-open SSH rule was added); the 'state changed since last scan' chip appears because no finding exists until a scan runs.", keep_toast=True)
        goto(page, "inventory")
        page.click("button[data-action=inv-type][data-type='']")
        page.wait_for_timeout(700)
        page.fill("#inv-search", "launch-wizard")
        page.wait_for_timeout(1500)
        page.locator("tr[data-action=inv-open]").first.click()
        page.wait_for_selector(".drawer")
        page.wait_for_timeout(900)
        sg_drawer_before = page.locator(".drawer").inner_text()
        assert "0.0.0.0/0" in sg_drawer_before, "scenario-created security group must allow the internet"
        rec.shot("security", "02-sg-before-remediation", "Security group BEFORE remediation", "The scenario's security group allows tcp/22 from 0.0.0.0/0 (resource state, before the fix).")
        sg_name = page.locator(".drawer-body .mono").first.inner_text()
        page.keyboard.press("Escape")
        goto(page, "security")
        page.locator("button[data-action=run-scan]:visible").first.click()
        toast_text(page)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1200)
        row = page.locator("tr[data-action=sec-open]", has_text="SSH is reachable")
        expect(row).to_have_count(1)
        rec.shot("security", "03-findings-after-scan", "Findings after the scenario and a scan", "A new HIGH finding NET-001 appears, derived from the changed security group, public address and route.")
        row.click()
        page.wait_for_selector(".drawer")
        page.wait_for_timeout(900)
        rec.shot("security", "04-finding-evidence", "Finding with evidence", "Explanation, impact, step-by-step reachability proof, detection rule, severity reason and timeline.", locator=page.locator(".drawer"))
        topo_name = page.locator(".drawer-body a, .drawer-body .link-btn").first.inner_text()

        goto(page, "topology")
        rec.shot("simulator", "12-topology-exposed", "Network topology with an exposed instance", "The instance is outlined red with 'EXPOSED 22' because the network model finds SSH reachable from the internet.", full=True)

        # ------------------------------------------------------------------ remediation
        print("6. remediation: preview, apply, verify")
        goto(page, "security")
        page.locator("tr[data-action=sec-open]", has_text="SSH is reachable").click()
        page.wait_for_selector(".drawer")
        page.get_by_role("button", name="Preview and remediate").click()
        page.wait_for_selector(".modal .compare")
        page.wait_for_timeout(1500)
        rec.shot("security", "05-remediation-preview", "Remediation preview (PROPOSED)", "Plan, risk, and a what-if comparison computed on an isolated copy: score before/after, cost, availability, config diff. Nothing has changed yet.", locator=page.locator(".modal"))
        expect(page.locator("#rem-apply")).to_be_disabled()
        page.check("#rem-ack")
        expect(page.locator("#rem-apply")).to_be_enabled()
        page.click("#rem-apply")
        page.wait_for_selector(".modal .banner.ok", timeout=30000)
        page.wait_for_timeout(800)
        expect(page.locator(".modal")).to_contain_text("VERIFIED")
        rec.shot("security", "06-remediation-verified", "Remediation executed and verified", "The change was applied to the simulated state, the analysis re-ran, and the condition is no longer detected (VERIFIED).", locator=page.locator(".modal"))
        page.get_by_role("button", name="Close", exact=True).last.click()
        page.wait_for_timeout(900)
        page.keyboard.press("Escape")
        goto(page, "inventory")
        page.click("button[data-action=inv-type][data-type='']")
        page.wait_for_timeout(700)
        page.fill("#inv-search", "launch-wizard")
        page.wait_for_timeout(1500)
        page.locator("tr[data-action=inv-open]").first.click()
        page.wait_for_selector(".drawer")
        page.wait_for_timeout(900)
        sg_after = page.locator(".drawer").inner_text()
        inbound = sg_after.lower().split("inbound rules")[1].split("outbound rules")[0]
        assert "0.0.0.0/0" not in inbound, "world-open rule must be gone"
        rec.shot("security", "07-sg-after-remediation", "Security group AFTER remediation", "Same resource after remediation: the world-open SSH rule is gone (compare with the BEFORE screenshot).")
        page.keyboard.press("Escape")
        goto(page, "security")
        page.click("button[data-action=sec-filter][data-key=status][data-val=RESOLVED]")
        page.wait_for_timeout(900)
        expect(page.locator("tr[data-action=sec-open]", has_text="SSH is reachable")).to_have_count(1)
        rec.shot("security", "08-findings-resolved", "Resolved finding kept in history", "The finding is RESOLVED because a re-scan no longer detects it; the record and its history remain.")
        page.locator("tr[data-action=sec-open]", has_text="SSH is reachable").click()
        page.wait_for_selector(".drawer")
        page.wait_for_timeout(900)
        rec.shot("security", "09-finding-resolution-detail", "Resolved finding detail", "Timeline, resolving scan, remediation record and verification result.", locator=page.locator(".drawer"))
        page.keyboard.press("Escape")
        page.click("[data-action=sec-tab][data-tab=remediations]")
        page.wait_for_timeout(900)
        rec.shot("security", "10-remediation-history", "Remediation and verification history", "Proposed -> executed -> verified, with score and run-rate before/after.")
        page.click("[data-action=sec-tab][data-tab=scans]")
        page.wait_for_timeout(900)
        boxes = page.locator("input[data-change=scan-pick]")
        boxes.nth(0).check()
        page.wait_for_timeout(600)
        page.locator("input[data-change=scan-pick]").nth(boxes.count() - 1).check()
        page.wait_for_timeout(600)
        page.click("[data-action=scan-compare]")
        page.wait_for_timeout(900)
        rec.shot("security", "11-scan-comparison", "Scan history and comparison", "Compare two scans: resolved/introduced findings and score change.", full=True)
        page.click("[data-action=sec-tab][data-tab=rules]")
        page.wait_for_timeout(700)
        rec.shot("security", "12-detection-rules", "Detection rules catalogue", "Each rule's logic and severity basis is documented and visible.", full=True)

        # ------------------------------------------------------------------ IAM scenario
        print("7. IAM scenario")
        goto(page, "simulator")
        page.click("[data-action=sim-tab][data-tab=time]")
        page.click("[data-action=scenario-trigger][data-name=overly_permissive_iam]")
        toast_text(page)
        page.wait_for_timeout(900)
        goto(page, "iam")
        page.wait_for_timeout(600)
        rec.shot("security", "13-iam-escalation", "IAM privilege escalation after a permissive role", "AdministratorAccess on a workload role creates escalation paths from ordinary users; red edges show the chain.", full=True)

        # ------------------------------------------------------------------ cost spike -> anomaly
        print("8. cost anomaly and optimization")
        goto(page, "simulator")
        page.click("[data-action=sim-tab][data-tab=time]")
        page.fill("#adv-cost_spike", "3")
        page.click("[data-action=scenario-trigger][data-name=cost_spike]")
        toast_text(page)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(900)
        goto(page, "cost")
        page.wait_for_timeout(600)
        expect(page.locator("text=Active anomalies")).to_be_visible()
        rec.shot("cost", "01-cost-anomaly", "Cost analysis with a detected anomaly", "Daily cost chart with the spike flagged (z-score above baseline), by-service breakdown and contributors.", full=True)
        page.click("[data-action=cost-mode][data-mode=service]")
        page.wait_for_timeout(700)
        rec.shot("cost", "02-cost-by-service", "Daily cost by service", "Stacked daily cost per service from simulated billing.", locator=page.locator("#sec-cost .card.panel").nth(0))
        goto(page, "dashboard")
        page.locator("button[data-action=run-scan]:visible").first.click()
        toast_text(page)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)
        rec.shot("application", "04-dashboard-after-scenarios", "Dashboard after scenarios and a rescan", "Dashboard reflects the new findings, the cost anomaly and updated compliance posture.", full=True)
        goto(page, "optimization")
        page.wait_for_timeout(700)
        rec.shot("cost", "03-optimization", "Optimization recommendations", "Each recommendation shows evidence, estimated saving (labelled ESTIMATED), risk and the action to take.", full=True)
        page.locator("details.more summary").first.click()
        page.wait_for_timeout(500)
        rec.shot("cost", "04-recommendation-evidence", "Recommendation evidence and assumptions", "Supporting metrics, assumptions, risk and the executable plan.", locator=page.locator(".rec-card").first)
        page.locator("button[data-action=remediate][data-kind=recommendation]").first.click()
        page.wait_for_selector(".modal .compare")
        page.wait_for_timeout(1200)
        rec.shot("cost", "05-recommendation-whatif", "Recommendation what-if preview", "Cost and security effect simulated before applying.", locator=page.locator(".modal"))
        page.check("#rem-ack")
        page.click("#rem-apply")
        page.wait_for_selector(".modal .banner.ok", timeout=30000)
        page.wait_for_timeout(800)
        rec.shot("cost", "06-recommendation-verified", "Recommendation applied and verified", "Run-rate before/after shows the verified (simulated) saving.", locator=page.locator(".modal"))
        page.get_by_role("button", name="Close", exact=True).last.click()
        page.wait_for_timeout(900)
        page.click("button[data-action=opt-status][data-val=VERIFIED]")
        page.wait_for_timeout(900)
        rec.shot("cost", "07-recommendation-status-verified", "Verified recommendation", "Estimated and verified savings are shown separately.", full=True)

        # ------------------------------------------------------------------ what-if
        print("9. what-if")
        goto(page, "whatif")
        page.select_option("#wi-action", "ec2.stop")
        page.wait_for_timeout(500)
        page.fill("#wi-target", page.evaluate("document.querySelector('#wi-targets option').value"))
        page.click("form[data-form=wi-add] button[type=submit]")
        page.wait_for_timeout(700)
        page.click("[data-action=wi-run]")
        page.wait_for_selector("#wi-result .compare", timeout=30000)
        page.wait_for_timeout(1000)
        expect(page.locator("#wi-result")).to_contain_text("baseline is unchanged")
        rec.shot("simulator", "13-whatif-result", "What-if comparison", "Baseline vs hypothetical: cost, security score, availability, compliance and config diff; the baseline fingerprint is verified unchanged.", full=True)

        # ------------------------------------------------------------------ audit and drift
        print("10. audit and drift")
        goto(page, "audit")
        rec.shot("simulator", "14-audit-log", "Audit log", "Append-only record of generation, scenarios, scans, remediation, what-if and time changes with actor, outcome and details.", full=True)
        page.locator("tr[data-action=aud-open]", has_text="REMEDIATION_APPLIED").first.click()
        page.wait_for_selector(".drawer")
        page.wait_for_timeout(700)
        rec.shot("simulator", "15-audit-event-detail", "Audit event with before/after", "A remediation event stores the changed fields before and after.", locator=page.locator(".drawer"))
        page.keyboard.press("Escape")
        page.click("[data-action=aud-tab][data-tab=drift]")
        page.wait_for_timeout(900)
        rec.shot("simulator", "16-configuration-drift", "Configuration drift", "Resources whose configuration differs from the saved baseline; security-relevant drift first. Drift is not a finding.", full=True)

        # ------------------------------------------------------------------ reports
        print("11. reports")
        goto(page, "reports")
        page.click("button[data-action=rep-select][data-type=full]")
        page.wait_for_timeout(500)
        page.click("button[data-action=rep-generate]")
        page.wait_for_selector("text=Assumptions and limitations", timeout=30000)
        page.wait_for_timeout(1000)
        rec.shot("application", "05-report-generated", "Generated report", "Report built from persisted state: score, run-rate, estimated vs verified savings, remediation evidence, limitations.", full=True)
        with page.expect_download() as dl:
            page.locator("button[data-action=rep-download][data-format=pdf]").first.click()
        dest = out / "application" / "downloaded-report.pdf"
        dl.value.save_as(str(dest))
        assert dest.read_bytes()[:5] == b"%PDF-", "downloaded report must be a PDF"
        print("  downloaded", dest.relative_to(ROOT).as_posix(), dest.stat().st_size, "bytes")
        with page.expect_download() as dl2:
            page.locator("button[data-action=rep-download][data-format=csv]").first.click()
        csv_dest = out / "application" / "downloaded-report.csv"
        dl2.value.save_as(str(csv_dest))
        assert "SECURITY FINDINGS" in csv_dest.read_text(encoding="utf-8")

        # ------------------------------------------------------------------ API docs
        print("12. API documentation")
        docs = ctx.new_page()
        docs.goto(base + "/docs")
        docs.wait_for_selector(".swagger-ui", timeout=30000)
        docs.wait_for_timeout(1500)
        docs.screenshot(path=str(out / "application" / "06-api-docs.png"))
        rec.items.append({"file": (out / "application" / "06-api-docs.png").relative_to(ROOT).as_posix(), "category": "application",
                          "title": "OpenAPI documentation", "purpose": "FastAPI /docs listing the simulator, analysis, remediation, what-if, audit and report endpoints."})
        docs.close()

        # ------------------------------------------------------------------ read-only role
        print("13. viewer role is read-only")
        page.click("[data-action=logout]")
        page.wait_for_selector("#view-login:not(.hidden)")
        login(page, base, viewer[0], viewer[1])
        goto(page, "simulator")
        expect(page.locator("#generate-btn")).to_be_disabled()
        rec.shot("application", "07-viewer-readonly", "Read-only viewer role", "A viewer sees a notice and cannot generate environments or change state (also enforced by the API with HTTP 403).")
        browser.close()

    (out / ".register").mkdir(parents=True, exist_ok=True)
    (out / ".register" / "ui.json").write_text(json.dumps(rec.items, indent=2), encoding="utf-8")
    if problems:
        print("\nBROWSER PROBLEMS:")
        for pr in problems:
            print("  -", pr)
        return 1
    print(f"\nOK - {len(rec.items)} screenshots, no browser errors")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8010")
    ap.add_argument("--out", default="docs/screenshots")
    ap.add_argument("--admin", required=True, help="email:password")
    ap.add_argument("--viewer", required=True, help="email:password")
    a = ap.parse_args()
    sys.exit(run(a.base.rstrip("/"), ROOT / a.out, tuple(a.admin.split(":", 1)), tuple(a.viewer.split(":", 1))))
