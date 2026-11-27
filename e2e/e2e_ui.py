"""Browser end-to-end test (Playwright, Chromium). Needs a FRESH database: use scripts/run_e2e.sh, which starts everything."""
import sys, re, json
from playwright.sync_api import sync_playwright, expect
import os
SH = os.environ.get("E2E_SHOTS", "/tmp/cybershield_e2e_shots"); os.makedirs(SH, exist_ok=True)
B = os.environ.get("E2E_BASE_URL", "http://127.0.0.1:5173")
errors = []
with sync_playwright() as p:
    br = p.chromium.launch()
    pg = br.new_page(viewport={"width": 1440, "height": 900})
    pg.on("console", lambda m: errors.append(("console", m.text)) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errors.append(("pageerror", str(e))))
    pg.goto(B); expect(pg.get_by_role("form", name="Sign in")).to_be_visible()
    pg.screenshot(path=f"{SH}/01_login.png")
    # register (first user => admin)
    pg.get_by_role("button", name="Create one").click()
    pg.get_by_label("Full name").fill("Aryan Admin"); pg.get_by_label("Email").fill("aryan@example.com"); pg.get_by_label("Password").fill("StrongPass123")
    pg.get_by_role("button", name="Create account").click()
    expect(pg.get_by_role("heading", name="Security Operations Dashboard")).to_be_visible()
    expect(pg.get_by_text("No security data yet")).to_be_visible()   # empty state, real zeros
    pg.screenshot(path=f"{SH}/02_dashboard_empty.png")
    # load builtin knowledge (admin)
    pg.get_by_role("link", name="Knowledge Base").click()
    pg.get_by_role("button", name="Load MITRE ATT&CK + playbooks").click()
    expect(pg.get_by_text("mitre_attack_techniques.md").first).to_be_visible(timeout=60000)
    pg.get_by_label("Search query").fill("contain brute force failed logins block source IP"); pg.get_by_role("button", name="Search").click()
    expect(pg.get_by_text(re.compile(r"incident_response_playbooks.md \(chunk"))).to_be_visible(timeout=20000)
    pg.screenshot(path=f"{SH}/03_knowledge.png")
    # log analyzer: sample
    pg.get_by_role("link", name="Log Analyzer").click()
    pg.get_by_role("button", name="Load sample log").click()
    expect(pg.get_by_text("Brute-force activity from 203.0.113.45")).to_be_visible(timeout=30000)
    pg.screenshot(path=f"{SH}/04_logs.png")
    # phishing
    pg.get_by_role("link", name="Phishing Analysis").click()
    pg.get_by_role("button", name="Phishing sample").click(); pg.get_by_role("button", name="Analyse email").click()
    expect(pg.get_by_text("Detected indicators")).to_be_visible(timeout=20000)
    pg.screenshot(path=f"{SH}/05_phishing.png")
    # threat intel
    pg.get_by_role("link", name="Threat Intelligence").click()
    pg.get_by_label("Indicator").fill("203.0.113.45"); pg.get_by_role("button", name="Lookup").click()
    expect(pg.get_by_text(re.compile("demo dataset"))).to_be_visible(timeout=15000)
    pg.screenshot(path=f"{SH}/06_intel.png")
    # AI investigation
    pg.get_by_role("link", name="AI Investigation Center").click()
    pg.get_by_label("Title", exact=True).fill("Brute force + phishing")
    pg.get_by_label("Indicators (IPs, domains, URLs, hashes)").fill("203.0.113.45")
    pg.get_by_label("Log batch").select_option(index=1)
    pg.get_by_label("Include a suspicious email").check()
    pg.get_by_label("Sender", exact=True).fill("security@paypa1-support.com"); pg.get_by_label("Subject", exact=True).fill("URGENT: Your account will be suspended")
    pg.get_by_label("Body", exact=True).fill("Dear customer, verify your password immediately or your account will be suspended within 24 hours.")
    pg.get_by_label("URLs", exact=True).fill("http://paypa1-support.com.verify-login.xyz/login")
    pg.get_by_role("button", name="Start investigation").click()
    expect(pg.get_by_text("Verified findings (observed)")).to_be_visible(timeout=90000)
    expect(pg.get_by_text("AI-generated hypotheses (unconfirmed)")).to_be_visible()
    pg.screenshot(path=f"{SH}/07_investigation.png", full_page=True)
    # PDF download via UI
    with pg.expect_download() as d: pg.get_by_role("button", name="Download PDF").click()
    path = d.value.path(); assert open(path, "rb").read(4) == b"%PDF", "PDF export invalid"
    # incidents
    pg.get_by_role("link", name="Incidents").click()
    pg.get_by_role("button", name=re.compile("Brute force")).first.click()
    expect(pg.get_by_text("Investigation history")).to_be_visible()
    pg.get_by_label("Add note").fill("Confirmed with network team"); pg.get_by_role("button", name="Add", exact=True).click()
    expect(pg.get_by_text("Confirmed with network team")).to_be_visible()
    pg.screenshot(path=f"{SH}/08_incident.png", full_page=True)
    # approvals
    pg.get_by_role("link", name="Response Approvals").click()
    expect(pg.get_by_text("Simulation mode")).to_be_visible()
    card = pg.locator("div.card", has_text="block indicator").first
    card.get_by_role("button", name="Approve (simulated)").click()
    expect(pg.get_by_text(re.compile(r"\[SIMULATION\] Added .* to the simulated blocklist")).first).to_be_visible(timeout=15000)
    pg.screenshot(path=f"{SH}/09_approvals.png", full_page=True)
    # dashboard now populated
    pg.get_by_role("link", name="Dashboard").click()
    expect(pg.get_by_text("No security data yet")).to_have_count(0)
    pg.wait_for_timeout(1200); pg.screenshot(path=f"{SH}/10_dashboard.png", full_page=True)
    # remaining pages render
    for name, h in [("Analytics & Reports", "Analytics & Reports"), ("My Profile", "My Profile"), ("Admin Settings", "Admin Settings"), ("About Project", "About Project")]:
        pg.get_by_role("link", name=name).click(); expect(pg.get_by_role("heading", name=h, exact=True)).to_be_visible()
    pg.get_by_role("link", name="Admin Settings").click(); pg.get_by_role("tab", name="Audit log").click()
    expect(pg.get_by_text("investigation.completed").first).to_be_visible(); pg.screenshot(path=f"{SH}/11_audit.png")
    # logout then protected route
    pg.get_by_role("button", name="Sign out").click(); expect(pg.get_by_role("form", name="Sign in")).to_be_visible()
    pg.goto(B + "/incidents"); expect(pg.get_by_role("form", name="Sign in")).to_be_visible()
    # mobile layout
    m = br.new_page(viewport={"width": 390, "height": 800}); m.goto(B)
    m.get_by_label("Email").fill("aryan@example.com"); m.get_by_label("Password").fill("StrongPass123"); m.get_by_role("button", name="Sign in").click()
    expect(m.get_by_label("Toggle menu")).to_be_visible(); m.wait_for_timeout(800)
    assert m.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "horizontal overflow on mobile"
    m.screenshot(path=f"{SH}/12_mobile.png")
    br.close()
print("E2E UI FLOW PASSED"); print("browser errors:", errors)
