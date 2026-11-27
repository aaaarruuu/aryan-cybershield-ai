"""Deterministically generate SYNTHETIC demo data (seeded). None of this is real telemetry.

Outputs into sample_data/:
  auth_logs.csv, auth_logs.json, auth_logs.txt  - same story in three supported formats
  phishing_samples.json                         - example emails for the Phishing page / tests
  threat_intel_demo.json                        - labelled DEMO threat-intel records (documentation IP ranges)
  datasets/phishing_synthetic.csv               - synthetic labelled corpus for the demo phishing classifier
"""
import csv
import json
import os
import random
from datetime import datetime, timedelta, timezone

random.seed(1337)
ROOT = os.path.join(os.path.dirname(__file__), "..", "sample_data")
os.makedirs(os.path.join(ROOT, "datasets"), exist_ok=True)

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
GOOD_IPS = [f"10.0.{i}.{j}" for i in (1, 2) for j in range(10, 18)]
BRUTE_IP = "203.0.113.45"          # TEST-NET-3 documentation range (not a real host)
SPRAY_IP = "198.51.100.77"         # TEST-NET-2 documentation range
ODD_IP = "192.0.2.99"              # TEST-NET-1 documentation range
START = datetime(2026, 11, 3, 8, 0, tzinfo=timezone.utc)


def build_events():
    ev = []
    t = START
    for _ in range(220):  # normal business-hours activity
        t += timedelta(minutes=random.randint(2, 6))
        if t.hour >= 18:
            t = t.replace(hour=8, minute=0) + timedelta(days=1)
        u = random.choice(USERS)
        ok = random.random() > 0.04
        ev.append((t, "login", u, random.choice(GOOD_IPS), "success" if ok else "failure"))
    bt = START + timedelta(days=1, hours=2, minutes=13)      # brute force against admin, then success
    for i in range(34):
        ev.append((bt + timedelta(seconds=7 * i), "login", "admin", BRUTE_IP, "failure"))
    ev.append((bt + timedelta(seconds=7 * 34 + 5), "login", "admin", BRUTE_IP, "success"))
    sp = START + timedelta(days=2, hours=1, minutes=5)       # password spraying
    for i, u in enumerate(USERS * 2):
        ev.append((sp + timedelta(seconds=20 * i), "login", u, SPRAY_IP, "failure"))
    ot = (START + timedelta(days=3)).replace(hour=3, minute=40)  # 03:40 UTC: unusual hour, new IP, sensitive access
    ev.append((ot, "login", "carol", ODD_IP, "success"))
    ev.append((ot + timedelta(minutes=3), "file_access", "carol", ODD_IP, "success"))
    ev.append((ot + timedelta(minutes=6), "privilege_change", "carol", ODD_IP, "success"))
    ev.sort(key=lambda e: e[0])
    return ev


def main():
    ev = build_events()
    with open(os.path.join(ROOT, "auth_logs.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "event_type", "username", "src_ip", "outcome"])
        for t, et, u, ip, o in ev:
            w.writerow([t.isoformat(), et, u, ip, o])
    with open(os.path.join(ROOT, "auth_logs.json"), "w") as f:
        json.dump([{"timestamp": t.isoformat(), "event_type": et, "username": u, "src_ip": ip, "outcome": o}
                   for t, et, u, ip, o in ev], f, indent=1)
    with open(os.path.join(ROOT, "auth_logs.txt"), "w") as f:  # sshd-style text log
        for t, et, u, ip, o in ev:
            if et == "login":
                verb = "Accepted password" if o == "success" else "Failed password"
                f.write(f"{t.strftime('%Y-%m-%d %H:%M:%S')} host sshd[1022]: {verb} for {u} from {ip} port 22\n")
            else:
                f.write(f"{t.strftime('%Y-%m-%d %H:%M:%S')} host app[88]: {et} user={u} src={ip} result={o}\n")

    phishing = [
        {"label": "phishing", "subject": "URGENT: Your account will be suspended", "sender": "security@paypa1-support.com",
         "body": "Dear customer, we detected unusual activity. Verify your password immediately or your account will be suspended within 24 hours.",
         "urls": ["http://paypa1-support.com.verify-login.xyz/login"]},
        {"label": "legitimate", "subject": "Team meeting notes - Tuesday", "sender": "bob@example.com",
         "body": "Hi all, attached are the notes from Tuesday's meeting. Let me know if I missed anything. Thanks, Bob",
         "urls": ["https://example.com/wiki/meeting-notes"]},
    ]
    json.dump(phishing, open(os.path.join(ROOT, "phishing_samples.json"), "w"), indent=1)

    intel = {  # DEMO records only; documentation-range IPs; clearly labelled in the app
        "ip:203.0.113.45": {"malicious": 14, "suspicious": 2, "harmless": 60, "note": "demo: simulated brute-force source"},
        "ip:198.51.100.77": {"malicious": 6, "suspicious": 4, "harmless": 70, "note": "demo: simulated password-spraying source"},
        "domain:paypa1-support.com": {"malicious": 11, "suspicious": 3, "harmless": 55, "note": "demo: simulated lookalike domain"},
        "domain:verify-login.xyz": {"malicious": 9, "suspicious": 5, "harmless": 58, "note": "demo: simulated phishing host"},
        "domain:example.com": {"malicious": 0, "suspicious": 0, "harmless": 80, "note": "demo: reserved example domain"},
    }
    json.dump(intel, open(os.path.join(ROOT, "threat_intel_demo.json"), "w"), indent=1)

    gen_phish_corpus()
    print("sample data generated")


PH_SUBJ = ["Urgent: verify your account", "Your password expires today", "Security alert: unusual sign-in",
           "Payment failed - action required", "You have won a prize, claim now", "Invoice overdue - final notice",
           "Confirm your identity to avoid suspension", "Your mailbox is full, upgrade now"]
PH_BODY = ["Click the link below to verify your password immediately or your account will be suspended.",
           "We noticed unusual activity. Confirm your bank details now to avoid permanent closure.",
           "Your payment could not be processed. Update your credit card information within 24 hours.",
           "Congratulations, you are selected. Provide your login credentials to claim the reward.",
           "Final notice: failure to respond will result in legal action. Download the attached invoice."]
OK_SUBJ = ["Weekly project update", "Lunch on Friday?", "Meeting notes", "Quarterly report draft", "Re: design review",
           "Schedule for next sprint", "Welcome to the team", "Question about the budget spreadsheet"]
OK_BODY = ["Hi, sharing the notes from our meeting. Let me know if you have questions.",
           "Could we move the review to Thursday afternoon? Thanks for your flexibility.",
           "Attached is the draft report for your feedback. No rush, whenever you have time.",
           "Looking forward to working with you. Please find the onboarding schedule below.",
           "Thanks for the update. I reviewed the spreadsheet and have a couple of suggestions."]


def gen_phish_corpus():
    rows = []
    for _ in range(300):
        rows.append((f"{random.choice(PH_SUBJ)} {random.choice(PH_BODY)} {random.choice(PH_BODY)}", "phishing"))
        rows.append((f"{random.choice(OK_SUBJ)} {random.choice(OK_BODY)} {random.choice(OK_BODY)}", "legitimate"))
    random.shuffle(rows)
    with open(os.path.join(ROOT, "datasets", "phishing_synthetic.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)


if __name__ == "__main__":
    main()
