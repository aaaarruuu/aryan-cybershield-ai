# Demo Walkthrough (about 10 minutes, demo mode)

Start the app ([INSTALLATION.md](INSTALLATION.md)). Banner "Demo mode" appears on the dashboard: intelligence is sample data and actions are simulated - say this out loud when presenting.

1. **Register** the first account (becomes admin). Show the identity on the login page: *ARYAN CYBERSHIELD AI - Developed by Aryan*.
2. **Dashboard** is empty: real zeros and an empty state, not fake numbers.
3. **Knowledge Base** -> *Load MITRE ATT&CK + playbooks*; search "contain brute force failed logins" and show the cited chunk. Search "banana smoothie" to show the honest "no relevant information" message.
4. **Log Analyzer** -> *Load sample log*. Point out: brute force from 203.0.113.45 followed by a success (critical), password spraying from 198.51.100.77, off-hours privileged activity by `carol`, and low-severity **ML signals** labelled unconfirmed. Toggle "Flagged only".
5. **Phishing Analysis** -> *Phishing sample*: indicators with evidence (look-alike `paypa1-support.com`, urgency, credential request, URL structure) and the ML contribution. Then *Legitimate sample*. Show the model evaluation table and its caveat banner.
6. **Threat Intelligence** -> `203.0.113.45` (demo malicious), then `198.51.100.200` (unknown - "not a clean verdict").
7. **AI Investigation Center**: title, indicator `203.0.113.45`, select the log batch, tick *Include a suspicious email* with the phishing sample, **Start**. Watch agents run; then show verified findings vs hypotheses, timeline, correlations, ATT&CK mapping (unverified), cited recommendations, agent activity chips (planner ... response), download the PDF.
8. **Incidents**: the auto-created incident (awaiting approval); add a note; try to resolve without notes (blocked).
9. **Response Approvals**: pending requests; approve a `block indicator` -> simulated result, verification, rollback button. Show an analyst cannot approve `reset password` (admin only).
10. **Admin Settings**: Audit log shows every step; Settings shows secrets only as yes/no.
11. **Dashboard** again: now populated from the database. Sign out; opening `/incidents` redirects to login.

Live mode: set `DEMO_MODE=false` and `VIRUSTOTAL_API_KEY`; without a key lookups show `unavailable`.
