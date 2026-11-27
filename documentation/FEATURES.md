# Feature Documentation

| # | Page | What you can do | Backend |
|---|---|---|---|
| 1 | Login / Register | validated forms, first user = admin, session expiry (30 min), server-side logout | `/auth/*` |
| 2 | Dashboard | 8 KPI tiles, trend line, severity pie, status bars, recent incidents and activity, range filter, demo banner, empty state | `/dashboard/stats`, `/incidents` |
| 3 | Threat Intelligence | look up IP/domain/URL/hash, refresh bypassing cache, history; shows source, timestamp, engine counts, IOC flag, demo/unavailable notices | `/intel/*` |
| 4 | Phishing Analysis | analyse an email; indicators with evidence; ML contribution; model evaluation table | `/phishing/*` |
| 5 | Log Analyzer | upload CSV/JSON/TXT/LOG or load sample; alerts; flagged events; reopen batches; jump to investigation | `/logs/*` |
| 6 | AI Investigation Center | combine email + indicators + log batch; live progress; report with verified vs hypothesis, timeline, correlations, ATT&CK mapping, actions, agent activity; PDF/CSV | `/investigations`, `/reports/*` |
| 7 | Incidents | create, search/filter, assign, change severity/status (transitions enforced), notes, history, CSV export | `/incidents*` |
| 8 | Knowledge Base | upload documents, list/delete (admin), load built-ins (admin), cited search, injection flags | `/knowledge/*` |
| 9 | Response Approvals | request actions, approve/reject with note, role limits, simulated execution result, verification, rollback | `/approvals*` |
| 10 | Analytics & Reports | severity chart, detection summary, per-investigation PDF/CSV, incidents CSV | `/reports/*`, `/dashboard/stats` |
| 11 | My Profile | change name/password (password change signs out everywhere) | `/auth/me` |
| 12 | Admin Settings | read-only config (no secrets), user roles/activation, audit log | `/admin/settings`, `/auth/users`, `/audit` |
| 13 | About Project | identity, capabilities, honest limitations | `/about` |

## Detection rules (log analysis)
Brute force: >=10 failures from one IP within 10 minutes (critical if a success follows within 30 minutes). Password spraying: >=5 distinct usernames failing from one IP. Off-hours success: 22:00-06:00 UTC. New network: success from a /16 not seen for a user with enough baseline. Sensitive activity (`privilege_change`, `file_access`, `admin_action`) off-hours. Isolation Forest over per-IP 10-minute windows (events, failures, users, off-hours share, failure ratio), 200 trees, seed 42, contamination 5%.

## Phishing indicators
Sender: look-alike/leetspeak brand domains, risky TLD, free-mail with brand display name, Reply-To mismatch, SPF/DKIM/DMARC failures (if supplied in metadata). Language: urgency, credential request, threats, reward lure, generic greeting. URLs: raw IP, no TLS, `@` userinfo, punycode, shorteners, risky TLD, deep subdomains, brand look-alike or brand-in-subdomain, sender/link mismatch. Classification needs >= 2 significant deterministic indicators; ML adds <= 25 points.
