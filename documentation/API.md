# REST API Reference

Base path `/api`. Interactive docs at `/docs` when `APP_ENV` is not `production`. Authentication: `Authorization: Bearer <token>` from `/auth/login` or `/auth/register`. Errors are JSON `{"detail": ...}` (422 validation, 401 unauthenticated, 403 forbidden, 404, 409 conflict, 413 too large, 429 rate-limited). Roles: **A** = admin only, **N** = analyst or admin, **-** = public.

| Method & path | Role | Purpose |
|---|---|---|
| GET `/health` | - | status, author, demo flag |
| GET `/about` | - | project identity |
| POST `/auth/register` | - | create account (first = admin); rate-limited |
| POST `/auth/login` | - | returns token + user; rate-limited |
| POST `/auth/logout` | N | revoke all tokens of this user |
| GET / PATCH `/auth/me` | N | profile; changing password revokes tokens |
| GET `/auth/users` | A | list users |
| PATCH `/auth/users/{id}` | A | set role / active (cannot demote self) |
| GET `/dashboard/stats?days=` | N | all dashboard figures from the DB |
| POST `/phishing/analyse` | N | `{subject, sender, body, urls[], metadata}` -> classification, confidence, risk, indicators, explanation, next steps |
| GET `/phishing/model-report` | N | stored ML evaluation |
| POST `/intel/lookup?refresh=` | N | `{value}` -> verdict, source, demo flag, timestamp, cached |
| GET `/intel/indicators?verdict=` | N | lookup history |
| POST `/logs/upload` | N | multipart `file` (.csv/.json/.txt/.log) -> batch id, summary, alerts |
| POST `/logs/load-sample` | N | ingest bundled synthetic log |
| GET `/logs/batches` | N | batches |
| GET `/logs/batches/{id}/analysis` | N | re-run detection on a stored batch |
| GET `/logs/events?batch_id=&suspicious=` | N | normalised events |
| POST `/investigations` | N | `{title, phishing?, indicators[], log_batch_id?, create_incident}` -> 202, runs in background |
| GET `/investigations`, `/investigations/{id}` | N | list; detail with full report and agent runs (poll until `completed`/`failed`) |
| POST `/knowledge/documents` | N | multipart upload (.pdf .txt .md .csv .json) |
| POST `/knowledge/load-builtin` | A | load bundled ATT&CK summary + playbooks |
| GET `/knowledge/documents` | N | list |
| DELETE `/knowledge/documents/{id}` | A | delete (also removes vectors) |
| GET `/knowledge/search?q=&k=` | N | `{results[{text, citation, similarity, injection_suspected}], has_relevant, message}` |
| GET / POST `/incidents` | N | list (filters `status`, `severity`, `q`) / create |
| GET / PATCH `/incidents/{id}` | N | detail with history / update (status transitions enforced; notes required to resolve/close) |
| POST `/incidents/{id}/history` | N | add investigation note |
| GET / POST `/approvals` | N | list (`status`, `incident_id`) / request an action |
| POST `/approvals/{id}/approve` , `/reject` | N* | decide (*role matrix: reset_password, revoke_sessions, isolate_endpoint need admin) |
| POST `/approvals/{id}/rollback` | N* | roll back a simulated block/isolate |
| GET `/reports/investigations/{id}?format=pdf|csv` | N | export report |
| GET `/reports/incidents.csv` | N | export incidents |
| GET `/audit?action=` | A | audit trail |
| GET `/admin/settings` | A | non-secret configuration (booleans for secrets) |

## Response shapes (abridged)
**Phishing:** `{classification: phishing|suspicious|legitimate, confidence, risk_level, risk_score, deterministic_score, ml{phishing_probability, points_contributed}, indicators[{id, category, points, summary, evidence, verified}], explanation, recommended_next_steps[], limitations}`

**Intel:** `{indicator, type, verdict: malicious|suspicious|clean|unknown|unavailable, score, source, demo, details, looked_up_at, cached, is_ioc}`

**Investigation report:** `{incident_summary, risk_level, risk_score, risk_explanation, verified_findings[], ai_hypotheses[], evidence{}, related_events_timeline[], correlations[], possible_attack_techniques[], recommended_actions[], knowledge_note, knowledge_citations[], approval_requests[], agent_execution[], tool_calls[], conclusion}`

**Allowed approval `action_type`:** `block_indicator, reset_password, revoke_sessions, isolate_endpoint, investigate_access, escalate_incident`. Incident statuses: `open, under_investigation, awaiting_approval, resolved, closed`. Severities: `low, medium, high, critical`.
