# Testing

Only results that were actually executed are reported.

## Automated suites
| Suite | Count | Covers |
|---|---|---|
| `backend/tests/test_auth.py` | 9 | register/login/me, weak password, duplicates, bad login, logout revocation, RBAC, self-demotion block |
| `test_threat_intel.py` | 10 | type detection, demo verdicts, "unknown is not clean", caching, mocked VirusTotal parsing, 429/403/500 -> `unavailable`, missing key, failures not cached |
| `test_rag.py` | 9 | upload validation, chunking, cited retrieval, ATT&CK retrieval, irrelevant query -> no relevant, empty KB, prompt-injection flagging/exclusion, delete |
| `test_agents.py` | 14 | full investigation, nothing executes without approval, selective agent execution, benign input, no input, empty-KB statement, tool allow-list, retry then success, persistent failure isolation, invalid output rejected, prompt-injection in email, unavailable intel not scored, domain-lookup regression, internal IPs skipped |
| `test_api.py` | 14 | endpoint inventory, auth on every route, dashboard empty->populated, phishing, intel, log upload validation, knowledge RBAC, incident lifecycle, approval RBAC/validation/execution/rollback/audit, **end-to-end** (login -> logs -> intel -> investigation -> incident -> approval -> PDF/CSV), CSV formula injection, PDF markup escaping, settings never leak secrets |
| `frontend/src/__tests__` | 24 | form validation, login/register flow, protected routes, expired token, API client (token header, error formatting, 401, 204, 429, unreachable), loading/error/empty states, threat-intel honesty labels, Badge regression |
| `e2e/e2e_ui.py` (Playwright) | 1 flow | full browser journey incl. PDF download, logout, mobile width (no horizontal overflow), zero console errors |

Total: **56 backend + 24 frontend unit/integration tests + 1 browser flow**, all passing at the time of writing. Backend tests were run on SQLite and PostgreSQL 16, and in a clean virtualenv.

## Bugs found by testing (and fixed)
1. Domains were skipped by the threat-intel agent as "internal" (regression test added).
2. Loopback blocking was not refused: `except ValueError` swallowed the validation error.
3. Corroboration points were awarded for any shared indicator, not just malicious ones.
4. `Badge` ignored custom children (found by the browser E2E).
5. Approved cards vanished from the Pending tab, hiding the simulated result (found by the browser E2E).
6. 100k-event analysis took 29 s (see PERFORMANCE.md).
7. PostgreSQL test run hung on leftover open sessions (fixture now closes them).

## Not tested / not done
* Docker image build and run; AWS deployment.
* Live VirusTotal calls (HTTP behaviour verified with a mocked transport only).
* Load/concurrency, penetration testing, accessibility audit (only labelled form controls and roles were used).
* RAG retrieval evaluation is a handful of queries, not a benchmark. No evaluation on public security datasets.
* Spec items "threat classification evaluation / false-positive testing" are limited to the synthetic and 16-sample checks in ML_EVALUATION.md.

## Commands
`cd backend && pytest -q` · `cd frontend && npm test` · `./scripts/run_e2e.sh` · `TEST_DATABASE_URL=postgresql+psycopg://... pytest -q`
