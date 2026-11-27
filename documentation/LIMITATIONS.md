# Limitations, Known Gaps and Residual Risks

Honest accounting of what this project does **not** do. Nothing here is hidden elsewhere.

## A. Requested in the brief but NOT implemented

| Item | Status | Why / what exists instead |
|---|---|---|
| Generative AI / LLM integration, LangChain, Hugging Face | **Not implemented** | All agents are deterministic and evidence-based. The structure (validated agent outputs, `wrap_untrusted`) is ready for an LLM to be added for narrative summaries, but no provider code exists, so no LLM config is exposed. |
| Public datasets (CIC-IDS2017, UNSW-NB15, Phishing Websites, BETH) | **Not used** | The build sandbox could not download them (e.g. UCI returned HTTP 403 via the proxy) and CIC/UNSW are multi-GB. Models are trained on a small **synthetic** corpus. `phishing_model.train(csv_path)` accepts a real `text,label` CSV. No supervised network-intrusion classifier was built. |
| Wazuh integration, Wireshark/pcap analysis | **Not implemented** | Logs are ingested as CSV / JSON / text only. |
| Redis | Not used | Not needed: background work uses FastAPI `BackgroundTasks`. |
| Real response execution | By design **simulation only** | No firewall/IdP/EDR connectors exist. |
| TypeScript | Not used | Frontend is JavaScript (allowed by the brief). |
| Frontend "AI assistant" chat | Not a chat | The AI Investigation Center (submit request, see per-agent activity) fills this role. |

## B. Docker / deployment verification

Dockerfiles, nginx config and `docker-compose.yml` are written and `docker compose config` validates them (and rejects a missing `SECRET_KEY`/`POSTGRES_PASSWORD`). **The images were not built or run** because the build environment had no Docker daemon. What *was* verified: the real `entrypoint.sh` (migrations then uvicorn) in production mode against PostgreSQL 16 using the images' `/srv` directory layout. Run `docker compose up --build` once and confirm before relying on it. AWS notes are guidance, **not tested** on AWS.

## C. Accuracy limits

* Phishing model: synthetic training data; a 16-email hand-written check scored accuracy 0.81, FPR 0.25 (tiny sample). The full analyser using body text only (no sender/URLs) missed 3 of 8 phishing texts on that set. See [ML_EVALUATION.md](ML_EVALUATION.md).
* The top learned terms include template artefacts (`be`, `in`), a sign of overfitting to the synthetic templates.
* Isolation Forest is fitted per uploaded batch with fixed 5% contamination, so it always flags ~5% of windows. Its output is a low-severity *signal*, never confirmed, never scored.
* Log detections were checked only on synthetic data whose attacks were authored alongside the rules. No claim of real-world detection rates is made. The platform does not detect every attack.
* RAG retrieval is lexical (hashing n-grams), not deep semantic: paraphrased queries with no shared words can miss.
* The ATT&CK knowledge file truncates descriptions to ~700 characters per technique.
* Demo threat-intel data is a handful of fabricated-for-demo records using documentation IP ranges.

## D. Security - residual risks

* **No claim of being "fully secure."** No penetration test or external audit was performed; automated checks only (unit/API tests, `pip-audit`, `npm audit`).
* **chromadb 1.5.9 has 5 open findings (4 distinct advisories: PYSEC-2026-311, -3813, -3814, -3815; no fixed release exists)**. All concern the Chroma *HTTP server* (REST endpoint code injection via `trust_remote_code`, tenant RBAC). This project uses the embedded `PersistentClient` and exposes no Chroma server, so they are not reachable here. **Never expose a Chroma server** with this version; re-check `pip-audit` periodically.
* JWT is stored in `sessionStorage` (cleared on tab close but readable by script): an XSS bug would expose it. React escapes output and a CSP is set in nginx, but there is no HttpOnly-cookie/refresh-token design.
* Rate limiting covers only register/login, is per-process and in-memory (resets on restart, not shared across workers). No account lockout, MFA or password-reset flow.
* Investigations run as in-process background tasks: an API restart mid-run leaves the investigation `running`.
* The first registered user becomes admin: register your admin immediately after first deploy, before exposing the service.
* Prompt-injection defence is pattern-based flagging plus the architectural rule that agents are code. Patterns can be evaded; with no LLM in the loop the blast radius is small, but revisit this if an LLM is added.
* Uploaded PDFs are parsed with `pypdf`; malformed-file parsing bugs in dependencies are possible (size/page limits applied).
* Frontend dev tooling is on current majors; production npm dependencies audit clean at time of writing.

## E. Functional limits

* Single-tenant. Roles limited to admin/analyst. Audit log is append-only by convention (no DB-level immutability).
* No email/SMS notifications, no SIEM export, no scheduled ingestion.
* Sample size / performance: 100,000 events analyse in ~4.4 s but uploads are synchronous (see [PERFORMANCE.md](PERFORMANCE.md)); larger files need chunking or async ingestion.
