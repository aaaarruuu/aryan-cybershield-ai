# Resume-Ready Description

**ARYAN CYBERSHIELD AI - Agentic AI-Based Cybersecurity Investigation Platform** *(personal / MCA project)*

* Built a full-stack SOC-assistant platform (FastAPI, PostgreSQL, React, Tailwind, Docker) with JWT auth, RBAC, audit logging and 40+ REST endpoints across 13 UI pages.
* Designed a LangGraph multi-agent investigation workflow (planner, phishing, log, threat-intel, investigation, risk, response) with validated structured outputs, bounded retries, per-agent tool allow-lists and parallel fan-out for independent agents.
* Implemented evidence-based risk scoring that separates verified findings from hypotheses; human-approval workflow with simulated, auditable, reversible response actions.
* Developed log analytics (rule engine + Isolation Forest) and a phishing analyser combining deterministic indicators with a TF-IDF/logistic-regression signal; reported honest evaluation on synthetic and hand-written sets.
* Built a RAG knowledge base (ChromaDB) with cited retrieval, prompt-injection flagging and an explicit "no relevant information" path.
* Wrote 80 automated tests (56 backend incl. PostgreSQL run, 24 frontend) plus a Playwright browser E2E; profiled and fixed a 6.7x performance bottleneck; cleared `npm audit` and triaged `pip-audit` findings.

**Short (one line):** Full-stack AI-assisted SOC platform: FastAPI + React + LangGraph agents + ML/RAG, human-approved simulated response, 80 automated tests.

*(Say plainly in interviews: agents are deterministic - no LLM; models trained on synthetic data; response actions simulated.)*
