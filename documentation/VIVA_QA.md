# Viva Questions and Answers

**1. What problem does the project solve?** Analysts triage alerts from separate sources (email, logs, reputation feeds) by hand. The platform collects those signals, correlates them, scores risk transparently and proposes actions that a human approves.

**2. What does "agentic" mean here?** Specialised components with defined inputs/outputs, controlled tools and explicit transitions, orchestrated by a LangGraph state graph. They are *not* free-form chatbots; they are deterministic functions.

**3. Did you use an LLM?** No. I chose deterministic, explainable analysis so every verdict is traceable to evidence. The design leaves a place for an LLM (validated outputs, untrusted-text wrapper), and I list it as future work. Claiming otherwise would be wrong.

**4. Why LangGraph?** It gives an explicit graph with typed shared state, parallel fan-out and conditional edges (e.g. skip response when risk is low), which matches the "controlled orchestration" requirement.

**5. How do you stop agents doing unsafe things?** A tool allow-list per agent, no shell/file/network-write tools, validated outputs, bounded retries, and recommended actions stored only as PENDING approvals. Execution is simulated and role-gated.

**6. How is severity decided?** `risk_agent` sums evidence factors with stated points (e.g. critical log alert 40, phishing class, malicious indicators), shows each factor, and never takes severity from model text. ML-only anomalies add zero points.

**7. Verified fact vs hypothesis?** Observed data (an alert, an indicator verdict) is a fact; inferences ("account may be compromised") are hypotheses. They are stored and exported separately.

**8. How does the phishing detector work?** Deterministic checks (look-alike domains, URL structure, urgency/credential language, auth results) plus a TF-IDF + logistic regression probability worth at most 25 points. Classification as phishing needs at least two independent deterministic indicators, so the ML model alone cannot condemn an email.

**9. How good is the model?** Honestly: trained on synthetic templates; held-out 1.0 is meaningless; on 16 hand-written emails accuracy 0.81, FPR 0.25; the full analyser on body text alone missed 3 of 8 phishing texts. No real-world accuracy is claimed. I did not tune on that tiny set to avoid overfitting my own test.

**10. Why Isolation Forest, and what are its limits?** It needs no labels. It is fitted per batch with fixed contamination (5%), so it always flags ~5% of windows; I show these as low-severity unconfirmed signals and give them no score weight.

**11. Why not CIC-IDS2017/UNSW-NB15?** They were not available in my build environment (download blocked) and are multi-GB flow datasets with schemas unlike auth logs; mixing incompatible schemas would be wrong. The training function accepts a real CSV; it is listed as a gap.

**12. How does RAG work here?** Extract -> clean -> chunk (900 chars, 150 overlap) -> embed -> ChromaDB -> cosine retrieval with a similarity floor -> cite file and chunk. Embeddings are local hashing n-grams (lexical), so no downloads or API keys; a neural embedder is an upgrade.

**13. What if nothing relevant is retrieved?** The response says "No relevant information found"; recommendations are labelled rule-based, never given fake citations.

**14. How do you defend against prompt injection?** Uploaded text is untrusted: injection-like chunks are flagged and excluded from agent context, retrieved text is quoted as data, and, more fundamentally, agents are code so text cannot change permissions. Pattern matching can be evaded; with an LLM added this needs more work.

**15. Authentication design?** bcrypt hashes; JWT (30 min) carrying a `token_version`; logout, password change and role change bump the version, instantly revoking old tokens. RBAC dependencies enforce roles server-side.

**16. Known security weaknesses?** Token in sessionStorage (XSS exposure), in-memory per-process rate limiting on auth only, no MFA/lockout, no pen test, 5 chromadb findings that apply only to its HTTP server (unused). All documented.

**17. How do you prevent CSV/PDF injection?** CSV cells starting with `= + - @` are prefixed with `'`; PDF text is XML-escaped (tested).

**18. Database design?** 13 tables, FKs, indexes, a CHECK constraint on action types, unique hashes; Alembic migration verified on PostgreSQL (up/down/up, no drift).

**19. What performance work did you do?** Benchmarked; 100k-event analysis took 29 s; profiling showed repeated dataframe scans per flagged window; a single `groupby` index cut it to 4.4 s.

**20. How did testing find real bugs?** Domains skipped as "internal", swallowed loopback validation, over-generous corroboration scoring, a UI Badge bug and a vanishing-approval UX bug (see TESTING.md).

**21. Why simulation-only response?** No integrations exist, and real blocking/disabling needs explicit authorisation and configured connectors; the design records approval, verification, rollback and audit so a connector can be added behind the same workflow.

**22. What would you do next?** Add an LLM for narrative summaries behind the validated-output layer, train on CIC-IDS2017/UNSW-NB15 with proper leakage control, add Wazuh/pcap ingestion, neural embeddings, async ingestion, HttpOnly-cookie sessions and MFA.

**23. Is it legally protected from copying?** No such claim is made; authorship and documentation establish project identity.

**24. Does Docker deployment work?** The files are written and `compose config` validates, and I ran the real entrypoint against PostgreSQL in production mode, but I could not build images in my environment; I'd confirm with `docker compose up --build` first.
