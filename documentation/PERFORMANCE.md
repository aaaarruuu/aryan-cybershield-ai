# Performance Measurements

Measured with `python scripts/benchmark.py` on the development sandbox (2 vCPU, Python 3.13, SQLite, in-process). Indicative only; your hardware will differ.

| Operation | Time |
|---|---|
| Parse sample CSV (274 events) | 6 ms |
| Analyse sample (rules + Isolation Forest) | ~210-230 ms |
| Analyse 10,000 events | 0.7-0.9 s |
| Analyse 100,000 events | **4.4 s** (29.4 s before the fix below) |
| Phishing analysis (one email) | 0.6-0.7 ms |
| RAG ingest of ATT&CK summary (503 KB) | 0.83 s |
| RAG search | 9 ms |
| Store 274 events + analysis | ~190 ms |
| Full multi-agent investigation (all agents + RAG) | 0.23-0.24 s |

## Bottleneck found and fixed
At 100,000 events, analysis took 29.4 s. Profiling showed `ml_anomalies` rescanned the whole dataframe for every flagged IP/time window (~5,000 windows). Building the window->events index once with `groupby(...).groups` cut it to 4.4 s (6.7x), with all tests unchanged.

## Remaining bottlenecks / notes
* Rule-based brute-force detection is a per-IP Python loop; it dominates at 100k events (a vectorised version is possible).
* Log upload is synchronous. The 100,000-row cap bounds the request to a few seconds on this hardware, but slower machines or larger limits warrant async ingestion.
* API cold start is several seconds (library imports); the phishing model trains on first use (~1 s) unless artifacts exist.
* Embedded ChromaDB is single-writer: run one backend process.
* No load testing (concurrent users) was performed.
