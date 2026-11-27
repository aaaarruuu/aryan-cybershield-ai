"""Measure real timings on this machine. Run: python scripts/benchmark.py  (from repo root, venv active)."""
import os, sys, tempfile, time, platform
tmp = tempfile.mkdtemp()
os.environ.update(DATABASE_URL=f"sqlite:///{tmp}/b.db", CHROMA_PATH=f"{tmp}/chroma", DEMO_MODE="true", SECRET_KEY="bench-secret-key-0123456789-abcdefghijklmnop")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import numpy as np, pandas as pd
from app.database.session import Base, engine, SessionLocal
import app.models
Base.metadata.create_all(engine)
from app.services.log_parser import parse_upload
from app.ml.log_analysis import analyse
from app.rag import store
from app.services import phishing, logs as logsvc, investigations as inv
from app.models.entities import Investigation
ROOT = os.path.join(os.path.dirname(__file__), "..", "sample_data")

def t(label, fn, n=1):
    s = time.perf_counter(); [fn() for _ in range(n)]; ms = (time.perf_counter() - s) / n * 1000
    print(f"{label:58s} {ms:10.1f} ms"); return ms

print(f"python {platform.python_version()}  cpus={os.cpu_count()}")
raw = open(f"{ROOT}/auth_logs.csv", "rb").read()
t("parse sample CSV (274 events)", lambda: parse_upload("a.csv", raw), 5)
df = parse_upload("a.csv", raw).events
t("analyse sample (rules + Isolation Forest, 274 events)", lambda: analyse(df), 3)
for n in (10_000, 100_000):
    rng = np.random.default_rng(1)
    big = pd.DataFrame({"timestamp": pd.Timestamp("2026-01-01", tz="UTC") + pd.to_timedelta(rng.integers(0, 86400 * 7, n), unit="s"),
                        "event_type": "login", "username": rng.choice([f"u{i}" for i in range(200)], n),
                        "src_ip": [f"10.{a}.{b}.{c}" for a, b, c in zip(rng.integers(0, 4, n), rng.integers(0, 255, n), rng.integers(1, 255, n))],
                        "outcome": rng.choice(["success", "failure"], n, p=[.95, .05]), "raw": ""}).sort_values("timestamp").reset_index(drop=True)
    t(f"analyse {n:,} synthetic events", lambda: analyse(big))
t("phishing analyse (single email)", lambda: phishing.analyse("URGENT verify", "a@paypa1-support.com", "verify your password immediately", ["http://paypa1-support.com.x.xyz/l"]), 20)
text = store.extract_text("k.md", open(f"{ROOT}/knowledge/mitre_attack_techniques.md", "rb").read())
t(f"RAG ingest ATT&CK summary ({len(text)//1024} KB)", lambda: store.add_document(1, "attack.md", text))
store.add_document(2, "pb.md", store.extract_text("p.md", open(f"{ROOT}/knowledge/incident_response_playbooks.md", "rb").read()))
t("RAG search (k=4)", lambda: store.search("brute force failed logins containment"), 10)
db = SessionLocal(); parsed = parse_upload("a.csv", raw); bid, _ = logsvc.store_events(db, parsed, "bench")
t("store 274 events + analysis in DB", lambda: logsvc.store_events(db, parsed, "bench"), 3)
req = {"phishing": dict(subject="URGENT", sender="security@paypa1-support.com", body="Dear customer, verify your password immediately", urls=["http://paypa1-support.com.verify-login.xyz/login"], metadata={}),
       "log_batch_id": bid, "indicators": ["203.0.113.45"], "create_incident": True}
def run():
    i = Investigation(title="b", request=req, status="queued"); db.add(i); db.commit(); inv.execute(db, i, None, req)
t("full multi-agent investigation (all agents, with RAG)", run, 3)
