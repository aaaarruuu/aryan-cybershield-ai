"""Persist parsed security events and re-load them for analysis."""
import uuid

import pandas as pd
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ml.log_analysis import analyse
from app.models.entities import MLPrediction, SecurityEvent
from app.services.log_parser import ParseResult


def store_events(db: Session, parsed: ParseResult, source: str) -> tuple[str, dict]:
    batch_id = uuid.uuid4().hex[:16]
    result = analyse(parsed.events)
    flagged = set(result["flagged_event_idx"])
    scores = result["anomaly_scores"]
    rows = []
    for i, r in parsed.events.iterrows():
        sc = scores.get(i)
        rows.append(SecurityEvent(timestamp=r["timestamp"].to_pydatetime(), source=source[:80], event_type=r["event_type"],
                                  username=r["username"] if isinstance(r["username"], str) else None,
                                  src_ip=r["src_ip"] if isinstance(r["src_ip"], str) else None, outcome=r["outcome"],
                                  raw=r["raw"], is_suspicious=i in flagged,
                                  anomaly_score=None if sc is None or pd.isna(sc) else float(sc), batch_id=batch_id))
    db.add_all(rows)
    for a in result["alerts"]:
        if a["source"] == "ml":
            db.add(MLPrediction(model_name="isolation_forest_logs", input_ref=f"{batch_id}:{a['src_ip']}", label="anomalous",
                                confidence=min(1.0, float(a["evidence"]["anomaly_score"])), features=a["evidence"]))
    db.commit()
    return batch_id, {"batch_id": batch_id, "summary": result["summary"], "ml_meta": result["ml_meta"], "warnings": parsed.warnings,
                      "skipped_rows": parsed.skipped_rows,
                      "alerts": [{k: v for k, v in a.items() if k != "event_idx"} for a in result["alerts"]]}


def load_batch(db: Session, batch_id: str) -> pd.DataFrame:
    rows = db.scalars(select(SecurityEvent).where(SecurityEvent.batch_id == batch_id).order_by(SecurityEvent.timestamp, SecurityEvent.id)).all()
    if not rows:
        raise ValueError(f"Log batch '{batch_id}' not found")
    return pd.DataFrame([{"timestamp": pd.Timestamp(r.timestamp).tz_convert("UTC") if pd.Timestamp(r.timestamp).tzinfo else pd.Timestamp(r.timestamp, tz="UTC"),
                          "event_type": r.event_type, "username": r.username, "src_ip": r.src_ip, "outcome": r.outcome or "unknown",
                          "raw": r.raw or ""} for r in rows])
