from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.ml import phishing_model
from app.models.entities import MLPrediction, SecurityEvent, ThreatIndicator, User
from app.schemas.common import IndicatorIn, PhishingIn
from app.security.auth import audit, require_analyst
from app.services import logs as log_service
from app.services import phishing as phishing_service
from app.services import threat_intel
from app.services.log_parser import LogValidationError, parse_upload

router = APIRouter(prefix="/api", tags=["analysis"])
SAMPLE_DIR = "sample_data"


@router.post("/phishing/analyse")
def analyse_phishing(body: PhishingIn, request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    if not (body.subject or body.body or body.urls or body.sender):
        raise HTTPException(422, "Provide at least a subject, sender, body or URL")
    res = phishing_service.analyse(body.subject, body.sender, body.body, body.urls, body.metadata)
    db.add(MLPrediction(model_name="phishing_analysis", input_ref=body.sender[:100], label=res["classification"], confidence=res["confidence"],
                        features={"risk_score": res["risk_score"], "indicator_ids": [i["id"] for i in res["indicators"]],
                                  "ml_probability": res["ml"]["phishing_probability"]}))
    db.commit()
    audit(db, "phishing.analysed", user, "phishing", "", {"classification": res["classification"], "risk": res["risk_level"]}, request)
    return res


@router.get("/phishing/model-report")
def model_report(_: User = Depends(require_analyst)):
    return phishing_model.evaluation_report()


@router.post("/intel/lookup")
def intel_lookup(body: IndicatorIn, request: Request, refresh: bool = False, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    try:
        res = threat_intel.lookup(db, body.value, body.indicator_type, use_cache=not refresh)
    except ValueError as e:
        raise HTTPException(422, str(e))
    audit(db, "intel.lookup", user, "indicator", body.value[:60], {"verdict": res["verdict"], "source": res["source"]}, request)
    return res


@router.get("/intel/indicators")
def list_indicators(verdict: str | None = None, limit: int = Query(100, le=500), _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    q = select(ThreatIndicator).order_by(ThreatIndicator.looked_up_at.desc()).limit(limit)
    if verdict:
        q = q.where(ThreatIndicator.verdict == verdict)
    return [threat_intel._out(r, cached=True) for r in db.scalars(q)]


@router.post("/logs/upload", status_code=201)
async def upload_logs(request: Request, file: UploadFile = File(...), user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    limit = get_settings().upload_max_mb * 1024 * 1024
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(413, f"File exceeds {get_settings().upload_max_mb} MB limit")
    try:
        parsed = parse_upload(file.filename or "", content)
    except LogValidationError as e:
        raise HTTPException(422, str(e))
    _, out = log_service.store_events(db, parsed, f"upload:{(file.filename or 'file')[:60]}")
    audit(db, "logs.uploaded", user, "log_batch", out["batch_id"], {"events": out["summary"]["events"], "alerts": out["summary"]["alerts"]}, request)
    return out


@router.get("/logs/batches")
def list_batches(_: User = Depends(require_analyst), db: Session = Depends(get_db)):
    from sqlalchemy import func
    rows = db.execute(select(SecurityEvent.batch_id, func.count(SecurityEvent.id), func.sum(SecurityEvent.is_suspicious), func.min(SecurityEvent.timestamp),
                             func.max(SecurityEvent.timestamp), func.max(SecurityEvent.source)).group_by(SecurityEvent.batch_id)
                      .order_by(func.max(SecurityEvent.created_at).desc()).limit(50)).all()
    return [{"batch_id": r[0], "events": r[1], "suspicious": int(r[2] or 0), "first": r[3].isoformat() if r[3] else None,
             "last": r[4].isoformat() if r[4] else None, "source": r[5]} for r in rows]


@router.get("/logs/batches/{batch_id}/analysis")
def batch_analysis(batch_id: str, _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    from app.ml.log_analysis import analyse
    try:
        df = log_service.load_batch(db, batch_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    r = analyse(df)
    return {"batch_id": batch_id, "summary": r["summary"], "ml_meta": r["ml_meta"],
            "alerts": [{k: v for k, v in a.items() if k != "event_idx"} for a in r["alerts"]]}


@router.get("/logs/events")
def list_events(batch_id: str | None = None, suspicious: bool | None = None, limit: int = Query(200, le=1000), offset: int = 0,
                _: User = Depends(require_analyst), db: Session = Depends(get_db)):
    q = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).offset(offset)
    if batch_id:
        q = q.where(SecurityEvent.batch_id == batch_id)
    if suspicious is not None:
        q = q.where(SecurityEvent.is_suspicious == suspicious)
    return [{"id": e.id, "timestamp": e.timestamp.isoformat(), "event_type": e.event_type, "username": e.username, "src_ip": e.src_ip,
             "outcome": e.outcome, "is_suspicious": e.is_suspicious, "anomaly_score": e.anomaly_score, "batch_id": e.batch_id} for e in db.scalars(q)]


@router.post("/logs/load-sample", status_code=201)
def load_sample(request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """Demo helper: ingest the bundled synthetic auth log so the platform can be explored without real data."""
    from pathlib import Path
    p = Path(__file__).resolve().parents[3] / "sample_data" / "auth_logs.csv"
    if not p.exists():
        raise HTTPException(404, "Bundled sample data not found")
    _, out = log_service.store_events(db, parse_upload("auth_logs.csv", p.read_bytes()), "demo:auth_logs.csv (synthetic)")
    audit(db, "logs.sample_loaded", user, "log_batch", out["batch_id"], {}, request)
    return out
