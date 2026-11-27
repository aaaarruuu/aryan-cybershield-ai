"""Threat intelligence lookups (VirusTotal v3 live, or labelled DEMO dataset).

Guarantees:
* Results are never invented. Every result carries `source`, `looked_up_at` and a `verdict`.
* If a live lookup fails, verdict is "unavailable" with the reason; it is never guessed.
* Indicators absent from the demo dataset get verdict "unknown" (not "clean").
* API keys come from settings (environment) only and are never returned to the client.
"""
import base64
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.entities import ThreatIndicator

DEMO_FILE = Path(__file__).resolve().parents[3] / "sample_data" / "threat_intel_demo.json"
CACHE_TTL = timedelta(hours=24)
VT_BASE = "https://www.virustotal.com/api/v3"
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


def detect_type(value: str) -> str | None:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "hash"
    if "://" in v:
        return "url" if urlparse(v).hostname else None
    return "domain" if DOMAIN_RE.match(v) else None


def normalise(value: str, itype: str) -> str:
    v = value.strip()
    return v.lower() if itype in ("domain", "hash") else v


def _verdict(mal: int, sus: int, harmless: int) -> tuple[str, float | None]:
    total = mal + sus + harmless
    score = round((mal + 0.5 * sus) / total * 100, 1) if total else None
    if mal >= 3:
        return "malicious", score
    if mal >= 1 or sus >= 3:
        return "suspicious", score
    return ("clean", score) if harmless > 0 else ("unknown", score)


def _demo_lookup(itype: str, value: str) -> dict:
    data = json.loads(DEMO_FILE.read_text()) if DEMO_FILE.exists() else {}
    rec = data.get(f"{itype}:{value}")
    if itype == "url" and not rec:
        host = urlparse(value).hostname or ""
        for k, v in data.items():
            if k.startswith("domain:") and (host == k[7:] or host.endswith("." + k[7:])):
                rec = v
                break
    base = {"source": "demo-sample-data", "demo": True}
    if not rec:
        return {**base, "verdict": "unknown", "score": None,
                "details": {"note": "Not present in the bundled demo dataset. This is NOT a clean verdict."}}
    verdict, score = _verdict(rec["malicious"], rec["suspicious"], rec["harmless"])
    return {**base, "verdict": verdict, "score": score,
            "details": {"engine_stats": {k: rec[k] for k in ("malicious", "suspicious", "harmless")}, "note": rec.get("note", "")}}


def _vt_path(itype: str, value: str) -> str:
    if itype == "ip":
        return f"/ip_addresses/{value}"
    if itype == "domain":
        return f"/domains/{value}"
    if itype == "hash":
        return f"/files/{value}"
    return "/urls/" + base64.urlsafe_b64encode(value.encode()).decode().strip("=")


def _vt_lookup(itype: str, value: str, client: httpx.Client | None = None) -> dict:
    key = get_settings().virustotal_api_key
    base = {"source": "virustotal", "demo": False}
    if not key:
        return {**base, "verdict": "unavailable", "score": None, "details": {"error": "VIRUSTOTAL_API_KEY is not configured"}}
    if itype == "ip":
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_reserved or ip.is_loopback:
            return {**base, "verdict": "unknown", "score": None, "details": {"note": "Private/reserved address; external reputation does not apply"}}
    own = client is None
    client = client or httpx.Client(timeout=10.0)
    try:
        r = client.get(VT_BASE + _vt_path(itype, value), headers={"x-apikey": key})
        if r.status_code == 404:
            return {**base, "verdict": "unknown", "score": None, "details": {"note": "Indicator not found in VirusTotal"}}
        if r.status_code == 429:
            return {**base, "verdict": "unavailable", "score": None, "details": {"error": "VirusTotal rate limit reached; retry later"}}
        if r.status_code in (401, 403):
            return {**base, "verdict": "unavailable", "score": None, "details": {"error": "VirusTotal rejected the API key"}}
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        st = attrs.get("last_analysis_stats", {})
        mal, sus, har = st.get("malicious", 0), st.get("suspicious", 0), st.get("harmless", 0)
        verdict, score = _verdict(mal, sus, har)
        return {**base, "verdict": verdict, "score": score,
                "details": {"engine_stats": {"malicious": mal, "suspicious": sus, "harmless": har, "undetected": st.get("undetected", 0)},
                            "reputation": attrs.get("reputation"), "last_analysis_date": attrs.get("last_analysis_date")}}
    except (httpx.HTTPError, KeyError, ValueError) as e:
        return {**base, "verdict": "unavailable", "score": None, "details": {"error": f"Lookup failed: {type(e).__name__}"}}
    finally:
        if own:
            client.close()


def lookup(db: Session, value: str, itype: str | None = None, use_cache: bool = True,
           client: httpx.Client | None = None) -> dict:
    itype = itype or detect_type(value)
    if not itype or (detect_type(value) != itype):
        raise ValueError("Unrecognised or invalid indicator. Supported: IPv4/IPv6, domain, URL, MD5/SHA1/SHA256 hash")
    value = normalise(value, itype)
    settings = get_settings()
    source = "demo-sample-data" if settings.demo_mode else "virustotal"
    now = datetime.now(timezone.utc)
    row = db.scalar(select(ThreatIndicator).where(ThreatIndicator.indicator_type == itype, ThreatIndicator.value == value,
                                                  ThreatIndicator.source == source))
    if row and use_cache and row.verdict != "unavailable":
        age = now - (row.looked_up_at if row.looked_up_at.tzinfo else row.looked_up_at.replace(tzinfo=timezone.utc))
        if age < CACHE_TTL:
            return _out(row, cached=True)
    res = _demo_lookup(itype, value) if settings.demo_mode else _vt_lookup(itype, value, client)
    if row is None:
        row = ThreatIndicator(indicator_type=itype, value=value, source=res["source"])
        db.add(row)
    row.verdict, row.score, row.details, row.looked_up_at = res["verdict"], res["score"], res["details"], now
    db.commit()
    return _out(row, cached=False)


def _out(row: ThreatIndicator, cached: bool) -> dict:
    return {"indicator": row.value, "type": row.indicator_type, "verdict": row.verdict, "score": row.score,
            "source": row.source, "demo": row.source == "demo-sample-data", "details": row.details,
            "looked_up_at": row.looked_up_at.isoformat(), "cached": cached,
            "is_ioc": row.verdict in ("malicious", "suspicious")}
