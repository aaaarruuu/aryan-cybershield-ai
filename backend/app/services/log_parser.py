"""Parse and validate uploaded security logs (CSV / JSON / text) into normalised events.

Uploaded content is untrusted: size/row limits, strict decoding, IP validation, no eval of any kind.
"""
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field

import pandas as pd

MAX_ROWS = 100_000
COLUMNS = ["timestamp", "event_type", "username", "src_ip", "outcome", "raw"]
ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp", "ts"],
    "event_type": ["event_type", "event", "type", "action", "category"],
    "username": ["username", "user", "account", "user_name", "target_user"],
    "src_ip": ["src_ip", "source_ip", "ip", "ip_address", "client_ip", "remote_ip", "src"],
    "outcome": ["outcome", "result", "status", "success"],
}
SSHD_RE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+sshd\[\d+\]:\s+"
                     r"(?P<res>Accepted|Failed) \w+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
KV_RE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+\S+:\s+(?P<et>\w+)\s+(?P<kv>.*)")
SUCCESS_WORDS = {"success", "succeeded", "ok", "accepted", "allowed", "true", "1"}
FAIL_WORDS = {"failure", "failed", "fail", "denied", "error", "invalid", "false", "0", "blocked"}


class LogValidationError(ValueError):
    pass


@dataclass
class ParseResult:
    events: pd.DataFrame
    total_rows: int
    skipped_rows: int
    warnings: list = field(default_factory=list)


def _valid_ip(v) -> str | None:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _norm_outcome(v) -> str:
    s = str(v).strip().lower()
    if s in SUCCESS_WORDS:
        return "success"
    if s in FAIL_WORDS:
        return "failure"
    return "unknown"


def _normalise(df: pd.DataFrame, raw_lines: list | None = None) -> ParseResult:
    if len(df) > MAX_ROWS:
        raise LogValidationError(f"Too many rows ({len(df)}); limit is {MAX_ROWS}")
    cols = {c.lower().strip(): c for c in df.columns}
    mapped = {}
    for target, names in ALIASES.items():
        for n in names:
            if n in cols:
                mapped[target] = cols[n]
                break
    if "timestamp" not in mapped:
        raise LogValidationError("No timestamp column found (expected one of: " + ", ".join(ALIASES["timestamp"]) + ")")
    if "src_ip" not in mapped and "username" not in mapped:
        raise LogValidationError("Log must contain at least a source IP or a username column")
    out = pd.DataFrame(index=df.index)
    out["timestamp"] = pd.to_datetime(df[mapped["timestamp"]], errors="coerce", utc=True)
    out["event_type"] = df[mapped["event_type"]].astype(str).str.lower().str.slice(0, 60) if "event_type" in mapped else "login"
    out["username"] = df[mapped["username"]].astype(str).str.slice(0, 120) if "username" in mapped else None
    out["src_ip"] = df[mapped["src_ip"]].map(_valid_ip) if "src_ip" in mapped else None
    out["outcome"] = df[mapped["outcome"]].map(_norm_outcome) if "outcome" in mapped else "unknown"
    out["raw"] = raw_lines if raw_lines is not None else df.astype(str).agg(",".join, axis=1).str.slice(0, 500)
    bad = out["timestamp"].isna()
    warnings = []
    if bad.any():
        warnings.append(f"{int(bad.sum())} rows skipped: unparseable timestamp")
    bad_ip = ("src_ip" in mapped) & out["src_ip"].isna()
    if "src_ip" in mapped and bad_ip.any():
        warnings.append(f"{int(bad_ip.sum())} rows have a missing or invalid IP address (kept, IP unset)")
    total = len(out)
    out = out[~bad].sort_values("timestamp").reset_index(drop=True)
    if out.empty:
        raise LogValidationError("No valid events found in file")
    return ParseResult(out[COLUMNS], total, total - len(out), warnings)


def parse_text(text: str) -> ParseResult:
    rows = []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) > MAX_ROWS:
        raise LogValidationError(f"Too many lines ({len(lines)}); limit is {MAX_ROWS}")
    skipped = 0
    for ln in lines:
        m = SSHD_RE.search(ln)
        if m:
            rows.append({"timestamp": m["ts"].replace(",", "."), "event_type": "login", "username": m["user"],
                         "src_ip": m["ip"], "outcome": "success" if m["res"] == "Accepted" else "failure", "raw": ln[:500]})
            continue
        m = KV_RE.search(ln)
        if m:
            kv = dict(re.findall(r"(\w+)=(\S+)", m["kv"]))
            rows.append({"timestamp": m["ts"].replace(",", "."), "event_type": m["et"].lower(),
                         "username": kv.get("user"), "src_ip": kv.get("src") or kv.get("ip"),
                         "outcome": kv.get("result") or kv.get("status") or "unknown", "raw": ln[:500]})
            continue
        skipped += 1
    if not rows:
        raise LogValidationError("No recognised log lines (supported: sshd-style auth lines and 'timestamp host app: event key=value')")
    res = _normalise(pd.DataFrame(rows), [r["raw"] for r in rows])
    res.total_rows, res.skipped_rows = len(lines), res.skipped_rows + skipped
    if skipped:
        res.warnings.append(f"{skipped} unrecognised lines skipped")
    return res


def parse_upload(filename: str, content: bytes) -> ParseResult:
    name = (filename or "").lower()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise LogValidationError("File must be UTF-8 text")
    try:
        if name.endswith(".csv"):
            return _normalise(pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False))
        if name.endswith(".json"):
            data = json.loads(text)
            if isinstance(data, dict):
                data = data.get("events") or data.get("records") or data.get("logs")
            if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
                raise LogValidationError("JSON must be a list of event objects (or an object with an 'events' list)")
            return _normalise(pd.DataFrame(data).astype(object))
        if name.endswith((".txt", ".log")):
            return parse_text(text)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, json.JSONDecodeError) as e:
        raise LogValidationError(f"Could not parse file: {e}")
    raise LogValidationError("Unsupported file type. Supported: .csv, .json, .txt, .log")
