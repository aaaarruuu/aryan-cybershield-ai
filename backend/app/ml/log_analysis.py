"""Security log detection: transparent rules + Isolation Forest anomaly detection.

Rules are the source of truth for alerts. The Isolation Forest is an unsupervised *supplement*; it is
fitted on the uploaded batch itself (no labels exist), so its scores are relative to that batch and are
reported as such. No detection-accuracy claim is made for it.
"""
import ipaddress
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

BRUTE_THRESHOLD = 10           # failures from one IP inside the window
BRUTE_WINDOW_MIN = 10
SPRAY_USERS = 5                # distinct usernames failed from one IP
OFF_HOURS = (22, 6)            # [22:00, 06:00) UTC treated as unusual
MIN_BASELINE_EVENTS = 5        # events needed before "new IP for user" is meaningful
WINDOW = "10min"


@dataclass
class Alert:
    type: str
    severity: str
    title: str
    description: str
    src_ip: str | None
    usernames: list
    evidence: dict
    event_idx: list
    source: str = "rule"

    def dict(self):
        return self.__dict__.copy()


def _off_hours(ts: pd.Series) -> pd.Series:
    h = ts.dt.hour
    return (h >= OFF_HOURS[0]) | (h < OFF_HOURS[1])


def rule_alerts(df: pd.DataFrame) -> list[Alert]:
    alerts: list[Alert] = []
    logins = df[df["event_type"].isin(["login", "auth", "authentication", "logon"])]
    fails = logins[(logins["outcome"] == "failure") & logins["src_ip"].notna()]

    # --- brute force: sliding window per source IP ---
    for ip, g in fails.groupby("src_ip"):
        ts = g["timestamp"].reset_index()
        best = (0, None, None)
        j = 0
        for i in range(len(ts)):
            while ts.loc[i, "timestamp"] - ts.loc[j, "timestamp"] > pd.Timedelta(minutes=BRUTE_WINDOW_MIN):
                j += 1
            if i - j + 1 > best[0]:
                best = (i - j + 1, j, i)
        if best[0] >= BRUTE_THRESHOLD:
            idx = list(ts.loc[best[1]:best[2], "index"])
            t_end = df.loc[idx[-1], "timestamp"]
            users = sorted(set(df.loc[idx, "username"].dropna()))
            later_ok = logins[(logins["src_ip"] == ip) & (logins["outcome"] == "success") & (logins["timestamp"] >= t_end)
                              & (logins["timestamp"] <= t_end + pd.Timedelta(minutes=30))]
            compromised = len(later_ok) > 0
            spray = len(users) >= SPRAY_USERS
            ev = {"failed_attempts": best[0], "distinct_users": len(users), "window_minutes": BRUTE_WINDOW_MIN,
                  "first_seen": str(df.loc[idx[0], "timestamp"]), "last_seen": str(t_end),
                  "success_after_failures": compromised}
            idx_all = idx + (list(later_ok.index[:1]) if compromised else [])
            kind = "password_spraying" if spray else "brute_force"
            label = "Password spraying" if spray else "Brute-force activity"
            alerts.append(Alert(
                kind, "critical" if compromised else "high",
                f"{label} from {ip}" + (" followed by a successful login" if compromised else ""),
                f"{best[0]} failed logins from {ip} within {BRUTE_WINDOW_MIN} minutes targeting {len(users)} account(s): {', '.join(users)}."
                + (" A successful login from the same IP followed, so the account may be compromised (hypothesis; verify)." if compromised else ""),
                ip, users, ev, idx_all))

    # --- password spraying: many users, one IP ---
    for ip, g in fails.groupby("src_ip"):
        users = sorted(set(g["username"].dropna()))
        if len(users) >= SPRAY_USERS and not any(a.src_ip == ip and a.type in ("brute_force", "password_spraying") for a in alerts):
            alerts.append(Alert("password_spraying", "high", f"Possible password spraying from {ip}",
                                f"{len(g)} failed logins against {len(users)} different accounts from {ip}.",
                                ip, users, {"distinct_users": len(users), "failed_attempts": len(g)}, list(g.index)))

    # --- unusual access time (successful logins/activity off-hours) ---
    ok = df[(df["outcome"] == "success")]
    odd = ok[_off_hours(ok["timestamp"])]
    for user, g in odd.groupby("username"):
        alerts.append(Alert("unusual_access_time", "medium", f"Off-hours activity by {user}",
                            f"{len(g)} successful events for {user} between {OFF_HOURS[0]}:00 and {OFF_HOURS[1]:02d}:00 UTC.",
                            g["src_ip"].dropna().iloc[0] if g["src_ip"].notna().any() else None, [user],
                            {"events": len(g), "hours_utc": sorted(set(int(h) for h in g["timestamp"].dt.hour))}, list(g.index)))

    # --- login from a network never seen for this user (compares /16 so normal in-network IP churn is ignored) ---
    def net16(ip):
        a = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{ip}/16", strict=False)) if a.version == 4 else str(ipaddress.ip_network(f"{ip}/48", strict=False))

    for user, g in logins[(logins["outcome"] == "success") & logins["src_ip"].notna()].groupby("username"):
        if len(g) < MIN_BASELINE_EVENTS:
            continue
        nets = g["src_ip"].map(net16)
        counts = nets.value_counts()
        usual = counts.index[0]
        if counts.iloc[0] < MIN_BASELINE_EVENTS - 1:
            continue
        rare = g[nets.isin(counts[counts <= 1].index)]
        for idx, row in rare.iterrows():
            alerts.append(Alert("new_source_ip", "medium", f"{user} logged in from an unfamiliar network ({row['src_ip']})",
                                f"{row['src_ip']} is outside the network(s) {user} normally uses (usually {usual}).",
                                row["src_ip"], [user], {"usual_network": usual}, [idx]))

    # --- sensitive actions after an off-hours login ---
    sens = df[df["event_type"].isin(["privilege_change", "file_access", "admin_action"]) & (df["outcome"] == "success")]
    sens = sens[_off_hours(sens["timestamp"])]
    for user, g in sens.groupby("username"):
        alerts.append(Alert("sensitive_activity_off_hours", "high", f"Sensitive activity by {user} outside normal hours",
                            f"{', '.join(sorted(set(g['event_type'])))} performed by {user} off-hours.",
                            g["src_ip"].dropna().iloc[0] if g["src_ip"].notna().any() else None, [user],
                            {"event_types": sorted(set(g["event_type"]))}, list(g.index)))
    return alerts


def ml_anomalies(df: pd.DataFrame, contamination: float = 0.05, seed: int = 42):
    """Isolation Forest over per-(IP, 10-minute) behaviour features. Returns (per-event score, ml alerts, meta)."""
    d = df[df["src_ip"].notna()].copy()
    meta = {"model": "IsolationForest", "contamination": contamination, "random_state": seed,
            "fit_on": "uploaded batch (unsupervised, relative scores)"}
    if len(d) < 30:
        meta["skipped"] = "fewer than 30 events with an IP; not enough data for anomaly detection"
        return pd.Series(np.nan, index=df.index), [], meta
    d["win"] = d["timestamp"].dt.floor(WINDOW)
    d["fail"] = (d["outcome"] == "failure").astype(int)
    d["off"] = _off_hours(d["timestamp"]).astype(int)
    agg = d.groupby(["src_ip", "win"]).agg(events=("fail", "size"), failures=("fail", "sum"),
                                           users=("username", "nunique"), off=("off", "mean")).reset_index()
    agg["fail_ratio"] = agg["failures"] / agg["events"]
    feats = ["events", "failures", "users", "off", "fail_ratio"]
    if len(agg) < 20:
        meta["skipped"] = "fewer than 20 behaviour windows"
        return pd.Series(np.nan, index=df.index), [], meta
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(agg[feats])
    agg["score"] = -model.score_samples(agg[feats])       # higher = more anomalous
    agg["anom"] = model.predict(agg[feats]) == -1
    meta.update(windows=int(len(agg)), flagged_windows=int(agg["anom"].sum()))
    key = d[["src_ip", "win"]].merge(agg[["src_ip", "win", "score"]], on=["src_ip", "win"], how="left")
    scores = pd.Series(np.nan, index=df.index)
    scores.loc[d.index] = key["score"].values
    alerts = []
    groups = d.groupby(["src_ip", "win"]).groups          # one pass; avoids rescanning the frame per flagged window
    for _, r in agg[agg["anom"]].iterrows():
        idx = list(groups[(r["src_ip"], r["win"])])
        alerts.append(Alert("ml_anomaly", "low",
                            f"Statistically unusual activity from {r['src_ip']}",
                            f"Isolation Forest flagged this IP/time window as unusual relative to the rest of the batch "
                            f"({int(r['events'])} events, {int(r['failures'])} failures, {int(r['users'])} users). "
                            "This is an anomaly signal, not a confirmed threat.",
                            r["src_ip"], [], {"anomaly_score": round(float(r["score"]), 4), "window_start": str(r["win"]),
                                              "events": int(r["events"]), "failures": int(r["failures"])}, idx, "ml"))
    return scores, alerts, meta


def analyse(df: pd.DataFrame) -> dict:
    rules = rule_alerts(df)
    scores, ml_alerts, meta = ml_anomalies(df)
    rule_ips = {a.src_ip for a in rules}
    best = {}
    for a in ml_alerts:                                   # one ML alert per IP, strongest window wins
        if a.src_ip not in rule_ips and (a.src_ip not in best or a.evidence["anomaly_score"] > best[a.src_ip].evidence["anomaly_score"]):
            best[a.src_ip] = a
    ml_alerts = list(best.values())
    alerts = rules + ml_alerts
    flagged = set()
    for a in alerts:
        flagged.update(a.event_idx)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: order[a.severity])
    return {"alerts": [a.dict() for a in alerts], "flagged_event_idx": sorted(flagged), "anomaly_scores": scores,
            "ml_meta": meta, "summary": {"events": int(len(df)),
                                          "failed_logins": int(((df["outcome"] == "failure") & (df["event_type"] == "login")).sum()),
                                          "unique_ips": int(df["src_ip"].nunique()), "alerts": len(alerts)}}
