"""Phishing analysis: deterministic checks + bounded ML signal -> evidence-based verdict.

Design rules (see ARCHITECTURE.md):
* Every indicator is an observable fact extracted from the input, with the evidence string.
* The ML probability adds at most ML_MAX_POINTS and can never by itself produce a 'phishing' verdict:
  'phishing' needs >= 2 independent deterministic indicators.
* No LLM is involved in the verdict.
"""
import ipaddress
import re
from urllib.parse import urlparse

from app.ml import phishing_model

ML_MAX_POINTS = 25
BRANDS = {"paypal": "paypal.com", "microsoft": "microsoft.com", "google": "google.com", "apple": "apple.com",
          "amazon": "amazon.com", "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com",
          "linkedin": "linkedin.com", "dropbox": "dropbox.com", "docusign": "docusign.com", "dhl": "dhl.com",
          "fedex": "fedex.com", "hdfc": "hdfcbank.com", "icici": "icicibank.com", "paytm": "paytm.com", "sbi": "sbi.co.in"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "aol.com", "mail.com", "gmx.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
RISKY_TLDS = {"xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "zip", "mov", "support", "loan", "rest"}
SECOND_LEVEL = {"co", "com", "org", "gov", "ac", "net", "edu"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})

URGENCY = re.compile(r"\b(urgent(ly)?|immediately|right away|within \d+ (hours?|minutes?)|expires? (today|soon|in)|final (notice|warning)|act now|last chance|asap)\b", re.I)
CREDENTIALS = re.compile(r"\b(verify|confirm|update|validate|reset)\b.{0,40}\b(password|account|identity|login|credentials?|bank|card|payment|security answers?)\b|\b(enter|provide|send|reply with)\b.{0,30}\b(password|pin|otp|card (number|details)|credentials?|ssn)\b", re.I)
THREAT = re.compile(r"\b(suspend(ed)?|locked|limited|terminated|closed|legal action|penalt(y|ies)|unauthori[sz]ed (access|activity))\b", re.I)
REWARD = re.compile(r"\b(won|winner|prize|gift card|reward|refund|congratulations|selected)\b", re.I)
GENERIC = re.compile(r"^\s*(dear (customer|user|client|member|account holder)|hello user|valued customer)\b", re.I | re.M)


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _ind(id_, category, points, summary, evidence):
    return {"id": id_, "category": category, "points": points, "summary": summary, "evidence": evidence, "verified": True}


def _email_domain(addr: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def _lookalike(domain: str):
    """Return (brand, why) if `domain` imitates a brand's official domain."""
    reg = registrable(domain)
    label = reg.split(".")[0]
    norm = label.translate(LEET).replace("rn", "m").replace("vv", "w")
    for brand, official in BRANDS.items():
        if reg == official:
            return None
    for brand, official in BRANDS.items():
        if len(brand) >= 4 and brand in norm and label != brand:
            return brand, f"'{reg}' resembles {official} using character substitution"
        if len(brand) >= 4 and brand in label and reg != official:
            return brand, f"'{reg}' embeds the brand name '{brand}' but is not {official}"
    return None


def check_sender(sender: str, metadata: dict) -> list:
    out = []
    dom = _email_domain(sender)
    if not dom:
        if sender:
            out.append(_ind("sender_malformed", "sender", 10, "Sender address is not a valid email address", sender[:120]))
        return out
    look = _lookalike(dom)
    if look:
        out.append(_ind("sender_lookalike", "impersonation", 30, f"Sender domain imitates {look[0]}", look[1]))
    tld = dom.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        out.append(_ind("sender_risky_tld", "sender", 10, "Sender uses a TLD frequently abused in phishing", f".{tld}"))
    display = str(metadata.get("display_name", ""))
    if display and dom in FREE_MAIL:
        for brand in BRANDS:
            if brand in display.lower():
                out.append(_ind("display_name_brand_freemail", "impersonation", 25,
                                f"Display name claims {brand} but sender uses a free mail provider", f"{display} <{sender}>"))
                break
    reply_to = _email_domain(str(metadata.get("reply_to", "")))
    if reply_to and registrable(reply_to) != registrable(dom):
        out.append(_ind("reply_to_mismatch", "sender", 20, "Reply-To domain differs from sender domain", f"from {dom}, reply-to {reply_to}"))
    for k in ("spf", "dkim", "dmarc"):
        if str(metadata.get(k, "")).lower() in {"fail", "softfail", "none"}:
            out.append(_ind(f"auth_{k}_fail", "sender", 15, f"{k.upper()} authentication did not pass", f"{k}={metadata[k]}"))
    return out


def check_language(subject: str, body: str) -> list:
    text = f"{subject}\n{body}"
    out = []
    for rx, id_, pts, summary in [(URGENCY, "lang_urgency", 8, "Urgency / time-pressure language"),
                                  (CREDENTIALS, "lang_credential_request", 18, "Requests credentials or sensitive information"),
                                  (THREAT, "lang_threat", 10, "Threatens account suspension or penalties"),
                                  (REWARD, "lang_reward", 8, "Reward / prize / refund lure")]:
        m = rx.search(text)
        if m:
            out.append(_ind(id_, "social_engineering", pts, summary, m.group(0)[:100]))
    if GENERIC.search(body):
        out.append(_ind("lang_generic_greeting", "social_engineering", 5, "Generic greeting instead of a personal name", GENERIC.search(body).group(0).strip()))
    return out


def check_url(url: str, sender_domain: str = "") -> list:
    out = []
    try:
        u = urlparse(url if "://" in url else "http://" + url)
        host = (u.hostname or "").lower()
    except ValueError:
        return [_ind("url_malformed", "url", 10, "URL could not be parsed", url[:120])]
    if not host:
        return [_ind("url_malformed", "url", 10, "URL has no host", url[:120])]
    try:
        ipaddress.ip_address(host)
        out.append(_ind("url_ip_host", "url", 25, "URL uses a raw IP address instead of a domain", url[:120]))
        return out
    except ValueError:
        pass
    if u.scheme == "http":
        out.append(_ind("url_no_tls", "url", 8, "Link does not use HTTPS", url[:120]))
    if "@" in (u.netloc or ""):
        out.append(_ind("url_userinfo", "url", 25, "URL contains '@' which can hide the real destination", u.netloc[:120]))
    if "xn--" in host:
        out.append(_ind("url_punycode", "url", 20, "Punycode (possible homograph) domain", host))
    reg = registrable(host)
    if reg in SHORTENERS:
        out.append(_ind("url_shortener", "url", 12, "URL shortener hides the destination", host))
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        out.append(_ind("url_risky_tld", "url", 12, "TLD frequently abused in phishing", f".{tld}"))
    if host.count(".") >= 4:
        out.append(_ind("url_many_subdomains", "url", 10, "Unusually deep subdomain nesting", host))
    look = _lookalike(host)
    if look:
        out.append(_ind("url_lookalike", "impersonation", 30, f"Link domain imitates {look[0]}", look[1]))
    else:  # brand named in a subdomain/path of an unrelated domain, e.g. paypal.com.evil.xyz
        for brand, official in BRANDS.items():
            sub = host.replace(reg, "").translate(LEET) + "."
            if reg != official and len(brand) >= 4 and (brand + ".") in sub.replace("-", ".") + ".":
                out.append(_ind("url_brand_in_subdomain", "impersonation", 25, f"'{brand}' appears in the subdomain of an unrelated domain", host))
                break
    if sender_domain and reg != registrable(sender_domain) and reg not in SHORTENERS:
        out.append(_ind("url_sender_mismatch", "url", 5, "Link domain differs from the sender's domain", f"{reg} vs {registrable(sender_domain)}"))
    return out


def _risk(score: int) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"


def analyse(subject: str = "", sender: str = "", body: str = "", urls: list | None = None, metadata: dict | None = None) -> dict:
    metadata = metadata or {}
    urls = list(dict.fromkeys((urls or []) + re.findall(r"https?://[^\s<>\"')]+", body or "")))[:50]
    sender_dom = _email_domain(sender)
    indicators = check_sender(sender, metadata) + check_language(subject, body)
    for u in urls:
        for i in check_url(u, sender_dom):
            i["evidence"] = f"{i['evidence']}  [url: {u[:80]}]" if u[:60] not in i["evidence"] else i["evidence"]
            indicators.append(i)
    # collapse duplicate ids from many URLs but keep points bounded per id
    seen, deduped = {}, []
    for i in indicators:
        if i["id"] in seen:
            seen[i["id"]]["evidence"] += f" | {i['evidence']}"[:300]
            continue
        seen[i["id"]] = i
        deduped.append(i)
    det = min(100, sum(i["points"] for i in deduped))
    ml = phishing_model.predict(f"{subject} {body}".strip() or " ")
    ml_points = round(ml["phishing_probability"] * ML_MAX_POINTS) if (subject or body) else 0
    score = min(100, det + ml_points)
    significant = [i for i in deduped if i["points"] >= 8 and i["id"] not in ("url_sender_mismatch",)]
    if score >= 60 and len(significant) >= 2:
        cls = "phishing"
    elif score >= 30:
        cls = "suspicious"
    else:
        cls = "legitimate"
    if cls == "legitimate" or (cls == "suspicious" and score < 60):
        risk = _risk(score) if cls != "legitimate" else "low"
    else:
        risk = _risk(score)
    if cls == "phishing" and risk == "low":
        risk = "high"
    agree = (ml["label"] == "phishing") == (cls != "legitimate")
    confidence = round(min(0.97, 0.5 + abs(score - 45) / 110 + (0.08 if agree else -0.05)), 2)
    if cls == "legitimate":
        explanation = ("No strong phishing indicators were found." if not deduped else
                       f"Only weak indicators were found ({len(deduped)}); not enough to classify as phishing.")
    else:
        top = sorted(deduped, key=lambda i: -i["points"])[:3]
        explanation = (f"Classified as {cls} because of {len(deduped)} observable indicator(s), mainly: "
                       + "; ".join(i["summary"] for i in top) + ".")
    explanation += f" The ML text model estimated a phishing probability of {ml['phishing_probability']:.0%} (supporting signal only, worth at most {ML_MAX_POINTS} points)."
    steps = {"phishing": ["Do not click links or open attachments; quarantine the message.", "Report to the security team and block the sender/URL domains after approval.",
                          "Check whether any recipient clicked or submitted credentials; reset those passwords and revoke sessions.", "Search mail logs for the same sender or URLs."],
             "suspicious": ["Verify the sender through a separate trusted channel before acting.", "Do not enter credentials via the links; navigate to the site directly.",
                            "Look up the URLs/domains in the Threat Intelligence page."],
             "legitimate": ["No action required; remain cautious with unexpected requests."]}[cls]
    return {"classification": cls, "confidence": confidence, "risk_level": risk, "risk_score": score,
            "deterministic_score": det, "ml": {**ml, "points_contributed": ml_points, "model": "tfidf-logreg"},
            "indicators": deduped, "urls_analysed": urls, "explanation": explanation, "recommended_next_steps": steps,
            "limitations": "Heuristic + ML analysis of the supplied text only; headers/attachments are not inspected unless provided in metadata."}
