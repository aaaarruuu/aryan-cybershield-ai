"""PDF / CSV report export. Report content can contain attacker-controlled strings (email text, usernames),
so PDF text is XML-escaped and CSV cells are neutralised against spreadsheet formula injection."""
import csv
import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.config import PROJECT_AUTHOR, PROJECT_NAME


def csv_safe(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def investigation_csv(report: dict) -> bytes:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["section", "item", "detail", "verified"])
    w.writerow(["summary", "incident_summary", csv_safe(report.get("incident_summary")), ""])
    w.writerow(["summary", "risk", csv_safe(f"{report.get('risk_level')} ({report.get('risk_score')}/100)"), ""])
    for f in report.get("verified_findings", []):
        w.writerow(["finding", "verified_fact", csv_safe(f), "yes"])
    for h in report.get("ai_hypotheses", []):
        w.writerow(["finding", "hypothesis", csv_safe(h), "no"])
    for t in report.get("related_events_timeline", []):
        w.writerow(["timeline", csv_safe(t.get("time")), csv_safe(t.get("description")), "yes" if t.get("verified") else "no"])
    for a in report.get("recommended_actions", []):
        w.writerow(["recommended_action", csv_safe(a["action_type"]), csv_safe(a["target"] + " - " + a["rationale"]), ""])
    for a in report.get("approval_requests", []):
        w.writerow(["approval", csv_safe(a["action_type"]), csv_safe(f"{a['target']} [{a['status']}]"), ""])
    for t in report.get("possible_attack_techniques", []):
        w.writerow(["attack_technique", csv_safe(t["id"]), csv_safe(f"{t['name']} ({t['basis']})"), "no"])
    return out.getvalue().encode()


def incidents_csv(rows: list[dict]) -> bytes:
    out = io.StringIO()
    w = csv.writer(out)
    cols = ["incident_uid", "title", "severity", "status", "category", "source", "detected_at", "related_indicators", "resolution_notes"]
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe(r[c]) if c != "related_indicators" else csv_safe(", ".join(r[c])) for c in cols])
    return out.getvalue().encode()


def _p(text, style):
    return Paragraph(escape(str(text if text is not None else "")), style)


def investigation_pdf(report: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Investigation report {report.get('investigation_id')}", author=PROJECT_AUTHOR)
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9, leading=12)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=12, textColor=colors.HexColor("#0b3a6f"), spaceBefore=10)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.grey)
    el = [Paragraph(escape(PROJECT_NAME), ss["Title"]), _p(f"Investigation report #{report.get('investigation_id')} - {report.get('title')}", body),
          _p(f"Generated {report.get('generated_at')}  |  Project Developed By: {PROJECT_AUTHOR}", small), Spacer(1, 6)]

    def section(title, items, style=body, bullet=True):
        el.append(Paragraph(escape(title), h2))
        if not items:
            el.append(_p("None.", body))
        for i in items:
            el.append(_p(("- " if bullet else "") + str(i), style))

    section("Incident summary", [report.get("incident_summary")], bullet=False)
    section("Threat classification and risk", [f"Classification: {report.get('threat_classification')}", f"Risk: {report.get('risk_level')} ({report.get('risk_score')}/100)",
                                               report.get("risk_explanation")], bullet=False)
    section("Verified findings (observed facts)", report.get("verified_findings", []))
    section("AI-generated hypotheses (require analyst confirmation)", report.get("ai_hypotheses", []))
    section("Suspicious indicators", report.get("suspicious_indicators", []))
    section("Related events / timeline", [f"{t.get('time') or 'n/a'} - {t['description']}" + ("" if t.get("verified") else " [unverified]") for t in report.get("related_events_timeline", [])])
    section("Possible attack techniques (mapped, unverified)", [f"{t['id']} {t['name']} - {t['basis']}" for t in report.get("possible_attack_techniques", [])])
    el.append(Paragraph("Recommended actions", h2))
    acts = report.get("recommended_actions", [])
    if acts:
        data = [["Action", "Target", "Rationale"]] + [[_p(a["action_type"], body), _p(a["target"], body), _p(a["rationale"][:200], body)] for a in acts]
        t = Table(data, colWidths=[35 * mm, 40 * mm, 95 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe7f5")), ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        el.append(t)
    else:
        el.append(_p("None.", body))
    section("Knowledge-base support", [report.get("knowledge_note")] + [f"Source: {c}" for c in report.get("knowledge_citations", [])], bullet=False)
    section("Approval history", [f"#{a['id']} {a['action_type']} on {a['target']} - {a['status']}" for a in report.get("approval_requests", [])])
    section("Agent execution", [f"{a['agent']}: {a['status']} ({a['attempts']} attempt(s), {a['duration_ms']} ms)" + (f" - {a['error']}" if a.get("error") else "") for a in report.get("agent_execution", [])])
    section("Conclusion", [report.get("conclusion")], bullet=False)
    doc.build(el)
    return buf.getvalue()
