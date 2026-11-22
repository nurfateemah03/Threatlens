import json
from datetime import datetime, timezone
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
)

from database.models import (
    DEFAULT_DB_PATH,
    get_incidents,
    get_incident_alerts,
    get_alert_evidence_events,
    get_incident_notes,
    get_incident_timeline,
)

from intelligence.scoring import calculate_incident_score


def parse_json(value, fallback=None):
    """Safely decode JSON values retrieved from SQLite."""

    if fallback is None:
        fallback = {}

    if value is None:
        return fallback

    if isinstance(value, (dict, list)):
        return value

    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback

    return fallback


def build_incident_report(
    incident_id,
    db_path=DEFAULT_DB_PATH
):
    """
    Gather all available investigation data into one report structure.
    """

    incidents = get_incidents(db_path)

    incident = next(
        (
            item for item in incidents
            if item["id"] == incident_id
        ),
        None
    )

    if incident is None:
        raise ValueError(
            f"Incident {incident_id} was not found."
        )

    alerts = get_incident_alerts(
        incident_id,
        db_path
    )

    scoring = calculate_incident_score(alerts)

    report_alerts = []

    for alert in alerts:
        evidence_events = get_alert_evidence_events(
            alert["id"],
            db_path
        )

        enrichment = parse_json(
            alert.get("enrichment_json"),
            {}
        )

        for event in evidence_events:
            event["raw_event"] = parse_json(
                event.get("raw_event"),
                {}
            )

        report_alerts.append({
            "id": alert["id"],
            "rule_id": alert["rule_id"],
            "rule_name": alert["rule_name"],
            "severity": alert["severity"],
            "description": alert.get("description"),
            "username": alert.get("username"),
            "source_ip": alert.get("source_ip"),
            "destination_ip": alert.get("destination_ip"),
            "process": alert.get("process"),
            "command_line": alert.get("command_line"),
            "mitre": {
                "tactic": alert.get("mitre_tactic"),
                "technique_id": alert.get("mitre_technique_id"),
                "technique": alert.get("mitre_technique"),
            },
            "threat_intelligence": enrichment,
            "evidence_events": evidence_events,
            "created_at": alert.get("created_at"),
        })

    notes = get_incident_notes(
        incident_id,
        db_path
    )

    timeline = get_incident_timeline(
        incident_id,
        db_path
    )

    return {
        "report_metadata": {
            "platform": "ThreatLens",
            "report_type": "Incident Investigation Report",
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
        },
        "incident": {
            "id": incident["id"],
            "title": incident["title"],
            "description": incident.get("description"),
            "severity": incident["severity"],
            "priority": incident["priority"],
            "priority_score": incident["priority_score"],
            "status": incident["status"],
            "created_at": incident["created_at"],
            "updated_at": incident["updated_at"],
            "resolved_at": incident.get("resolved_at"),
            "alert_count": len(report_alerts),
        },
        "risk_assessment": scoring,
        "alerts": report_alerts,
        "analyst_notes": notes,
        "incident_timeline": timeline,
    }


def generate_json_report(
    incident_id,
    db_path=DEFAULT_DB_PATH
):
    """Generate a JSON incident report as UTF-8 bytes."""

    report = build_incident_report(
        incident_id,
        db_path
    )

    return json.dumps(
        report,
        indent=4,
        ensure_ascii=False,
        default=str
    ).encode("utf-8")


def generate_pdf_report(
    incident_id,
    db_path=DEFAULT_DB_PATH
):
    """Generate a formatted PDF incident report in memory."""

    report = build_incident_report(
        incident_id,
        db_path
    )

    incident = report["incident"]
    scoring = report["risk_assessment"]

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"ThreatLens Incident #{incident_id}",
        author="ThreatLens",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ThreatLensTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        spaceAfter=8,
    )

    section_style = ParagraphStyle(
        "ThreatLensSection",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=7,
    )

    body_style = styles["BodyText"]

    small_style = ParagraphStyle(
        "ThreatLensSmall",
        parent=body_style,
        fontSize=8,
        leading=10,
    )

    code_style = ParagraphStyle(
        "ThreatLensCode",
        fontName="Courier",
        fontSize=7,
        leading=9,
        leftIndent=5,
        rightIndent=5,
    )

    story = []

    def add_section(title):
        story.append(Paragraph(title, section_style))

    def add_table(rows, widths=None):
        table = Table(
            rows,
            colWidths=widths,
            repeatRows=1,
            hAlign="LEFT",
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#26364A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))

        story.append(table)
        story.append(Spacer(1, 6))

    story.append(
        Paragraph("ThreatLens", title_style)
    )

    story.append(
        Paragraph(
            "Incident Investigation Report",
            ParagraphStyle(
                "Subtitle",
                parent=body_style,
                alignment=TA_CENTER,
                fontSize=11,
            )
        )
    )

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        f"<b>Report generated:</b> "
        f"{report['report_metadata']['generated_at']}",
        body_style
    ))

    add_section("1. Incident Overview")

    add_table([
        ["Field", "Value"],
        ["Incident ID", str(incident["id"])],
        ["Title", incident["title"]],
        ["Description", incident.get("description") or "Not provided"],
        ["Severity", incident["severity"].upper()],
        ["Priority", incident["priority"].upper()],
        [
            "Risk Score",
            f"{incident['priority_score']}/90"
        ],
        ["Status", incident["status"].replace("_", " ").upper()],
        ["Related Alerts", str(incident["alert_count"])],
        ["Created At", incident["created_at"]],
        ["Last Updated", incident["updated_at"]],
        ["Resolved At", incident.get("resolved_at") or "Not resolved"],
    ], [45 * mm, 125 * mm])

    add_section("2. Risk Assessment")

    breakdown = scoring["breakdown"]

    add_table([
        ["Scoring Dimension", "Score"],
        ["Severity", f"{breakdown['severity']}/40"],
        ["Alert Volume", f"{breakdown['alert_volume']}/15"],
        [
            "Threat Intelligence",
            f"{breakdown['threat_intelligence']}/25"
        ],
        ["MITRE ATT&CK", f"{breakdown['mitre']}/10"],
        ["Total", f"{scoring['score']}/90"],
        ["Calculated Priority", scoring["priority"].upper()],
    ], [100 * mm, 70 * mm])

    add_section("3. Related Alerts")

    if not report["alerts"]:
        story.append(
            Paragraph("No alerts are associated with this incident.", body_style)
        )

    for alert in report["alerts"]:
        story.append(Paragraph(
            f"Alert #{alert['id']} — {alert['rule_name']}",
            styles["Heading3"]
        ))

        add_table([
            ["Field", "Value"],
            ["Rule ID", alert["rule_id"]],
            ["Severity", alert["severity"].upper()],
            ["Description", alert.get("description") or "Not provided"],
            ["Username", alert.get("username") or "Not available"],
            ["Source IP", alert.get("source_ip") or "Not available"],
            [
                "Destination IP",
                alert.get("destination_ip") or "Not available"
            ],
            ["Process", alert.get("process") or "Not available"],
            [
                "Command Line",
                alert.get("command_line") or "Not available"
            ],
            ["MITRE Tactic", alert["mitre"]["tactic"] or "Not mapped"],
            [
                "MITRE Technique ID",
                alert["mitre"]["technique_id"] or "Not mapped"
            ],
            [
                "MITRE Technique",
                alert["mitre"]["technique"] or "Not mapped"
            ],
        ], [45 * mm, 125 * mm])

        add_section("Observed Evidence")

        evidence_events = alert["evidence_events"]

        if not evidence_events:
            story.append(Paragraph(
                "No original evidence events could be retrieved.",
                body_style
            ))

        for event in evidence_events:
            event_fields = [
                ["Event Field", "Observed Value"],
                ["Event ID", str(event["id"])],
                ["Timestamp", event.get("timestamp") or "Not available"],
                ["Event Type", event.get("event_type") or "Not available"],
                ["Source", event.get("source") or "Not available"],
                ["Hostname", event.get("host") or "Not available"],
                ["Username", event.get("username") or "Not available"],
                ["Source IP", event.get("source_ip") or "Not available"],
                [
                    "Destination IP",
                    event.get("destination_ip") or "Not available"
                ],
                ["Process", event.get("process") or "Not available"],
                [
                    "Command Line",
                    event.get("command_line") or "Not available"
                ],
                ["Status", event.get("status") or "Not available"],
            ]

            add_table(event_fields, [45 * mm, 125 * mm])

            raw_event = json.dumps(
                event.get("raw_event", {}),
                indent=2,
                ensure_ascii=False,
                default=str,
            )

            story.append(Paragraph(
                "Original Raw Event",
                styles["Heading4"]
            ))

            story.append(
                Preformatted(raw_event, code_style)
            )
            story.append(Spacer(1, 8))

        add_section("Threat Intelligence Enrichment")

        enrichment_text = json.dumps(
            alert["threat_intelligence"],
            indent=2,
            ensure_ascii=False,
            default=str,
        )

        story.append(
            Preformatted(enrichment_text, code_style)
        )

    add_section("4. Analyst Notes")

    if report["analyst_notes"]:
        for note in report["analyst_notes"]:
            story.append(Paragraph(
                f"<b>{note['created_at']}</b>",
                small_style
            ))
            story.append(Paragraph(
                note["note"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
                body_style
            ))
            story.append(Spacer(1, 7))
    else:
        story.append(
            Paragraph("No analyst notes recorded.", body_style)
        )

    add_section("5. Incident Timeline")

    if report["incident_timeline"]:
        timeline_rows = [
            ["Timestamp", "Activity", "Description"]
        ]

        for activity in report["incident_timeline"]:
            timeline_rows.append([
                activity["created_at"],
                activity["activity_type"].replace("_", " ").title(),
                activity["description"],
            ])

        add_table(
            timeline_rows,
            [40 * mm, 40 * mm, 90 * mm]
        )
    else:
        story.append(
            Paragraph("No timeline activity recorded.", body_style)
        )

    story.append(Spacer(1, 12))

    story.append(Paragraph(
        "Analyst note: Detection alerts and threat-intelligence matches "
        "are investigative signals, not independent confirmation of "
        "malicious activity. Findings should be validated in context.",
        small_style
    ))

    document.build(story)

    return buffer.getvalue()