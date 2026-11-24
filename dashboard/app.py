import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from database.models import (
    get_incidents,
    initialize_db,
    get_incident_alerts,
    get_alert_evidence_events,
    update_incident_status,
    add_incident_note,
    get_incident_notes,
    get_incident_timeline,
    
)
from reporting.report_generator import (
    generate_json_report,
    generate_pdf_report,
)
from intelligence.scoring import calculate_incident_score


st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide"
)


def display_json(value):
    """Display JSON whether the database returned a string or object."""

    if value is None:
        st.info("No data available.")
        return

    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            st.code(value)
            return

    st.json(value)


def display_evidence_event(event):
    """Display the original security event behind an alert."""

    st.markdown(
        f"**Event #{event['id']} — {event['event_type']}**"
    )

    fields = [
        ("Timestamp", event.get("timestamp")),
        ("Source", event.get("source")),
        ("Hostname", event.get("host")),
        ("Username", event.get("username")),
        ("Source IP", event.get("source_ip")),
        ("Destination IP", event.get("destination_ip")),
        ("Process", event.get("process")),
        ("Command Line", event.get("command_line")),
        ("Status", event.get("status")),
    ]

    available_fields = [
        {"Field": name, "Observed Value": value}
        for name, value in fields
        if value not in (None, "")
    ]

    if available_fields:
        st.dataframe(
            available_fields,
            use_container_width=True,
            hide_index=True
        )

    with st.expander("View original raw event"):
        display_json(event.get("raw_event"))


def main():
    initialize_db()

    st.title("🛡️ ThreatLens")
    st.caption("Automated Threat Detection & Intelligence Platform")

    # --------------------------------------------------
    # SECURITY OVERVIEW
    # --------------------------------------------------

    incidents = get_incidents()

    total_incidents = len(incidents)

    critical = sum(
        incident["priority"] == "critical"
        for incident in incidents
    )

    high = sum(
        incident["priority"] == "high"
        for incident in incidents
    )

    open_incidents = sum(
        incident["status"] == "open"
        for incident in incidents
    )

    st.subheader("Security Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Incidents", total_incidents)
    col2.metric("Critical Incidents", critical)
    col3.metric("High Priority", high)
    col4.metric("Open Incidents", open_incidents)

    st.divider()

    # --------------------------------------------------
    # INCIDENT QUEUE
    # --------------------------------------------------

    st.subheader("Incident Queue")

    if not incidents:
        st.info("No incidents found. Run the detection pipeline first.")
        return

    st.markdown("### Filter Incidents")

    col1, col2, col3 = st.columns(3)

    with col1:
        priority_filter = st.selectbox(
            "Priority",
            options=["All", "Critical", "High", "Medium", "Low"]
        )

    with col2:
        status_filter = st.selectbox(
            "Status",
            options=[
                "All",
                "Open",
                "Investigating",
                "Resolved",
                "False Positive"
            ]
        )

    with col3:
        sort_order = st.selectbox(
            "Sort by",
            options=[
                "Highest Risk First",
                "Lowest Risk First",
                "Newest First",
                "Oldest First"
            ]
        )

    filtered_incidents = incidents.copy()

    if priority_filter != "All":
        filtered_incidents = [
            incident for incident in filtered_incidents
            if incident["priority"].lower()
            == priority_filter.lower()
        ]

    if status_filter != "All":
        filtered_incidents = [
            incident for incident in filtered_incidents
            if incident["status"].lower()
            == status_filter.lower().replace(" ", "_")
        ]

    if sort_order == "Highest Risk First":
        filtered_incidents.sort(
            key=lambda incident: incident["priority_score"],
            reverse=True
        )

    elif sort_order == "Lowest Risk First":
        filtered_incidents.sort(
            key=lambda incident: incident["priority_score"]
        )

    elif sort_order == "Newest First":
        filtered_incidents.sort(
            key=lambda incident: incident["created_at"],
            reverse=True
        )

    elif sort_order == "Oldest First":
        filtered_incidents.sort(
            key=lambda incident: incident["created_at"]
        )

    st.caption(
        f"Showing {len(filtered_incidents)} "
        f"of {len(incidents)} incidents"
    )

    incident_table = [
        {
            "ID": incident["id"],
            "Title": incident["title"],
            "Priority": incident["priority"].upper(),
            "Score": f"{incident['priority_score']}/90",
            "Status": incident["status"].replace("_", " ").upper(),
            "Alerts": incident["alert_count"],
            "Created": incident["created_at"],
        }
        for incident in filtered_incidents
    ]

    st.dataframe(
        incident_table,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # --------------------------------------------------
    # INCIDENT SELECTION
    # --------------------------------------------------

    st.subheader("Incident Investigation")

    if not filtered_incidents:
        st.info("No incidents match your selected filters.")
        return

    incident_options = {
        f"#{incident['id']} - {incident['title']}": incident["id"]
        for incident in filtered_incidents
    }

    selected_label = st.selectbox(
        "Select an incident to investigate",
        options=list(incident_options.keys())
    )

    selected_id = incident_options[selected_label]

    selected_incident = next(
        incident
        for incident in incidents
        if incident["id"] == selected_id
    )

    st.markdown(f"### {selected_incident['title']}")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Priority",
        selected_incident["priority"].upper()
    )

    col2.metric(
        "Risk Score",
        f"{selected_incident['priority_score']}/90"
    )

    col3.metric(
        "Related Alerts",
        selected_incident["alert_count"]
    )

    st.write("**Description:**")
    st.write(
        selected_incident["description"]
        or "No description available."
    )

    st.write("**Status:**", selected_incident["status"].upper())

    # --------------------------------------------------
    # INCIDENT LIFECYCLE
    # --------------------------------------------------

    st.markdown("### Incident Lifecycle")

    valid_statuses = [
        "open",
        "investigating",
        "resolved",
        "false_positive"
    ]

    current_status = selected_incident["status"]

    new_status = st.selectbox(
        "Update incident status",
        options=valid_statuses,
        index=valid_statuses.index(current_status),
        format_func=lambda status: status.replace("_", " ").title(),
        key=f"status_{selected_id}"
    )

    if st.button("Save Status", key=f"save_status_{selected_id}"):

        if new_status != current_status:

            update_incident_status(
                incident_id=selected_id,
                new_status=new_status
            )

            st.success("Incident status updated successfully.")
            st.rerun()

        else:
            st.info("No status changes were made.")

    st.divider()

    # --------------------------------------------------
    # ANALYST NOTES
    # --------------------------------------------------

    st.markdown("### Analyst Notes")

    notes = get_incident_notes(selected_id)

    if notes:
        for note in notes:
            with st.container(border=True):
                st.caption(f"Added: {note['created_at']}")
                st.write(note["note"])
    else:
        st.info("No investigation notes have been added yet.")

    with st.form(key=f"note_form_{selected_id}"):

        note_text = st.text_area(
            "Document your investigation",
            placeholder=(
                "Example: Reviewed the destination IP against "
                "external threat intelligence sources..."
            )
        )

        submitted = st.form_submit_button(
            "Save Investigation Note"
        )

        if submitted:

            if note_text.strip():

                add_incident_note(
                    incident_id=selected_id,
                    note=note_text.strip()
                )

                st.success("Investigation note saved.")
                st.rerun()

            else:
                st.warning("Please enter a note before saving.")

    st.divider()

    # --------------------------------------------------
    # INCIDENT TIMELINE
    # --------------------------------------------------

    st.markdown("### Incident Timeline")

    timeline = get_incident_timeline(selected_id)

    if timeline:

        for activity in timeline:

            activity_type = activity["activity_type"]

            if activity_type == "created":
                icon = "🆕"
            elif activity_type == "status_changed":
                icon = "🔄"
            elif activity_type == "note_added":
                icon = "📝"
            elif activity_type == "incident_merged":
                icon = "🔀"
            else:
                icon = "📌"

            with st.container(border=True):

                st.write(
                    f"{icon} **{activity_type.replace('_', ' ').title()}**"
                )

                st.caption(activity["created_at"])
                st.write(activity["description"])

    else:
        st.info("No activity history available for this incident.")

    st.divider()

    # --------------------------------------------------
    # INCIDENT REPORT EXPORT
    # --------------------------------------------------

    st.markdown("### Export Incident Report")

    st.write(
        "Download a structured JSON report or a formatted PDF "
        "containing the incident investigation details."
    )

    try:
        json_report = generate_json_report(selected_id)
        pdf_report = generate_pdf_report(selected_id)

        col1, col2 = st.columns(2)

        with col1:
            st.download_button(
                label="Download JSON Report",
                data=json_report,
                file_name=f"threatlens_incident_{selected_id}.json",
                mime="application/json",
                use_container_width=True,
            )

        with col2:
            st.download_button(
                label="Download PDF Report",
                data=pdf_report,
                file_name=f"threatlens_incident_{selected_id}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    except Exception as error:
        st.error(f"Could not generate incident report: {error}")

    st.divider()

    # --------------------------------------------------
    # RELATED ALERTS
    # --------------------------------------------------

    st.markdown("### Related Alerts")

    alerts = get_incident_alerts(selected_id)

    if not alerts:
        st.info("No alerts associated with this incident.")
        return

    # --------------------------------------------------
    # RISK SCORE BREAKDOWN
    # --------------------------------------------------

    scoring_result = calculate_incident_score(alerts)

    st.markdown("### Risk Score Breakdown")

    breakdown = scoring_result["breakdown"]

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Severity", f"{breakdown['severity']}/40")
    col2.metric("Alert Volume", f"{breakdown['alert_volume']}/15")

    col3.metric(
        "Threat Intelligence",
        f"{breakdown['threat_intelligence']}/25"
    )

    col4.metric("MITRE ATT&CK", f"{breakdown['mitre']}/10")

    st.caption(
        f"Recalculated score: {scoring_result['score']}/90 "
        f"| Priority: {scoring_result['priority'].upper()}"
    )

    st.divider()

    # --------------------------------------------------
    # ALERT INVESTIGATION AND ORIGINAL EVIDENCE
    # --------------------------------------------------

    for alert in alerts:

        with st.expander(
            f"{alert['severity'].upper()} — "
            f"{alert['rule_name']} (Alert #{alert['id']})"
        ):

            st.markdown("#### Detection Details")

            st.write("**Rule ID:**", alert["rule_id"])
            st.write("**Rule Name:**", alert["rule_name"])
            st.write("**Detection Description:**", alert["description"])

            st.caption(
                "This section describes the detection rule's conclusion, "
                "not an independent confirmation of malicious activity."
            )

            st.divider()

            # Original events
            st.markdown("#### Observed Evidence")

            evidence_events = get_alert_evidence_events(alert["id"])

            st.caption(
                f"{len(evidence_events)} original event(s) retrieved "
                f"for this alert."
            )

            if evidence_events:

                for event in evidence_events:

                    with st.container(border=True):
                        display_evidence_event(event)

            else:
                st.warning(
                    "No original event records could be retrieved "
                    "for this alert."
                )

            st.divider()

            # Threat intelligence
            st.markdown("#### Threat Intelligence Enrichment")

            display_json(alert["enrichment_json"])

            st.divider()

            # MITRE ATT&CK
            st.markdown("#### MITRE ATT&CK Mapping")

            st.write(
                "**Tactic:**",
                alert["mitre_tactic"] or "No tactic mapped"
            )

            st.write(
                "**Technique ID:**",
                alert["mitre_technique_id"] or "No technique mapped"
            )

            st.write(
                "**Technique:**",
                alert["mitre_technique"] or "No technique description"
            )


if __name__ == "__main__":
    main()
