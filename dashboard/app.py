
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st

from database.models import (
    get_incidents,
    get_incident_alerts,
    update_incident_status,
    add_incident_note,
    get_incident_notes
)

from intelligence.scoring import calculate_incident_score


st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide"
)


def main():
    st.title("🛡️ ThreatLens")
    st.caption("Automated Threat Detection & Intelligence Platform")

    # Retrieve incidents from SQLite
    incidents = get_incidents()

    # Dashboard metrics
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

    # Incident queue
    st.subheader("Incident Queue")

    if not incidents:
        st.info("No incidents found. Run the detection pipeline first.")
        return

    # Incident filtering
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

    # Apply priority filter
    filtered_incidents = incidents.copy()

    if priority_filter != "All":
        filtered_incidents = [
            incident for incident in filtered_incidents
            if incident["priority"].lower() == priority_filter.lower()
        ]

    # Apply status filter
    if status_filter != "All":
        filtered_incidents = [
            incident for incident in filtered_incidents
            if incident["status"].lower()
            == status_filter.lower().replace(" ", "_")
        ]

    # Apply sorting
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

    # Display filtered incident queue
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

    # Incident investigation
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

    # Incident lifecycle management
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

    # Analyst notes
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

        submitted = st.form_submit_button("Save Investigation Note")

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

    # Related alerts
    st.markdown("### Related Alerts")

    alerts = get_incident_alerts(selected_id)

    scoring_result = calculate_incident_score(alerts)

    # Risk score breakdown
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

    # Alert investigation details
    if not alerts:
        st.info("No alerts associated with this incident.")

    else:
        for alert in alerts:

            with st.expander(
                f"{alert['severity'].upper()} — {alert['rule_name']}"
            ):

                st.write("**Rule ID:**", alert["rule_id"])
                st.write("**Description:**", alert["description"])

                st.write("**Evidence:**")
                st.json(alert["evidence_json"])

                st.write("**Threat Intelligence:**")
                st.json(alert["enrichment_json"])

                st.write("**MITRE Tactic:**")
                st.write(alert["mitre_tactic"] or "No tactic mapped")

                st.write("**MITRE Technique:**")
                st.write(
                    alert["mitre_technique_id"]
                    or "No technique mapped"
                )


if __name__ == "__main__":
    main()
