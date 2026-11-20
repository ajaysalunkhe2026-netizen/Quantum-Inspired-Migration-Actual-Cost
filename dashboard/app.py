"""Optional Streamlit viewer for validated evidence JSON."""

from pathlib import Path

import streamlit as st

from pqtls.report import load_document

st.set_page_config(page_title="PQC Migration Evidence", layout="wide")
st.title("PQC Migration Evidence")
st.caption(
    "Only values present in validated evidence files are shown. No demo data is generated."
)
uploaded = st.file_uploader("Upload an evidence JSON file", type=["json"])

if uploaded is None:
    st.info("Upload a JSON report produced by pqtls measure.")
else:
    temp = Path("/tmp/pqtls-dashboard-upload.json")
    temp.write_bytes(uploaded.getvalue())
    try:
        document = load_document(temp)
    except (OSError, ValueError) as exc:
        st.error(f"Invalid evidence document: {exc}")
    else:
        rows = []
        for record in document.records:
            for metric in record.metrics:
                rows.append(
                    {
                        "Target": f"{record.target}:{record.port}",
                        "Requested group": record.requested_group,
                        "Negotiated group": record.negotiated_group or "Unverified",
                        "Metric": metric.name,
                        "Value": metric.value,
                        "Unit": metric.unit,
                        "Evidence": metric.label.value,
                        "Not measured reason": metric.not_measured_reason or "",
                    }
                )
        st.dataframe(rows, use_container_width=True)
        st.caption("Null values are intentionally retained and are not interpreted as zero.")
