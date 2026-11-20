"""JSON, CSV and Markdown reporting for evidence documents."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from .schema import EvidenceDocument


def load_document(path: str | Path) -> EvidenceDocument:
    """Load and validate a JSON evidence document."""
    return EvidenceDocument.model_validate_json(Path(path).read_text(encoding="utf-8"))


def write_json(document: EvidenceDocument, path: str | Path) -> None:
    """Write a validated evidence document as JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document.model_dump_json(indent=2), encoding="utf-8")


def markdown(document: EvidenceDocument) -> str:
    """Render evidence metrics as a human-readable Markdown table."""
    rows = [
        "# PQC migration measurement report",
        "",
        "| Target | Requested | Negotiated | Metric | Value | Unit | Evidence |",
        "|---|---|---|---|---:|---|---|",
    ]
    for record in document.records:
        for metric in record.metrics:
            value = "Not measured" if metric.value is None else str(metric.value)
            rows.append(
                f"| {record.target}:{record.port} | {record.requested_group} | "
                f"{record.negotiated_group or 'Unverified'} | {metric.name} | {value} | "
                f"{metric.unit} | {metric.label.value} |"
            )

    rows.extend(["", "## Not-measured reasons", ""])
    for record in document.records:
        for metric in record.metrics:
            if metric.not_measured_reason:
                rows.append(f"- **{metric.name}:** {metric.not_measured_reason}")
    return "\n".join(rows) + "\n"


def write_csv(document: EvidenceDocument, path: str | Path) -> None:
    """Write one CSV row per metric while retaining evidence metadata."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "record_id",
        "target",
        "requested_group",
        "negotiated_group",
        "metric",
        "value",
        "unit",
        "label",
        "baseline",
        "path",
        "method",
        "limits",
        "source",
        "not_measured_reason",
    ]
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in document.records:
            for metric in record.metrics:
                writer.writerow(
                    {
                        "record_id": record.id,
                        "target": record.target,
                        "requested_group": record.requested_group,
                        "negotiated_group": record.negotiated_group,
                        "metric": metric.name,
                        "value": metric.value,
                        "unit": metric.unit,
                        "label": metric.label.value,
                        "baseline": metric.baseline,
                        "path": metric.path,
                        "method": metric.method,
                        "limits": "; ".join(metric.limits),
                        "source": metric.source,
                        "not_measured_reason": metric.not_measured_reason,
                    }
                )


def compare_values(baseline: float, candidate: float) -> dict[str, Any]:
    """Return arithmetic comparison explicitly labeled as calculated."""
    return {
        "baseline": baseline,
        "candidate": candidate,
        "delta": candidate - baseline,
        "label": "Calculated",
    }
