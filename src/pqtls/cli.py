"""Typer command-line interface for evidence-first TLS measurements."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import typer
from rich import print

from .audit import append_audit_event, verify_audit_log
from .capture import CaptureError, CaptureTimeoutError, measure_live
from .config import load_settings
from .pcap import PcapError, analyze_pcap
from .report import compare_values, load_document, markdown, write_csv, write_json
from .schema import EvidenceDocument
from .structured_logging import configure_logging

app = typer.Typer(no_args_is_help=True, help="Evidence-first TLS 1.3 PQC migration measurements.")
configure_logging()
logger = logging.getLogger("pqtls")


@app.command()
def measure(
    host: str | None = typer.Option(None, help="TLS server hostname or IP address."),
    port: int | None = typer.Option(None, min=1, max=65535),
    group: str = typer.Option("X25519", help="OpenSSL supported TLS group."),
    timeout: float | None = typer.Option(None, min=0.1, max=300),
    out: Path | None = typer.Option(None),
    config: Path | None = typer.Option(None, "--config", help="YAML operator configuration."),
) -> None:
    """Capture one real connection with local OpenSSL and append an audit event."""
    try:
        settings = load_settings(
            config,
            overrides={
                key: value
                for key, value in {
                    "host": host,
                    "port": port,
                    "timeout_seconds": timeout,
                    "output_directory": out.parent if out else None,
                }.items()
                if value is not None
            },
        )
        target = settings.host
        if not target:
            raise ValueError("Set --host, host in YAML, or PQTLS_HOST.")
        output = out or settings.output_directory / "measurement.json"

        record = None
        for attempt in range(settings.retries + 1):
            try:
                record = measure_live(
                    target,
                    settings.port,
                    group,
                    settings.timeout_seconds,
                    openssl=settings.openssl_binary,
                    output_dir=str(settings.output_directory),
                )
                break
            except CaptureTimeoutError:
                if attempt >= settings.retries:
                    raise
                logger.warning(
                    "Transient OpenSSL timeout; retrying",
                    extra={"event": "capture_retry", "attempt": attempt + 1, "target": target},
                )
                time.sleep(min(2**attempt, 5))

        if record is None:
            raise CaptureError("Measurement did not produce a record")
        document = EvidenceDocument(records=[record])
        write_json(document, output)
        audit_hash = append_audit_event(
            settings.audit_log,
            {
                "event_type": "measurement_completed",
                "measurement_id": record.id,
                "target": record.target,
                "port": record.port,
                "evidence_file": str(output),
                "raw_transcript": record.raw_log_path,
                "metric_names": [metric.name for metric in record.metrics],
            },
        )
    except (CaptureError, ValueError, OSError) as exc:
        logger.exception("Measurement failed", extra={"event": "measurement_failed"})
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    logger.info(
        "Measurement completed",
        extra={
            "event": "measurement_completed",
            "measurement_id": record.id,
            "target": record.target,
            "duration_ms": record.duration_ms,
        },
    )
    print(f"[green]Evidence written:[/green] {output}")
    print(f"Negotiated group: {record.negotiated_group or 'unverified'}")
    print(f"Audit event hash: {audit_hash}")


@app.command("pcap")
def pcap_command(
    source: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False),
    out: Path = typer.Option(Path("results/pcap-analysis.json")),
    keylog: Path | None = typer.Option(None, help="TLS NSS key log; keep secret and mode 0600."),
    config: Path | None = typer.Option(None, "--config", help="YAML operator configuration."),
) -> None:
    """Analyze an offline PCAP with tshark; unavailable fields remain null."""
    try:
        settings = load_settings(config)
        result = analyze_pcap(source, settings.tshark_binary, keylog)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        digest = append_audit_event(
            settings.audit_log,
            {
                "event_type": "pcap_analysis_completed",
                "source": source.name,
                "output": str(out),
                "packet_count": result["packet_count"],
                "keylog_used": keylog is not None,
            },
        )
    except (PcapError, ValueError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    print(f"[green]PCAP analysis written:[/green] {out}")
    print(f"Audit event hash: {digest}")


@app.command("audit-verify")
def audit_verify(path: Path = typer.Option(Path("results/audit.jsonl"))) -> None:
    """Verify the SHA-256 audit chain without changing it."""
    result = verify_audit_log(path)
    print(json.dumps(result, indent=2))
    if not result["valid"]:
        raise typer.Exit(code=1)


@app.command()
def report(
    source: Path = typer.Argument(..., exists=True, readable=True),
    output_format: str = typer.Option("markdown", "--format"),
    out: Path = typer.Option(Path("report.md")),
) -> None:
    """Render a validated evidence JSON document."""
    document = load_document(source)
    if output_format == "markdown":
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown(document), encoding="utf-8")
    elif output_format == "csv":
        write_csv(document, out)
    elif output_format == "json":
        write_json(document, out)
    else:
        raise typer.BadParameter("format must be markdown, csv, or json")
    print(f"[green]Report written:[/green] {out}")


@app.command()
def compare(
    baseline: Path = typer.Argument(..., exists=True, readable=True),
    candidate: Path = typer.Argument(..., exists=True, readable=True),
    metric: str = typer.Option("client_process_duration"),
) -> None:
    """Compare named metrics only when both documents contain measured values."""
    left_document = load_document(baseline)
    right_document = load_document(candidate)

    def find_measured_value(document: EvidenceDocument) -> float:
        for record in document.records:
            for item in record.metrics:
                if (
                    item.name == metric
                    and item.value is not None
                    and item.label.value == "Measured"
                ):
                    return float(item.value)
        raise typer.BadParameter(f"No measured value for {metric!r}")

    result = compare_values(find_measured_value(left_document), find_measured_value(right_document))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    app()
