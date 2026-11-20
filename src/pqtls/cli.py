"""Typer CLI."""
from __future__ import annotations
import json
import logging
from pathlib import Path
import typer
from rich import print
from .capture import CaptureError, measure_live
from .report import compare_values, load_document, markdown, write_csv, write_json
from .schema import EvidenceDocument

app = typer.Typer(no_args_is_help=True, help="Evidence-first TLS 1.3 PQC migration measurements.")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

@app.command()
def measure(host: str = typer.Option(...), port: int = typer.Option(443, min=1, max=65535),
            group: str = typer.Option("X25519"), timeout: float = typer.Option(15.0, min=1.0),
            out: Path = typer.Option(Path("results/measurement.json"))) -> None:
    """Capture one real connection with local OpenSSL."""
    try:
        record = measure_live(host, port, group, timeout)
    except CaptureError as exc:
        typer.echo(str(exc), err=True); raise typer.Exit(code=2) from exc
    doc = EvidenceDocument(records=[record]); write_json(doc, out)
    print(f"[green]Evidence written:[/green] {out}")
    print(f"Negotiated group: {record.negotiated_group or 'unverified'}")

@app.command()
def report(source: Path = typer.Argument(..., exists=True, readable=True),
           format: str = typer.Option("markdown"), out: Path = typer.Option(Path("report.md"))) -> None:
    """Render a validated evidence JSON document."""
    doc = load_document(source)
    if format == "markdown": out.write_text(markdown(doc), encoding="utf-8")
    elif format == "csv": write_csv(doc, out)
    elif format == "json": write_json(doc, out)
    else: raise typer.BadParameter("format must be markdown, csv, or json")
    print(f"[green]Report written:[/green] {out}")

@app.command()
def compare(baseline: Path = typer.Argument(..., exists=True, readable=True),
            candidate: Path = typer.Argument(..., exists=True, readable=True),
            metric: str = typer.Option("client_process_duration")) -> None:
    """Compare named metrics only when both documents contain measured values."""
    left, right = load_document(baseline), load_document(candidate)
    def find(doc: EvidenceDocument) -> float:
        for record in doc.records:
            for item in record.metrics:
                if item.name == metric and item.value is not None and item.label.value == "Measured":
                    return float(item.value)
        raise typer.BadParameter(f"No measured value for {metric!r}")
    print(json.dumps(compare_values(find(left), find(right)), indent=2))

if __name__ == "__main__": app()
