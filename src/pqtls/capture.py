"""Live TLS capture using OpenSSL s_client. Does not infer packet metrics."""

from __future__ import annotations

import base64
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from .schema import EvidenceLabel, HandshakeRecord, Metric

PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
NEGOTIATED = (
    re.compile(r"Negotiated TLS1?\.3 group:\s*([A-Za-z0-9_-]+)", re.IGNORECASE),
    re.compile(r"Server Temp Key:\s*([^\r\n]+)", re.IGNORECASE),
)


class CaptureError(RuntimeError):
    """OpenSSL capture failure."""


class CaptureTimeoutError(CaptureError):
    """OpenSSL capture exceeded its configured timeout."""


def _cert_der(text: str) -> list[bytes]:
    certificates: list[bytes] = []
    for block in PEM_CERT.findall(text):
        body = re.sub(r"-----[^-]+-----|\s+", "", block)
        certificates.append(base64.b64decode(body, validate=True))
    return certificates


def _normalise_group(value: str) -> str:
    """Return the group token, excluding OpenSSL's optional key-size annotation."""
    return value.split(",", maxsplit=1)[0].strip().split(maxsplit=1)[0]


def measure_live(
    host: str,
    port: int = 443,
    group: str = "X25519",
    timeout: float = 15.0,
    openssl: str = "openssl",
    output_dir: str = "results",
) -> HandshakeRecord:
    """Run OpenSSL against a live host and preserve the raw diagnostic transcript."""
    binary = shutil.which(openssl)
    if not binary:
        raise CaptureError(f"OpenSSL executable not found: {openssl}")

    version_proc = subprocess.run(
        [binary, "version"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if version_proc.returncode:
        raise CaptureError(version_proc.stderr.strip() or "Cannot query OpenSSL version")

    command = [
        binary,
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-tls1_3",
        "-groups",
        group,
        "-msg",
        "-trace",
        "-showcerts",
        "-brief",
    ]
    started = time.perf_counter()
    try:
        process = subprocess.run(
            command,
            input="\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CaptureTimeoutError(f"OpenSSL timed out after {timeout}s") from exc

    duration_ms = (time.perf_counter() - started) * 1000
    transcript = process.stdout + "\n" + process.stderr
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / f"{host.replace(':', '_')}-{uuid.uuid4().hex[:8]}.openssl.txt"
    artifact.write_text(transcript, encoding="utf-8")

    negotiated_group = None
    for pattern in NEGOTIATED:
        match = pattern.search(transcript)
        if match:
            negotiated_group = _normalise_group(match.group(1))
            break

    certificates = _cert_der(transcript)
    baseline = f"{host}:{port}; requested_group={group}"
    shared = {"baseline": baseline}
    metrics = [
        Metric(
            name="certificate_chain_der_bytes",
            value=sum(map(len, certificates)) if certificates else None,
            unit="bytes",
            label=(
                EvidenceLabel.MEASURED if certificates else EvidenceLabel.NOT_MEASURED
            ),
            path="live TCP/TLS connection",
            method="Sum DER lengths decoded from peer PEM certificates in s_client output",
            limits=[
                "Peer-emitted chain only; root may be omitted.",
                "Excludes TLS Certificate message and record framing.",
            ],
            source=str(artifact) if certificates else None,
            not_measured_reason=(
                None if certificates else "No parseable PEM certificates in OpenSSL output"
            ),
            **shared,
        ),
        Metric(
            name="client_key_share_bytes",
            value=None,
            unit="bytes",
            label=EvidenceLabel.NOT_MEASURED,
            path="TLS 1.3 ClientHello",
            method="OpenSSL trace; no stable parser enabled",
            limits=["Requested group is not a measured key-share length."],
            not_measured_reason="Not parsed from this OpenSSL build's diagnostic output.",
            **shared,
        ),
        Metric(
            name="server_key_share_bytes",
            value=None,
            unit="bytes",
            label=EvidenceLabel.NOT_MEASURED,
            path="TLS 1.3 ServerHello",
            method="OpenSSL trace; no stable parser enabled",
            limits=["Selected group and server key-share length are distinct fields."],
            not_measured_reason="Not parsed from this OpenSSL build's diagnostic output.",
            **shared,
        ),
        Metric(
            name="certificate_verify_signature_bytes",
            value=None,
            unit="bytes",
            label=EvidenceLabel.NOT_MEASURED,
            path="encrypted TLS 1.3 handshake",
            method="Decrypted handshake parser required",
            limits=["TLS 1.3 CertificateVerify is encrypted after ServerHello."],
            not_measured_reason="No reliable decoded CertificateVerify vector available.",
            **shared,
        ),
        Metric(
            name="handshake_message_bytes",
            value=None,
            unit="bytes",
            label=EvidenceLabel.NOT_MEASURED,
            path="TLS handshake messages",
            method="Serialized handshake parser required",
            limits=["Diagnostic text length is not serialized handshake length."],
            not_measured_reason="Not measured by the OpenSSL text adapter.",
            **shared,
        ),
        Metric(
            name="tls_record_bytes",
            value=None,
            unit="bytes",
            label=EvidenceLabel.NOT_MEASURED,
            path="TCP stream",
            method="Packet capture and TLS record accounting required",
            limits=["Requires capture-point and reassembly policy."],
            not_measured_reason="No packet capture was taken.",
            **shared,
        ),
        Metric(
            name="tcp_ip_bytes",
            value=None,
            unit="bytes",
            label=EvidenceLabel.NOT_MEASURED,
            path="network interface",
            method="PCAP packet accounting required",
            limits=[
                "Depends on interface, offload, segmentation, retransmissions and capture drops."
            ],
            not_measured_reason="No packet capture was taken.",
            **shared,
        ),
        Metric(
            name="client_process_duration",
            value=duration_ms,
            unit="ms",
            label=EvidenceLabel.MEASURED,
            path="local OpenSSL process invocation",
            method="time.perf_counter around subprocess launch and exit",
            limits=[
                "Includes process startup, DNS, TCP/TLS and shutdown; not pure handshake latency.",
                "One observation, not a statistically stable benchmark.",
            ],
            source=str(artifact),
            **shared,
        ),
    ]

    notes = []
    if process.returncode:
        notes.append(f"OpenSSL exited with status {process.returncode}; inspect transcript.")
    if not negotiated_group:
        notes.append("Negotiated group not parsed; requested group is not asserted as negotiated.")

    return HandshakeRecord(
        id=uuid.uuid4().hex,
        target=host,
        port=port,
        tls_version="TLS 1.3" if process.returncode == 0 else None,
        requested_group=group,
        negotiated_group=negotiated_group,
        negotiation_verified=(
            negotiated_group is not None and group.casefold() == negotiated_group.casefold()
        ),
        session_kind="unknown",
        openssl_version=version_proc.stdout.strip(),
        command=command,
        exit_code=process.returncode,
        duration_ms=duration_ms,
        metrics=metrics,
        raw_log_path=str(artifact),
        notes=notes,
    )
