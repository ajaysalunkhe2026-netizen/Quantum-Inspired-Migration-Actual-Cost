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

PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)
NEGOTIATED = (
    re.compile(r"Negotiated TLS1?\.3 group:\s*([A-Za-z0-9_-]+)", re.I),
    re.compile(r"Server Temp Key:\s*([^\r\n]+)", re.I),
)

class CaptureError(RuntimeError):
    """OpenSSL capture failure."""

def _cert_der(text: str) -> list[bytes]:
    result = []
    for block in PEM_CERT.findall(text):
        body = re.sub(r"-----[^-]+-----|\s+", "", block)
        result.append(base64.b64decode(body, validate=True))
    return result

def measure_live(host: str, port: int = 443, group: str = "X25519",
                 timeout: float = 15.0, openssl: str = "openssl",
                 output_dir: str = "results") -> HandshakeRecord:
    binary = shutil.which(openssl)
    if not binary:
        raise CaptureError(f"OpenSSL executable not found: {openssl}")
    version_proc = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=5)
    if version_proc.returncode:
        raise CaptureError(version_proc.stderr.strip() or "Cannot query OpenSSL version")
    command = [binary, "s_client", "-connect", f"{host}:{port}", "-servername", host,
               "-tls1_3", "-groups", group, "-msg", "-trace", "-showcerts", "-brief"]
    started = time.perf_counter()
    try:
        proc = subprocess.run(command, input="\n", capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise CaptureError(f"OpenSSL timed out after {timeout}s") from exc
    duration_ms = (time.perf_counter() - started) * 1000
    transcript = proc.stdout + "\n" + proc.stderr
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / f"{host.replace(':', '_')}-{uuid.uuid4().hex[:8]}.openssl.txt"
    artifact.write_text(transcript, encoding="utf-8")
    negotiated = None
    for pattern in NEGOTIATED:
        match = pattern.search(transcript)
        if match:
            negotiated = match.group(1).strip()
            break
    certs = _cert_der(transcript)
    baseline = f"{host}:{port}; requested_group={group}"
    common = dict(baseline=baseline, limits=["Single live connection; environment-specific.",
                 "OpenSSL diagnostics are not a packet capture."])
    metrics = [
        Metric(name="certificate_chain_der_bytes", value=sum(map(len, certs)) if certs else None,
               unit="bytes", label=EvidenceLabel.MEASURED, path="live TCP/TLS connection",
               method="Sum DER lengths decoded from peer PEM certificates in s_client output",
               limits=["Peer-emitted chain only; root may be omitted.",
                       "Excludes TLS Certificate message and record framing."],
               source=str(artifact) if certs else None,
               not_measured_reason=None if certs else "No parseable PEM certificates in OpenSSL output", **common),
        Metric(name="client_key_share_bytes", value=None, unit="bytes", label=EvidenceLabel.MEASURED,
               path="TLS 1.3 ClientHello", method="OpenSSL trace; no stable parser enabled",
               limits=["Requested group is not a measured key-share length."],
               not_measured_reason="Not parsed from this OpenSSL build's diagnostic output.", **common),
        Metric(name="server_key_share_bytes", value=None, unit="bytes", label=EvidenceLabel.MEASURED,
               path="TLS 1.3 ServerHello", method="OpenSSL trace; no stable parser enabled",
               limits=["Selected group and server key-share length are distinct fields."],
               not_measured_reason="Not parsed from this OpenSSL build's diagnostic output.", **common),
        Metric(name="certificate_verify_signature_bytes", value=None, unit="bytes",
               label=EvidenceLabel.MEASURED, path="encrypted TLS 1.3 handshake",
               method="Decrypted handshake parser required",
               limits=["TLS 1.3 CertificateVerify is encrypted after ServerHello."],
               not_measured_reason="No reliable decoded CertificateVerify vector available.", **common),
        Metric(name="handshake_message_bytes", value=None, unit="bytes", label=EvidenceLabel.MEASURED,
               path="TLS handshake messages", method="Serialized handshake parser required",
               limits=["Diagnostic text length is not serialized handshake length."],
               not_measured_reason="Not measured by the OpenSSL text adapter.", **common),
        Metric(name="tls_record_bytes", value=None, unit="bytes", label=EvidenceLabel.MEASURED,
               path="TCP stream", method="Packet capture and TLS record accounting required",
               limits=["Requires capture-point and reassembly policy."],
               not_measured_reason="No packet capture was taken.", **common),
        Metric(name="tcp_ip_bytes", value=None, unit="bytes", label=EvidenceLabel.MEASURED,
               path="network interface", method="PCAP packet accounting required",
               limits=["Depends on interface, offload, segmentation, retransmissions and capture drops."],
               not_measured_reason="No packet capture was taken.", **common),
        Metric(name="client_process_duration", value=duration_ms, unit="ms",
               label=EvidenceLabel.MEASURED, path="local OpenSSL process invocation",
               method="time.perf_counter around subprocess launch and exit",
               limits=["Includes process startup, DNS, TCP/TLS and shutdown; not pure handshake latency.",
                       "One observation, not a statistically stable benchmark."],
               source=str(artifact), **common),
    ]
    notes = []
    if proc.returncode:
        notes.append(f"OpenSSL exited with status {proc.returncode}; inspect transcript.")
    if not negotiated:
        notes.append("Negotiated group not parsed; requested group is not asserted as negotiated.")
    return HandshakeRecord(id=uuid.uuid4().hex, target=host, port=port, tls_version="TLS 1.3",
        requested_group=group, negotiated_group=negotiated,
        negotiation_verified=bool(negotiated and group.lower() in negotiated.lower()),
        session_kind="unknown", openssl_version=version_proc.stdout.strip(),
        command=command, exit_code=proc.returncode, duration_ms=duration_ms,
        metrics=metrics, raw_log_path=str(artifact), notes=notes)
