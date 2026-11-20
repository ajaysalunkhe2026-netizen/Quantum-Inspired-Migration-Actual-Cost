"""Offline PCAP accounting via Wireshark/tshark.

Only fields exposed by the installed dissector are emitted. Missing/decryption-dependent
fields remain null with an explicit reason; this module never estimates protocol overhead.
"""
from __future__ import annotations

import csv
import io
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .schema import EvidenceLabel, Metric


FIELD_CANDIDATES = {
    "frame_number": ("frame.number",),
    "frame_length": ("frame.len",),
    "ipv4_length": ("ip.len",),
    "ipv6_payload_length": ("ipv6.plen",),
    "tls_record_length": ("tls.record.length",),
    "handshake_type": ("tls.handshake.type",),
    "handshake_length": ("tls.handshake.length",),
    "key_share_length": ("tls.handshake.extensions_key_share_key_exchange_length",),
    "signature_length": ("tls.handshake.sig_len",),
    "psk_selected_identity": ("tls.handshake.extensions_psk_selected_identity",),
}


class PcapError(RuntimeError):
    """PCAP could not be inspected safely."""


def _available_fields(binary: str) -> set[str]:
    result = subprocess.run(
        [binary, "-G", "fields"], capture_output=True, text=True, timeout=20, check=False
    )
    if result.returncode:
        raise PcapError(result.stderr.strip() or "tshark field discovery failed")
    return {line.split("\t")[2] for line in result.stdout.splitlines()
            if line.startswith("F\t") and len(line.split("\t")) > 2}


def _ints(value: str) -> list[int]:
    values: list[int] = []
    for part in value.split(","):
        try:
            values.append(int(part, 0))
        except ValueError:
            continue
    return values


def analyze_pcap(
    pcap_path: str | Path,
    tshark: str = "tshark",
    keylog_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return packet/record/handshake totals and explicitly unavailable metrics.

    TCP/IP byte policy: sum captured IPv4 total lengths and IPv6 payload+40 bytes
    per packet, including retransmissions; excludes link-layer headers. TLS record
    totals include the 5-byte record header per dissected record. Handshake totals
    include the 4-byte handshake header per dissected message. Capture loss and
    NIC offload effects remain properties of the capture point, not corrected here.
    """
    binary = shutil.which(tshark)
    source = Path(pcap_path)
    if binary is None:
        raise PcapError(f"tshark executable not found: {tshark}")
    if not source.is_file():
        raise PcapError(f"PCAP file does not exist: {source}")
    if keylog_path is not None:
        from .security import validate_secret_file
        try:
            validate_secret_file(str(keylog_path))
        except (OSError, ValueError) as exc:
            raise PcapError(f"TLS key log rejected: {exc}") from exc

    available = _available_fields(binary)
    selected = [key for key, candidates in FIELD_CANDIDATES.items()
                if any(field in available for field in candidates)]
    field_names = [FIELD_CANDIDATES[key][0] for key in selected]
    if not field_names:
        raise PcapError("Installed tshark exposes none of the required frame fields")
    command = [binary, "-r", str(source), "-T", "fields", "-E", "separator=|",
               "-E", "occurrence=a", "-E", "aggregator=,"]
    for field in field_names:
        command.extend(["-e", field])
    if keylog_path is not None:
        command.extend(["-o", f"tls.keylog_file:{Path(keylog_path)}"])
    result = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    if result.returncode:
        raise PcapError(result.stderr.strip() or "tshark PCAP analysis failed")

    rows = list(csv.reader(io.StringIO(result.stdout), delimiter="|"))
    index = {name: pos for pos, name in enumerate(selected)}
    totals = {name: 0 for name in ("packets", "frame_bytes", "ip_bytes",
                                   "tls_record_bytes", "handshake_message_bytes",
                                   "key_share_payload_bytes", "certificate_verify_signature_bytes")}
    psk_selected = False
    handshake_types: list[int] = []
    observed: dict[str, bool] = {}

    for row in rows:
        if not row:
            continue
        totals["packets"] += 1
        def values(key: str) -> list[int]:
            pos = index.get(key)
            return _ints(row[pos]) if pos is not None and pos < len(row) else []
        frame = values("frame_length")
        ipv4 = values("ipv4_length")
        ipv6 = values("ipv6_payload_length")
        records = values("tls_record_length")
        handshakes = values("handshake_length")
        keyshares = values("key_share_length")
        signatures = values("signature_length")
        types = values("handshake_type")
        totals["frame_bytes"] += sum(frame)
        totals["ip_bytes"] += sum(ipv4) + sum(length + 40 for length in ipv6)
        totals["tls_record_bytes"] += sum(length + 5 for length in records)
        totals["handshake_message_bytes"] += sum(length + 4 for length in handshakes)
        totals["key_share_payload_bytes"] += sum(keyshares)
        if 15 in types:
            totals["certificate_verify_signature_bytes"] += sum(signatures)
        handshake_types.extend(types)
        psk_pos = index.get("psk_selected_identity")
        if psk_pos is not None and psk_pos < len(row) and row[psk_pos]:
            psk_selected = True
        for key, vals in (("frame_bytes", frame), ("ip_bytes", ipv4 + ipv6),
                          ("tls_record_bytes", records), ("handshake_message_bytes", handshakes),
                          ("key_share_payload_bytes", keyshares)):
            observed[key] = observed.get(key, False) or bool(vals)

    def metric(name: str, value: int | None, reason: str, method: str,
               limits: list[str]) -> Metric:
        return Metric(
            name=name, value=value, unit="bytes", label=EvidenceLabel.MEASURED,
            baseline=f"PCAP:{source.name}", path="offline packet capture",
            method=method, limits=limits, source=str(source) if value is not None else None,
            not_measured_reason=None if value is not None else reason,
        )

    metrics = [
        metric("tls_record_bytes", totals["tls_record_bytes"] if observed.get("tls_record_bytes") else None,
               "No TLS records were dissected; verify ports, capture integrity and Wireshark TLS dissector.",
               "Sum tls.record.length plus 5-byte TLS record headers per dissected record.",
               ["Only records dissected by this tshark version are counted."]),
        metric("handshake_message_bytes", totals["handshake_message_bytes"] if observed.get("handshake_message_bytes") else None,
               "No handshake message lengths were dissected; encrypted messages require a valid TLS key log.",
               "Sum tls.handshake.length plus 4-byte handshake headers.",
               ["Only decoded handshake messages are counted; encrypted messages may be unavailable."]),
        metric("tcp_ip_bytes", totals["ip_bytes"] if totals["ip_bytes"] else None,
               "No IPv4 or IPv6 packet lengths were found.",
               "Sum IPv4 total length and IPv6 payload length plus 40-byte base header per packet.",
               ["Includes retransmissions; excludes link-layer headers; capture drops/offloads are not corrected."]),
        metric("key_share_payload_bytes", totals["key_share_payload_bytes"] if observed.get("key_share_payload_bytes") else None,
               "Installed tshark did not expose key-share payload lengths in this capture.",
               "Sum the Wireshark key-share key-exchange-length field where dissected.",
               ["Payload only; excludes key-share group and vector framing."]),
        metric("certificate_verify_signature_bytes",
               totals["certificate_verify_signature_bytes"] if totals["certificate_verify_signature_bytes"] else None,
               "CertificateVerify signature length unavailable; TLS 1.3 encrypted handshake needs usable key log.",
               "Sum signature-length field only on decoded CertificateVerify handshake messages.",
               ["Depends on Wireshark dissector field availability and successful TLS decryption."]),
    ]
    return {
        "source": str(source),
        "tshark_version": subprocess.run([binary, "--version"], capture_output=True,
                                           text=True, timeout=10, check=False).stdout.splitlines()[0],
        "packet_count": totals["packets"],
        "frame_bytes": totals["frame_bytes"],
        "session_kind_observation": (
            "psk_selected_identity_observed" if psk_selected else "no_psk_selection_observed"
        ),
        "session_kind_limit": (
            "PSK selection is evidence of PSK use, not proof that the PSK was a resumption ticket; "
            "external PSKs must be distinguished by the operator."
        ),
        "handshake_types_observed": sorted(set(handshake_types)),
        "metrics": [item.model_dump(mode="json") for item in metrics],
        "field_availability": {key: any(name in available for name in names)
                               for key, names in FIELD_CANDIDATES.items()},
        "capture_policy": {
            "tcp_ip": "IPv4 total length + IPv6 payload + 40; per captured packet; retransmissions included",
            "tls_record": "record payload length + 5-byte header",
            "handshake": "message body length + 4-byte header",
            "keylog_used": keylog_path is not None,
        },
    }
