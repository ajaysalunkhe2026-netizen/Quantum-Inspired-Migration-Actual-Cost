"""Offline TLS/TCP accounting using Wireshark's TCP stream dissector.

TCP payload accounting deduplicates sequence ranges per stream and direction. TLS
record and handshake fields are emitted only when tshark actually dissects them.
A PSK selection is never treated as proof of ticket-based resumption.
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
    "frame_length": ("frame.len",),
    "frame_time": ("frame.time_epoch",),
    "ipv4_length": ("ip.len",),
    "ipv6_payload_length": ("ipv6.plen",),
    "ip_src": ("ip.src", "ipv6.src"),
    "ip_dst": ("ip.dst",),
    "ipv6_src": ("ipv6.src",),
    "ipv6_dst": ("ipv6.dst",),
    "tcp_srcport": ("tcp.srcport",),
    "tcp_dstport": ("tcp.dstport",),
    "tcp_stream": ("tcp.stream",),
    "tcp_seq": ("tcp.seq",),
    "tcp_len": ("tcp.len",),
    "tcp_syn": ("tcp.flags.syn",),
    "tcp_ack": ("tcp.flags.ack",),
    "tcp_retransmission": ("tcp.analysis.retransmission",),
    "tcp_fast_retransmission": ("tcp.analysis.fast_retransmission",),
    "tls_record_length": ("tls.record.length",),
    "handshake_type": ("tls.handshake.type",),
    "handshake_length": ("tls.handshake.length",),
    "key_share_length": (
        "tls.handshake.extensions_key_share_key_exchange_length",
    ),
    "key_share_group": (
        "tls.handshake.extensions_key_share_group",
        "tls.handshake.extensions_key_share_selected_group",
    ),
    "signature_length": ("tls.handshake.sig_len",),
    "psk_selected_identity": (
        "tls.handshake.extensions_psk_selected_identity",
    ),
}

HANDSHAKE_TYPES = {
    1: "client_hello",
    2: "server_hello",
    8: "encrypted_extensions",
    11: "certificate",
    15: "certificate_verify",
    20: "finished",
}


class PcapError(RuntimeError):
    """PCAP could not be inspected safely."""


def _available_fields(binary: str) -> set[str]:
    result = subprocess.run(
        [binary, "-G", "fields"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if result.returncode:
        raise PcapError(result.stderr.strip() or "tshark field discovery failed")
    return {
        parts[2]
        for line in result.stdout.splitlines()
        if (parts := line.split("\t"))[0] == "F" and len(parts) > 2
    }


def _ints(value: str) -> list[int]:
    values: list[int] = []
    for part in value.split(","):
        try:
            values.append(int(part, 0))
        except ValueError:
            continue
    return values


def _row_values(row: list[str], index: dict[str, int], key: str) -> list[int]:
    position = index.get(key)
    if position is None or position >= len(row):
        return []
    return _ints(row[position])


def _row_text(row: list[str], index: dict[str, int], key: str) -> str | None:
    position = index.get(key)
    if position is None or position >= len(row) or not row[position]:
        return None
    return row[position].split(",", maxsplit=1)[0]


def _insert_sequence_range(
    intervals: list[tuple[int, int]], sequence: int, length: int
) -> int:
    """Add a TCP sequence range and return newly covered bytes.

    Sequence numbers are unwrapped relative to the highest previously observed
    endpoint. This handles normal 32-bit wraparound and out-of-order segments.
    """
    if length <= 0:
        return 0
    modulus = 1 << 32
    reference = max((end for _, end in intervals), default=None)
    start = sequence % modulus
    if reference is not None:
        quotient = round((reference - start) / modulus)
        candidates = [start + (quotient + offset) * modulus for offset in (-1, 0, 1)]
        start = min(candidates, key=lambda candidate: abs(candidate - reference))
    end = start + length
    covered = 0
    for left, right in intervals:
        covered += max(0, min(end, right) - max(start, left))
    newly_covered = max(0, length - covered)
    merged: list[tuple[int, int]] = []
    for left, right in sorted([*intervals, (start, end)]):
        if merged and left <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
        else:
            merged.append((left, right))
    intervals[:] = merged
    return newly_covered


def _seconds(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _metric(
    name: str,
    value: int | float | None,
    unit: str,
    source: Path,
    reason: str,
    method: str,
    limits: list[str],
) -> Metric:
    return Metric(
        name=name,
        value=value,
        unit=unit,
        label=EvidenceLabel.MEASURED,
        baseline=f"PCAP:{source.name}",
        path="offline packet capture",
        method=method,
        limits=limits,
        source=str(source) if value is not None else None,
        not_measured_reason=None if value is not None else reason,
    )


def analyze_pcap(
    pcap_path: str | Path,
    tshark: str = "tshark",
    keylog_path: str | Path | None = None,
) -> dict[str, Any]:
    """Analyze TCP streams and decoded TLS events without estimating missing data.

    IP-byte totals describe captured packets and therefore include retransmissions.
    Unique TCP payload is computed from per-stream, per-direction sequence ranges.
    TLS record/message totals come from tshark's TCP-reassembled dissector output;
    they are separate protocol-layer quantities and are not added to IP totals.
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
    selected = {
        key: next((field for field in candidates if field in available), None)
        for key, candidates in FIELD_CANDIDATES.items()
    }
    field_names = list(dict.fromkeys(field for field in selected.values() if field))
    if not field_names:
        raise PcapError("Installed tshark exposes none of the required packet fields")
    command = [
        binary,
        "-r",
        str(source),
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=,",
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "tls.desegment_ssl_records:TRUE",
    ]
    for field in field_names:
        command.extend(["-e", field])
    if keylog_path is not None:
        command.extend(["-o", f"tls.keylog_file:{Path(keylog_path)}"])
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise PcapError("tshark analysis timed out after 300 seconds") from exc
    if result.returncode:
        raise PcapError(result.stderr.strip() or "tshark PCAP analysis failed")

    rows = list(csv.reader(io.StringIO(result.stdout), delimiter="|"))
    index = {
        key: field_names.index(field)
        for key, field in selected.items()
        if field is not None
    }
    totals = {
        "packets": 0,
        "frame_bytes": 0,
        "ip_bytes": 0,
        "tls_record_bytes": 0,
        "handshake_message_bytes": 0,
        "key_share_payload_bytes": 0,
        "certificate_verify_signature_bytes": 0,
        "tcp_payload_captured_bytes": 0,
        "tcp_payload_unique_bytes": 0,
        "tcp_payload_retransmitted_bytes": 0,
        "tcp_retransmission_packets": 0,
    }
    direction_totals: dict[tuple[int, str, str, str, str], dict[str, int]] = {}
    sequence_ranges: dict[tuple[int, str, str, str, str], list[tuple[int, int]]] = {}
    handshake_events: list[tuple[int, float, str | None, str | None, str | None]] = []
    handshake_types: set[int] = set()
    psk_selected = False
    client_endpoint: tuple[str, str] | None = None
    observed: set[str] = set()
    negotiated_group: str | None = None

    for row in rows:
        if not row:
            continue
        totals["packets"] += 1
        frame = _row_values(row, index, "frame_length")
        ipv4 = _row_values(row, index, "ipv4_length")
        ipv6 = _row_values(row, index, "ipv6_payload_length")
        totals["frame_bytes"] += sum(frame)
        totals["ip_bytes"] += sum(ipv4) + sum(length + 40 for length in ipv6)
        if frame:
            observed.add("frame_bytes")
        if ipv4 or ipv6:
            observed.add("ip_bytes")

        stream_text = _row_text(row, index, "tcp_stream")
        src = _row_text(row, index, "ip_src") or _row_text(row, index, "ipv6_src")
        dst = _row_text(row, index, "ip_dst") or _row_text(row, index, "ipv6_dst")
        src_port = _row_text(row, index, "tcp_srcport")
        dst_port = _row_text(row, index, "tcp_dstport")
        stream = int(stream_text) if stream_text and stream_text.isdigit() else None
        src_endpoint = f"{src or '?'}:{src_port or '?'}"
        dst_endpoint = f"{dst or '?'}:{dst_port or '?'}"
        tcp_len_values = _row_values(row, index, "tcp_len")
        if _row_text(row, index, "tcp_retransmission") or _row_text(
            row, index, "tcp_fast_retransmission"
        ):
            totals["tcp_retransmission_packets"] += 1
        seq_values = _row_values(row, index, "tcp_seq")
        if stream is not None and src and dst and src_port and dst_port and tcp_len_values:
            key = (stream, src, src_port, dst, dst_port)
            payload_len = sum(tcp_len_values)
            direction = direction_totals.setdefault(
                key, {"ip_bytes": 0, "captured_payload_bytes": 0, "unique_payload_bytes": 0}
            )
            direction["ip_bytes"] += sum(ipv4) + sum(length + 40 for length in ipv6)
            direction["captured_payload_bytes"] += payload_len
            totals["tcp_payload_captured_bytes"] += payload_len
            if seq_values:
                ranges = sequence_ranges.setdefault(key, [])
                unique = _insert_sequence_range(ranges, seq_values[0], payload_len)
                direction["unique_payload_bytes"] += unique
                totals["tcp_payload_unique_bytes"] += unique
                totals["tcp_payload_retransmitted_bytes"] += payload_len - unique
            syn = _row_values(row, index, "tcp_syn")
            ack = _row_values(row, index, "tcp_ack")
            if client_endpoint is None and syn and syn[0] == 1 and (not ack or ack[0] == 0):
                client_endpoint = (src, src_port)

        records = _row_values(row, index, "tls_record_length")
        handshakes = _row_values(row, index, "handshake_length")
        keyshares = _row_values(row, index, "key_share_length")
        signatures = _row_values(row, index, "signature_length")
        types = _row_values(row, index, "handshake_type")
        totals["tls_record_bytes"] += sum(length + 5 for length in records)
        totals["handshake_message_bytes"] += sum(length + 4 for length in handshakes)
        totals["key_share_payload_bytes"] += sum(keyshares)
        if 15 in types:
            totals["certificate_verify_signature_bytes"] += sum(signatures)
        if records:
            observed.add("tls_record_bytes")
        if handshakes:
            observed.add("handshake_message_bytes")
        if keyshares:
            observed.add("key_share_payload_bytes")
        if signatures and 15 in types:
            observed.add("certificate_verify_signature_bytes")
        handshake_types.update(types)

        timestamp = _seconds(_row_text(row, index, "frame_time"))
        if timestamp is not None and types:
            for handshake_type in types:
                handshake_events.append(
                    (handshake_type, timestamp, src, src_port, dst_endpoint)
                )
        if 2 in types:
            negotiated_group = _row_text(row, index, "key_share_group") or negotiated_group
        if _row_text(row, index, "psk_selected_identity") is not None:
            psk_selected = True

    client_finished: float | None = None
    server_finished: float | None = None
    client_hello: float | None = None
    server_certificate = False
    server_certificate_verify = False
    for event_type, timestamp, src, src_port, _dst in handshake_events:
        if event_type == 1 and client_hello is None:
            client_hello = timestamp
            if src and src_port:
                client_endpoint = client_endpoint or (src, src_port)
        elif event_type == 11 and client_endpoint and (src, src_port) != client_endpoint:
            server_certificate = True
        elif event_type == 15 and client_endpoint and (src, src_port) != client_endpoint:
            server_certificate_verify = True
        elif event_type == 20 and client_endpoint:
            if (src, src_port) == client_endpoint:
                client_finished = client_finished or timestamp
            else:
                server_finished = server_finished or timestamp

    server_latency = (
        (server_finished - client_hello) * 1000
        if client_hello is not None and server_finished is not None
        else None
    )
    client_latency = (
        (client_finished - client_hello) * 1000
        if client_hello is not None and client_finished is not None
        else None
    )
    full_handshake_verified = (
        server_certificate and server_certificate_verify and server_finished is not None
    )
    session_kind = "full" if full_handshake_verified and not psk_selected else "unknown"
    session_kind_reason = (
        None
        if session_kind == "full"
        else (
            "A PSK identity was selected, but the capture cannot prove that it was a "
            "NewSessionTicket rather than an externally provisioned PSK."
            if psk_selected
            else "Certificate, CertificateVerify and server Finished were not all "
            "decoded; TLS 1.3 encrypted handshake data may require a valid key log."
        )
    )

    def metric(
        name: str,
        value: int | float | None,
        unit: str,
        reason: str,
        method: str,
        limits: list[str],
    ) -> Metric:
        return _metric(name, value, unit, source, reason, method, limits)

    limits = ["Only packets and protocol messages visible to this capture are counted."]
    metrics = [
        metric(
            "tcp_ip_bytes",
            totals["ip_bytes"] or None,
            "bytes",
            "No IPv4 or IPv6 packet lengths were dissected.",
            "Sum captured IPv4 total lengths and IPv6 payload lengths plus 40-byte base headers.",
            ["Includes retransmissions; excludes link-layer headers and capture-drop correction."],
        ),
        metric(
            "tcp_payload_unique_bytes",
            totals["tcp_payload_unique_bytes"] or None,
            "bytes",
            "TCP stream IDs, sequence numbers or payload lengths were unavailable.",
            "Deduplicate TCP sequence ranges independently for each stream and direction.",
            ["Sequence coverage, not a byte-for-byte exported reassembled stream."],
        ),
        metric(
            "tcp_payload_retransmitted_bytes",
            totals["tcp_payload_retransmitted_bytes"] if totals["tcp_payload_captured_bytes"] else None,
            "bytes",
            "No TCP payload segments with sequence metadata were dissected.",
            "Captured TCP payload bytes minus newly covered sequence-range bytes.",
            ["Overlapping sequence ranges are counted as retransmitted/duplicate payload."],
        ),
        metric(
            "tls_record_bytes",
            totals["tls_record_bytes"] if "tls_record_bytes" in observed else None,
            "bytes",
            "No TLS records were dissected; verify capture integrity and TLS dissector support.",
            "Sum dissected TLS record lengths plus 5-byte record headers.",
            ["Uses tshark TCP reassembly; only records exposed by this dissector are counted."],
        ),
        metric(
            "handshake_message_bytes",
            totals["handshake_message_bytes"] if "handshake_message_bytes" in observed else None,
            "bytes",
            "No TLS handshake message lengths were dissected; encrypted messages may need a key log.",
            "Sum dissected handshake message lengths plus 4-byte handshake headers.",
            ["TLS record bytes and handshake message bytes are separate, non-additive layers."],
        ),
        metric(
            "key_share_payload_bytes",
            totals["key_share_payload_bytes"] if "key_share_payload_bytes" in observed else None,
            "bytes",
            "No supported key-share payload length was dissected.",
            "Sum the dissector's key-exchange vector lengths.",
            ["Payload only; excludes extension, group and vector framing."],
        ),
        metric(
            "certificate_verify_signature_bytes",
            totals["certificate_verify_signature_bytes"]
            if "certificate_verify_signature_bytes" in observed
            else None,
            "bytes",
            "CertificateVerify signature length was not decoded; TLS 1.3 decryption may be required.",
            "Sum signature-length fields on decoded CertificateVerify messages.",
            ["Depends on key-log validity and installed tshark field support."],
        ),
        metric(
            "clienthello_to_server_finished_ms",
            server_latency,
            "ms",
            "ClientHello and server Finished timestamps were not both decoded.",
            "Difference between first ClientHello and first server-direction Finished frame timestamps.",
            ["Capture timestamp interval, not endpoint processing time or one-way latency."],
        ),
        metric(
            "clienthello_to_client_finished_ms",
            client_latency,
            "ms",
            "ClientHello and client Finished timestamps were not both decoded.",
            "Difference between first ClientHello and first client-direction Finished frame timestamps.",
            ["Capture timestamp interval; requires both Finished messages to be dissected."],
        ),
    ]

    directional: dict[str, dict[str, int]] = {}
    for key, values in direction_totals.items():
        stream_id, src, src_port, dst, dst_port = key
        direction_name = (
            "client_to_server"
            if client_endpoint == (src, src_port)
            else "server_to_client"
            if client_endpoint == (dst, dst_port)
            else "endpoint_a_to_b"
        )
        label = f"stream_{stream_id}_{direction_name}"
        current = directional.setdefault(
            label,
            {"ip_bytes_including_retransmissions": 0, "tcp_payload_captured_bytes": 0,
             "tcp_payload_unique_bytes": 0},
        )
        current["ip_bytes_including_retransmissions"] += values["ip_bytes"]
        current["tcp_payload_captured_bytes"] += values["captured_payload_bytes"]
        current["tcp_payload_unique_bytes"] += values["unique_payload_bytes"]

    version_result = subprocess.run(
        [binary, "--version"], capture_output=True, text=True, timeout=10, check=False
    )
    version_lines = version_result.stdout.splitlines()
    return {
        "source": str(source),
        "tshark_version": version_lines[0] if version_lines else "unknown",
        "packet_count": totals["packets"],
        "tcp_retransmission_packet_count": totals["tcp_retransmission_packets"],
        "frame_bytes": totals["frame_bytes"],
        "tcp_directional_accounting": directional,
        "session_kind": session_kind,
        "session_kind_reason": session_kind_reason,
        "psk_selected_identity_observed": psk_selected,
        "session_kind_observation": (
            "psk_selected_identity_observed" if psk_selected else "no_psk_selection_observed"
        ),
        "session_kind_limit": (
            "PSK selection is not proof of ticket-based resumption; external PSKs are also possible."
        ),
        "handshake_events_observed": sorted(
            {HANDSHAKE_TYPES.get(kind, f"unknown_{kind}") for kind in handshake_types}
        ),
        "clienthello_to_server_finished_ms": server_latency,
        "clienthello_to_client_finished_ms": client_latency,
        "negotiated_group": negotiated_group,
        "metrics": [item.model_dump(mode="json") for item in metrics],
        "field_availability": {
            key: field is not None for key, field in selected.items()
        },
        "capture_policy": {
            "tcp_ip": "Captured IP packet bytes; retransmissions included",
            "tcp_payload_unique": "TCP sequence-range coverage per stream and direction",
            "tcp_payload_retransmitted": "Captured payload bytes minus unique sequence coverage",
            "tls_record": "TLS record body length + 5-byte record header",
            "handshake": "Handshake message body length + 4-byte handshake header",
            "tls_reassembly": "Wireshark/tshark TCP stream dissector",
            "keylog_used": keylog_path is not None,
        },
    }
