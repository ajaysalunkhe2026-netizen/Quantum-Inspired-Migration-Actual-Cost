"""Regression tests for TCP sequence accounting and TLS 1.3 PCAP events."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pqtls.pcap import _insert_sequence_range, analyze_pcap


def test_tcp_sequence_ranges_deduplicate_retransmission_and_overlap() -> None:
    intervals: list[tuple[int, int]] = []
    assert _insert_sequence_range(intervals, 100, 100) == 100
    assert _insert_sequence_range(intervals, 100, 100) == 0
    assert _insert_sequence_range(intervals, 150, 100) == 50
    assert intervals == [(100, 250)]


def test_tcp_sequence_ranges_handle_32_bit_wraparound() -> None:
    intervals: list[tuple[int, int]] = []
    assert _insert_sequence_range(intervals, 0xFFFFFFF0, 32) == 32
    assert _insert_sequence_range(intervals, 0x00000000, 16) == 0


def test_pcap_extracts_tls13_events_and_stream_directions(tmp_path, monkeypatch) -> None:
    source = tmp_path / "mocked-tls13-events.pcapng"
    source.write_bytes(b"unit test stub; tshark output is mocked")
    fields = [
        "frame.len",
        "frame.time_epoch",
        "ip.len",
        "ipv6.plen",
        "ip.src",
        "ip.dst",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.stream",
        "tcp.seq",
        "tcp.len",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tls.record.length",
        "tls.handshake.type",
        "tls.handshake.length",
        "tls.handshake.extensions_key_share_key_exchange_length",
        "tls.handshake.extensions_key_share_group",
        "tls.handshake.sig_len",
        "tls.handshake.extensions_psk_selected_identity",
    ]
    field_listing = "\n".join(f"F\tName\t{field}\tDescription" for field in fields)

    def row(
        time: str,
        source_ip: str,
        destination_ip: str,
        source_port: str,
        destination_port: str,
        sequence: str,
        handshake_type: str,
        handshake_length: str = "",
        group: str = "",
        signature_length: str = "",
    ) -> str:
        values = [
            "100",
            time,
            "100",
            "",
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            "7",
            sequence,
            "40",
            "",
            "",
            "35",
            handshake_type,
            handshake_length,
            "32" if handshake_type in {"1", "2"} else "",
            group,
            signature_length,
            "",
        ]
        return "|".join(values)

    rows = [
        row("100.000", "192.0.2.10", "192.0.2.20", "50000", "443", "1000", "1", "20"),
        row(
            "100.050",
            "192.0.2.20",
            "192.0.2.10",
            "443",
            "50000",
            "2000",
            "2",
            "10",
            "x25519_mlkem768",
        ),
        row("100.100", "192.0.2.20", "192.0.2.10", "443", "50000", "2040", "11", "50"),
        row("100.150", "192.0.2.20", "192.0.2.10", "443", "50000", "2080", "15", "70", "", "64"),
        row("100.200", "192.0.2.20", "192.0.2.10", "443", "50000", "2120", "20", "10"),
        row("100.250", "192.0.2.10", "192.0.2.20", "50000", "443", "1040", "20", "10"),
        row("100.300", "192.0.2.10", "192.0.2.20", "50000", "443", "1080", "1", "20"),
    ]

    def fake_run(command, **_kwargs):
        if command[1] == "-G":
            return SimpleNamespace(returncode=0, stdout=field_listing, stderr="")
        if command[1] == "--version":
            return SimpleNamespace(returncode=0, stdout="TShark 4.4.0\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="\n".join(rows) + "\n", stderr="")

    monkeypatch.setattr("pqtls.pcap.shutil.which", lambda _name: "/usr/bin/tshark")
    monkeypatch.setattr("pqtls.pcap.subprocess.run", fake_run)

    result = analyze_pcap(source)
    metrics = {item["name"]: item for item in result["metrics"]}

    assert result["session_kind"] == "full"
    assert result["negotiated_group"] == "x25519_mlkem768"
    assert result["clienthello_to_server_finished_ms"] == pytest.approx(200.0)
    assert result["clienthello_to_client_finished_ms"] == pytest.approx(250.0)
    assert metrics["certificate_verify_signature_bytes"]["value"] == 64
    assert metrics["client_key_share_payload_bytes"]["value"] == 64
    assert metrics["server_key_share_payload_bytes"]["value"] == 32
    assert metrics["tls_record_bytes"]["value"] == 280
    assert metrics["handshake_message_bytes"]["value"] == 218
    assert (
        result["tcp_directional_accounting"]["stream_7_client_to_server"][
            "tcp_payload_unique_bytes"
        ]
        == 120
    )
    assert (
        result["tcp_directional_accounting"]["stream_7_server_to_client"][
            "tcp_payload_unique_bytes"
        ]
        == 160
    )


def test_psk_selection_is_not_claimed_as_ticket_resumption(tmp_path, monkeypatch) -> None:
    source = tmp_path / "psk.pcap"
    source.write_bytes(b"test capture placeholder")
    fields = [
        "frame.len",
        "tls.handshake.type",
        "tls.handshake.extensions_psk_selected_identity",
    ]
    listing = "\n".join(f"F\tName\t{field}\tDescription" for field in fields)

    def fake_run(command, **_kwargs):
        if command[1] == "-G":
            return SimpleNamespace(returncode=0, stdout=listing, stderr="")
        if command[1] == "--version":
            return SimpleNamespace(returncode=0, stdout="TShark 4.4.0\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="100|2|0\n", stderr="")

    monkeypatch.setattr("pqtls.pcap.shutil.which", lambda _name: "/usr/bin/tshark")
    monkeypatch.setattr("pqtls.pcap.subprocess.run", fake_run)

    result = analyze_pcap(source)
    metrics = {item["name"]: item for item in result["metrics"]}

    assert metrics["tls_record_bytes"]["value"] is None
    assert metrics["tls_record_bytes"]["label"] == "Not measured"
    assert result["psk_selected_identity_observed"] is True
    assert result["session_kind"] == "unknown"
    assert "externally provisioned PSK" in result["session_kind_reason"]
