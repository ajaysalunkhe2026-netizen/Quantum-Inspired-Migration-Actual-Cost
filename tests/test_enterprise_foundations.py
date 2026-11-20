"""Tests for configuration, host validation, audit integrity and PCAP parsing."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from pqtls.audit import append_audit_event, verify_audit_log
from pqtls.config import load_settings
from pqtls.pcap import _ints, _row_values, analyze_pcap
from pqtls.security import normalize_host


def test_config_precedence_yaml_env_override(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("host: example.com\nport: 8443\n", encoding="utf-8")
    settings = load_settings(config, {"PQTLS_PORT": "9443"}, {"port": 10443})
    assert settings.host == "example.com"
    assert settings.port == 10443


def test_config_rejects_unknown_keys():
    with pytest.raises(ValueError):
        load_settings(environ={}, overrides={"unexpected": True})


@pytest.mark.parametrize("host", ["https://example.com", "bad host", "example.com/path"])
def test_host_rejects_url_and_whitespace(host):
    with pytest.raises(ValueError):
        normalize_host(host)


def test_host_normalizes_idna():
    assert normalize_host("EXAMPLE.COM.") == "example.com"


def test_audit_hash_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    append_audit_event(path, {"measurement_id": "m-1", "result": "captured"})
    append_audit_event(path, {"measurement_id": "m-2", "result": "captured"})
    assert verify_audit_log(path)["valid"] is True
    rows = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(rows[0])
    row["event"]["result"] = "altered"
    rows[0] = json.dumps(row)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert verify_audit_log(path)["valid"] is False


def test_secret_file_permissions_are_enforced(tmp_path):
    from pqtls.security import validate_secret_file

    secret = tmp_path / "keys.log"
    secret.write_text("secret", encoding="utf-8")
    secret.chmod(0o600)
    validate_secret_file(str(secret))
    secret.chmod(0o644)
    with pytest.raises(ValueError):
        validate_secret_file(str(secret))


def test_pcap_integer_field_parsing():
    assert _ints("10,0x20,invalid") == [10, 32]
    assert _row_values(["1", "10,20"], {"frame_length": 1}, "frame_length") == [10, 20]
    assert _row_values(["1"], {}, "absent") == []


def test_pcap_accounting_uses_dissected_lengths_and_labels_psk(tmp_path, monkeypatch):
    source = tmp_path / "capture.pcap"
    source.write_bytes(b"fixture placeholder")
    fields = [
        "frame.number",
        "frame.len",
        "ip.len",
        "ipv6.plen",
        "tls.record.length",
        "tls.handshake.type",
        "tls.handshake.length",
        "tls.handshake.extensions_key_share_key_exchange_length",
        "tls.handshake.sig_len",
        "tls.handshake.extensions_psk_selected_identity",
    ]
    field_listing = "\n".join(f"F\tName\t{field}\tDescription" for field in fields)

    def fake_run(command, **_kwargs):
        if command[1] == "-G":
            return SimpleNamespace(returncode=0, stdout=field_listing, stderr="")
        if command[1] == "--version":
            return SimpleNamespace(returncode=0, stdout="TShark (Wireshark) 4.4.0\n", stderr="")
        return SimpleNamespace(
            returncode=0,
            stdout="1|1514|1500||120|2|10|32||0\n2|100|100|||15|70||64|\n",
            stderr="",
        )

    monkeypatch.setattr("pqtls.pcap.shutil.which", lambda _name: "/usr/bin/tshark")
    monkeypatch.setattr("pqtls.pcap.subprocess.run", fake_run)

    result = analyze_pcap(source)
    values = {metric["name"]: metric["value"] for metric in result["metrics"]}

    assert result["packet_count"] == 2
    assert result["frame_bytes"] == 1614
    assert result["session_kind_observation"] == "psk_selected_identity_observed"
    assert values["tcp_ip_bytes"] == 1600
    assert values["tls_record_bytes"] == 125
    assert values["handshake_message_bytes"] is None
    assert values["key_share_payload_bytes"] == 32
    assert values["certificate_verify_signature_bytes"] == 64
