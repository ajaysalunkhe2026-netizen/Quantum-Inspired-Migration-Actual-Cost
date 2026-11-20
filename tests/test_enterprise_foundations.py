"""Tests for configuration, host validation and audit integrity."""
from __future__ import annotations

import json

import pytest

from pqtls.audit import append_audit_event, verify_audit_log
from pqtls.config import load_settings
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
