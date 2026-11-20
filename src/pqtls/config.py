"""Layered YAML, environment and CLI configuration with explicit precedence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class Settings(BaseModel):
    """Runtime settings. Precedence: defaults < YAML < PQTLS_* env < CLI overrides."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    host: str | None = None
    port: int = Field(default=443, ge=1, le=65535)
    timeout_seconds: float = Field(default=15.0, gt=0, le=300)
    openssl_binary: str = "openssl"
    tshark_binary: str = "tshark"
    output_directory: Path = Path("results")
    audit_log: Path = Path("results/audit.jsonl")
    json_logs: bool = True
    retries: int = Field(default=0, ge=0, le=5)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str | None) -> str | None:
        if value is None:
            return value
        from .security import normalize_host

        return normalize_host(value)


def load_settings(
    config_path: str | Path | None = None,
    environ: dict[str, str] | None = None,
    overrides: dict[str, Any] | None = None,
) -> Settings:
    """Load YAML, then PQTLS_* environment variables, then explicit CLI overrides."""
    data: dict[str, Any] = {}
    if config_path is not None:
        path = Path(config_path)
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"Cannot read configuration file: {path}") from exc
        if loaded is not None and not isinstance(loaded, dict):
            raise ValueError("Configuration root must be a YAML mapping")
        data.update(loaded or {})

    env = os.environ if environ is None else environ
    env_map = {
        "PQTLS_HOST": "host",
        "PQTLS_PORT": "port",
        "PQTLS_TIMEOUT_SECONDS": "timeout_seconds",
        "PQTLS_OPENSSL_BINARY": "openssl_binary",
        "PQTLS_TSHARK_BINARY": "tshark_binary",
        "PQTLS_OUTPUT_DIRECTORY": "output_directory",
        "PQTLS_AUDIT_LOG": "audit_log",
        "PQTLS_JSON_LOGS": "json_logs",
        "PQTLS_RETRIES": "retries",
    }
    for env_name, field_name in env_map.items():
        if env_name in env:
            data[field_name] = env[env_name]

    data.update(overrides or {})
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid PQTLS configuration: {exc}") from exc
