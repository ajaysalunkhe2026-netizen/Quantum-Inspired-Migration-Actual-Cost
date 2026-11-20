"""Strict evidence schema; unavailable measurements are explicit nulls."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceLabel(str, Enum):
    MEASURED = "Measured"
    SPECIFICATION_DERIVED = "Specification-derived"
    CALCULATED = "Calculated"
    EXAMPLE = "Example"


class Metric(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    value: float | int | None = None
    unit: str
    label: EvidenceLabel
    baseline: str
    path: str
    method: str
    limits: list[str] = Field(min_length=1)
    source: str | None = None
    not_measured_reason: str | None = None

    @model_validator(mode="after")
    def validate_evidence(self) -> Metric:
        if self.value is None and not self.not_measured_reason:
            raise ValueError("null metrics require not_measured_reason")
        if self.value is not None and self.not_measured_reason:
            raise ValueError("valued metrics cannot have not_measured_reason")
        if self.label == EvidenceLabel.MEASURED and self.value is not None and not self.source:
            raise ValueError("Measured metrics require a source artifact")
        return self


class HandshakeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    id: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str
    port: int
    tls_version: str | None = None
    requested_group: str
    negotiated_group: str | None = None
    negotiation_verified: bool = False
    session_kind: str = "unknown"
    openssl_version: str
    command: list[str]
    exit_code: int
    duration_ms: float
    metrics: list[Metric]
    raw_log_path: str | None = None
    notes: list[str] = Field(default_factory=list)


class EvidenceDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    project: str = "Quantum-Inspired-Migration-Actual-Cost"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    records: list[HandshakeRecord]
    metadata: dict[str, Any] = Field(default_factory=dict)
