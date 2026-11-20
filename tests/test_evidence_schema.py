import pytest

from pqtls.schema import EvidenceLabel, Metric


def test_null_requires_reason():
    with pytest.raises(ValueError):
        Metric(
            name="metric",
            value=None,
            unit="bytes",
            label=EvidenceLabel.MEASURED,
            baseline="X25519",
            path="live",
            method="capture",
            limits=["scope"],
        )


def test_measured_value_requires_source():
    with pytest.raises(ValueError):
        Metric(
            name="metric",
            value=32,
            unit="bytes",
            label=EvidenceLabel.MEASURED,
            baseline="X25519",
            path="live",
            method="capture",
            limits=["scope"],
        )


def test_explicit_unmeasured_value():
    metric = Metric(
        name="metric",
        value=None,
        unit="bytes",
        label=EvidenceLabel.MEASURED,
        baseline="X25519",
        path="live",
        method="capture",
        limits=["scope"],
        not_measured_reason="parser unavailable",
    )
    assert metric.value is None
