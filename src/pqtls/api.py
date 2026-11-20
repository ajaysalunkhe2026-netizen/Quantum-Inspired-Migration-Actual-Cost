"""Optional FastAPI operational endpoints; install the api extra."""

from __future__ import annotations

import shutil

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

app = FastAPI(title="PQTLS Measurement Service", version="0.2.0")


@app.get("/health/live")
def liveness() -> dict[str, str]:
    """Liveness probe: process is responding."""
    return {"status": "alive"}


@app.get("/health/ready")
def readiness() -> dict[str, object]:
    """Readiness probe for the live capture runtime."""
    checks = {
        "openssl": shutil.which("openssl") is not None,
        "tshark": shutil.which("tshark") is not None,
    }
    ready = checks["openssl"]
    return {"status": "ready" if ready else "degraded", "checks": checks}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    """Prometheus text endpoint; measurement values are not fabricated or exported."""
    return (
        "# HELP pqtls_api_up API process is responding\n"
        "# TYPE pqtls_api_up gauge\n"
        "pqtls_api_up 1\n"
    )
