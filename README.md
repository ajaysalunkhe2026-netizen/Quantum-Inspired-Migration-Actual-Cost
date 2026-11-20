# Quantum-Inspired-Migration-Actual-Cost

Evidence-first TLS 1.3 post-quantum migration measurement. The project is a research/engineering tool under active development, not a certification or production-readiness claim.

> No synthetic metrics. A requested group is not a negotiated group. A null metric is not zero.

## What is implemented on this branch

- Live OpenSSL capture with preserved diagnostic transcript, peer certificate DER byte count and process wall time.
- Strict evidence records with provenance, methods, limits and explicit not-measured reasons.
- Offline PCAP accounting through the installed Wireshark/tshark dissector.
- Runtime discovery of tshark field availability; unsupported/decryption-dependent fields remain null.
- Optional TLS key-log input with strict file-permission checks.
- YAML + environment + CLI configuration precedence.
- JSON structured logs and a SHA-256 hash-chained local audit log.
- Optional FastAPI liveness/readiness endpoints.
- Multi-stage, non-root Docker image and hardened Compose example.
- CI gates for tests, Ruff, Black, strict mypy, pip-audit and SBOM artifact generation.

## Important measurement boundaries

PCAP accounting is capture-point dependent. This branch counts IPv4/IPv6 packet lengths per captured packet (retransmissions included, link layer excluded), TLS record payload length plus the 5-byte record header, and decoded handshake body length plus the 4-byte handshake header. Only packets/messages dissected by the installed tshark build are included.

Key-share byte counts are payload bytes only when the installed dissector exposes the corresponding field. CertificateVerify signature length requires successful TLS 1.3 handshake decryption and an available dissector field. Missing values are null with a reason.

PSK selection is not conclusive proof of session resumption because externally provisioned PSKs may also be selected. The offline analyzer reports this observation but does not assert full/resumed session classification. Exact directional accounting, TCP stream reassembly, capture-drop correction and protocol event timing remain production gates.

The live OpenSSL adapter still measures process duration, not isolated handshake latency. Do not compare it as pure network RTT.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,api]"
pqtls --help
```

OpenSSL is required for live capture. tshark is required for PCAP analysis.

## Commands

Live capture:

```bash
pqtls measure --host www.example.com --group X25519
```

Configuration precedence is defaults < YAML < `PQTLS_*` environment < CLI flags:

```bash
pqtls measure --config config.example.yaml --host www.example.com
```

Offline PCAP:

```bash
chmod 600 session.keys
pqtls pcap capture.pcapng --keylog session.keys --out results/pcap.json
```

Audit integrity:

```bash
pqtls audit-verify --path results/audit.jsonl
```

Reports:

```bash
pqtls report results/measurement.json --format markdown --out results/report.md
pqtls report results/measurement.json --format csv --out results/report.csv
```

Optional API:

```bash
python -m pip install -e ".[api]"
uvicorn pqtls.api:app --host 127.0.0.1 --port 8000
```

- `GET /health/live`: process liveness.
- `GET /health/ready`: checks required runtime executables.
- `GET /metrics`: service availability gauge only; no synthetic measurement metrics.

## Docker

```bash
docker compose build
docker compose run --rm pqtls --help
```

The image runs as UID 10001. Compose drops capabilities, enables no-new-privileges and uses a read-only root filesystem.

## Security and operations

- Treat TLS key logs as secrets; they can decrypt captured sessions. Do not commit them.
- Local audit hash chaining detects tampering but is not immutable/WORM storage or a digital signature. Forward checkpoints to an independently controlled audit system for enterprise deployment.
- Restrict network egress and access to capture artifacts.
- Review `docs/enterprise-operations.md` and `docs/measurement-boundaries.md` before operational use.

## Quality checks

```bash
pytest --cov=pqtls
ruff check .
black --check .
mypy src/pqtls
pip-audit
cyclonedx-py environment --output-format JSON --output-file sbom.json
```

A green CI run is required before merging. Coverage is reported but not yet enforced at a project-wide threshold. Dependency ranges are bounded but a fully hash-pinned lockfile and release signing are still required for a production release.

## Production readiness gates still open

1. Validate tshark fields and decryption behaviour against versioned PCAP fixtures across supported Wireshark versions.
2. Add client/server direction attribution, TCP stream reassembly, retransmission-aware unique-byte metrics and capture-drop reporting.
3. Prove full vs resumed TLS 1.3 handshakes using controlled ticket-based fixtures; distinguish external PSKs.
4. Measure ClientHello-to-ServerHello and Finished/application-ready timing from protocol events, separately from process overhead.
5. Add authenticated API access, authorization, rate limits, tenant isolation and external immutable audit storage before exposing the service.
6. Pin every dependency with hashes, scan container images, sign releases and complete independent security review.

This branch provides enterprise-oriented foundations and an offline dissector adapter; it is not yet an enterprise-certified or fully production-ready wire-level analyzer.
