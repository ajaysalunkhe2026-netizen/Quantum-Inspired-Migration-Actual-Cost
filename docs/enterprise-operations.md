# Enterprise operations foundation

This release adds operator foundations, not a certification of production readiness.

## Configuration precedence

Defaults are overridden by YAML, then `PQTLS_*` environment variables, then explicit CLI overrides. See `config.example.yaml`. Do not commit key logs, private keys, credentials, or production captures.

## Audit integrity

Each audit event is a canonical JSON object linked to the previous event by SHA-256. The log is created with mode 0600 and fsync is used after append. This detects accidental or unauthorized modification of the existing chain; it is not a tamper-proof remote audit service. Production deployments should forward events to immutable/WORM storage and sign checkpoints with a managed key.

## Offline PCAP

Install tshark and use `pqtls pcap` (added in the API layer in this branch). An optional TLS key log must be a regular file with mode 0600 or stricter. Treat it as a secret: it can decrypt captured sessions. Never upload it to issue trackers or public artifacts.

The PCAP adapter discovers field availability from the installed tshark build. It emits null plus a reason when fields are unavailable. Packet byte counts include retransmissions and exclude link-layer headers. Capture drops, offload, capture location, and direction attribution must be documented for each study.

PSK selection is not sufficient to prove a resumed session: external PSKs can also be selected. The adapter reports the observation without overclaiming full/resumed classification.

## API and metrics

Install `.[api]` and run `uvicorn pqtls.api:app`. Liveness and readiness endpoints are available. The Prometheus endpoint exports service availability only; it does not synthesize measurement metrics.

## Deployment

The multi-stage image installs runtime tools, drops root privileges, and uses a non-root UID. Compose defaults to a read-only root filesystem, drops Linux capabilities, and mounts only the results directory. Restrict network egress and mount captures/key logs read-only in production.

## Remaining production gates

- Validate tshark field names and decrypted handshake extraction against versioned PCAP fixtures from supported Wireshark releases.
- Add server/client direction attribution, retransmission-aware unique-byte accounting, TCP stream reassembly and capture-drop reporting.
- Distinguish TLS 1.3 resumption tickets from external PSKs using controlled full/resumed test fixtures.
- Separate ClientHello-to-ServerHello, Finished, and application-ready timing using protocol events rather than subprocess wall time.
- Add signed audit checkpoints, external immutable storage, authentication/authorization, rate limiting and tenant isolation before exposing the API.
- Pin dependencies with hashes, run vulnerability scans and publish an SBOM in release CI.
- Meet a measured coverage target and complete independent security review before production claims.
