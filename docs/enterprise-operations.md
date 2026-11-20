# Enterprise operations foundation

This release adds operator foundations, not a certification of production readiness.

## Configuration precedence

Defaults are overridden by YAML, then `PQTLS_*` environment variables, then explicit CLI overrides. See `config.example.yaml`. Do not commit key logs, private keys, credentials, or production captures.

## Audit integrity

Each audit event is a canonical JSON object linked to the previous event by SHA-256. The log is created with mode 0600 and fsync is used after append. This detects accidental or unauthorized modification of the existing chain; it is not a tamper-proof remote audit service. Production deployments should forward events to immutable/WORM storage and sign checkpoints with a managed key.

## Offline PCAP

Install tshark and use `pqtls pcap`. An optional TLS key log must be a regular file with mode 0600 or stricter. Treat it as a secret: it can decrypt captured sessions. Never upload it to issue trackers or public artifacts.

The adapter discovers field availability from the installed tshark build. It emits null plus a reason when fields are unavailable. IPv4/IPv6 byte totals describe captured IP packets, include retransmissions, and exclude link-layer headers. TCP payload sequence ranges are deduplicated independently by TCP stream and direction; captured payload minus unique sequence coverage is reported as duplicate/retransmitted payload. Direction is attributed from the observed ClientHello or initial SYN where available.

TLS record bytes and TLS handshake-message bytes are separate protocol-layer measurements. Record lengths include the 5-byte record header; handshake message lengths include the 4-byte handshake header. They are not added to IP totals. TShark's TCP stream dissector performs the protocol reassembly; the adapter reports sequence coverage rather than exporting reconstructed application payload.

Handshake timing is derived from capture timestamps: first ClientHello to server Finished, and first ClientHello to client Finished. These are capture-point intervals, not endpoint processing time or pure one-way latency. Missing events or timestamps remain null with an explicit reason.

A server-direction ServerHello key-share group is reported when the installed dissector exposes it. Key-share payload bytes exclude extension/vector framing. CertificateVerify signature bytes require successful TLS 1.3 decryption and supported dissector fields.

A decoded server Certificate + CertificateVerify + server Finished is evidence for a full certificate handshake. PSK selected identity alone is not proof of ticket-based resumption: external PSKs can also be selected. Such sessions remain `unknown` until ticket provenance can be established. No ticket-based resumed classification is currently claimed.

## Fixture policy

Real hybrid-PQC PCAP fixtures are not included yet. Unit tests use mocked tshark rows and synthetic sequence ranges only; they are not represented as real captures. See `tests/fixtures/README.md` for the evidence and provenance required before adding versioned packet captures.

## API and metrics

Install `.[api]` and run `uvicorn pqtls.api:app`. Liveness and readiness endpoints are available. The Prometheus endpoint exports service availability only; it does not synthesize measurement metrics.

## Deployment

The multi-stage image installs runtime tools, drops root privileges, and uses a non-root UID. Compose defaults to a read-only root filesystem, drops Linux capabilities, and mounts only the results directory. Restrict network egress and mount captures/key logs read-only in production.

## Remaining production gates

- Add real, versioned full and ticket-resumed TLS 1.3 PCAP fixtures from controlled hybrid-PQC endpoints, with capture provenance and expected dissector output.
- Validate tshark field names, TCP reassembly behavior and timing extraction against each supported Wireshark release.
- Distinguish ticket resumption from external PSKs using ticket provenance or controlled endpoint-side session metadata; do not infer it from PSK selection alone.
- Add capture-drop reporting and validate retransmission accounting under packet loss, reordering, IPv4/IPv6 and sequence wraparound.
- Add signed audit checkpoints, external immutable storage, authentication/authorization, rate limiting and tenant isolation before exposing the API.
- Pin dependencies with hashes, run vulnerability scans and publish an SBOM in release CI.
- Meet a measured coverage target and complete independent security review before production claims.
