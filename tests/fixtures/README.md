# Real TLS 1.3 PCAP fixtures

The `pcap/` directory contains real packet captures generated from controlled OpenSSL TLS endpoints. They are not handcrafted packets or mocked tshark output.

## Fixture matrix

| Capture | TLS group | Expected handshake |
|---|---|---|
| `tls13-x25519mlkem768-full.pcap` | X25519MLKEM768 | Full certificate handshake |
| `tls13-x25519mlkem768-resumed.pcap` | X25519MLKEM768 | Ticket-based PSK resumption |
| `tls13-x25519-full.pcap` | X25519 | Full certificate handshake |

The generator uses OpenSSL `s_server` and `s_client` on the loopback interface, with `tcpdump` capturing the actual TCP/IP packets. It generates an ephemeral self-signed certificate and a fixture-only HTTP GET request. The private key is never committed. The hybrid full-handshake session exports a TLS 1.3 ticket; the resumed connection reuses that session on the same server process. OpenSSL endpoint output must contain `Reused, TLSv1.3` before the resumed fixture is accepted.

## Reproduction

Run on Debian 13 (Trixie) or another environment with OpenSSL 3.5+ supporting both groups, tcpdump, tshark, Python 3.11+, and the project test dependencies:

```bash
python scripts/generate_pcap_fixtures.py
pytest -q tests/test_pcap_integration.py
```

The dedicated GitHub Actions workflow runs in Debian Trixie with packet-capture capabilities, validates the captures, uploads an evidence artifact, and commits only validated fixtures to the PR branch. The manifest records OpenSSL/tcpdump/tshark versions, capture interface/filter, endpoint evidence, and SHA-256 digests for each capture and key log.

## TLS key logs

The `.keys` files are intentionally public, test-only TLS traffic secrets. They can decrypt only the sanitized loopback fixture sessions in this directory. They contain no production credentials, and the ephemeral server private key is not included. Never reuse these files, the fixture certificate, or this test pattern with real user traffic. Integration tests change key-log permissions to `0600` before passing them to the analyzer.

## Measurement validation

Integration tests independently query tshark for handshake event timestamps and TCP packet fields. They compare ClientHello-to-Finished intervals and per-direction IP/payload totals against the analyzer output. Full handshakes require decoded ClientHello, ServerHello, server Certificate, CertificateVerify, and both Finished messages. Resumption requires a PSK-selected identity, an abbreviated handshake without Certificate/CertificateVerify, both Finished messages, and explicit endpoint-side session-reuse confirmation. PSK selection by itself remains `unknown`.

Unavailable metrics must remain null, carry the `Not measured` label, and include a reason. A metric with a non-null value must have the `Measured` label and source artifact.

## Limits

- Loopback captures validate dissector and accounting behavior, not WAN latency or NIC offload behavior.
- Handshake timing is the capture timestamp interval between decoded protocol events, not endpoint processing time.
- The endpoint reuse confirmation is corroborating evidence from OpenSSL; the PCAP alone cannot prove whether a PSK originated from a ticket or an externally configured PSK.
- The fixture key logs are public only because the captures contain test traffic; never treat key logs from real traffic as shareable.
