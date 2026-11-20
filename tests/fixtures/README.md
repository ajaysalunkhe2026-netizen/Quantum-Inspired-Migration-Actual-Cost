# PCAP fixture policy

No real packet-capture fixture is currently checked into this directory.

The current automated tests mock tshark's field output and exercise TCP sequence-range accounting. Those tests are synthetic unit tests, not real PCAP integration evidence, and must not be cited as validation of a hybrid post-quantum TLS handshake.

A fixture may be added only when all of the following are recorded:

- Capture provenance: controlled endpoint implementation, exact versions/builds, date, and capture point.
- TLS configuration: TLS version, negotiated group, signature algorithm, full/resumed test intent, and whether a TLS key log is supplied.
- Toolchain: exact tshark/Wireshark version and relevant dissector fields.
- Integrity: SHA-256 of the original PCAP/PCAPNG and a sanitized, non-secret fixture.
- Ground truth: endpoint-side handshake/session logs and independently checked expected packet, record, handshake, direction, retransmission, and timing values.
- Licensing/privacy: permission to redistribute the capture and confirmation that it contains no credentials or personal data.

Required initial fixture matrix:

| Fixture ID | Expected handshake | Required evidence |
|---|---|---|
| `tls13-hybrid-full-v1` | Full certificate handshake using a hybrid key-exchange group | ClientHello, ServerHello key_share group, Certificate, CertificateVerify, both Finished events |
| `tls13-ticket-resumed-v1` | Ticket-based PSK resumption | Prior NewSessionTicket provenance, ticket identity correlation, selected PSK identity, endpoint-side session-reuse confirmation |
| `tls13-external-psk-v1` | External PSK (negative control) | External PSK configuration and selected identity; must not be mislabeled as ticket resumption |

Do not add placeholder bytes with a `.pcap` extension. Until these captures exist and pass integration tests, the corresponding production-validation gate remains open.
