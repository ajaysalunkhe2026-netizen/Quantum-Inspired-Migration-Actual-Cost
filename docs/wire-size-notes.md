# Wire-Size Notes

**Author:** Ajay Salunkhe

## Measurement boundary

This note compares encoded TLS 1.3 key-exchange `key_exchange` values. It does not describe complete TLS handshake bytes, TLS record bytes, TCP/IP bytes, or a packet-capture result.

## X25519MLKEM768 share sizes

RFC 10024 specifies these values for the X25519MLKEM768 group:

| Direction | Component | Length |
|---|---|---:|
| Client | ML-KEM-768 encapsulation key | 1,184 bytes |
| Client | X25519 ephemeral share | 32 bytes |
| Client | Combined key share | 1,216 bytes |
| Server | ML-KEM ciphertext | 1,088 bytes |
| Server | X25519 ephemeral share | 32 bytes |
| Server | Combined key share | 1,120 bytes |

Combined client and server key-exchange values:

`1,216 + 1,120 = 2,336 bytes`

These are specification-defined encoded values.

## Fixed baseline deltas

### X25519 to X25519MLKEM768

Baseline:

- Client X25519 share: 32 bytes.
- Server X25519 share: 32 bytes.
- Combined baseline: 64 bytes.

Hybrid candidate:

- Client X25519MLKEM768 share: 1,216 bytes.
- Server X25519MLKEM768 share: 1,120 bytes.
- Combined candidate: 2,336 bytes.

`2,336 - 64 = 2,272 bytes`

**Specification-derived combined share delta: +2,272 bytes.**

### P-256 baseline to X25519MLKEM768

For an uncompressed secp256r1 (P-256) TLS key share, the point encoding is 65 bytes.

Baseline:

- Client P-256 share: 65 bytes.
- Server P-256 share: 65 bytes.
- Combined baseline: 130 bytes.

Candidate:

- Client X25519MLKEM768 share: 1,216 bytes.
- Server X25519MLKEM768 share: 1,120 bytes.
- Combined candidate: 2,336 bytes.

`2,336 - 130 = 2,206 bytes`

**Specification-derived combined share delta: +2,206 bytes.**

This is a size comparison between a P-256 classical baseline and the X25519MLKEM768 hybrid candidate. It is not a like-for-like P-256 hybrid group comparison. RFC 10024 separately specifies SecP256r1MLKEM768 with its own client and server share sizes.

## Certificate and ML-DSA growth is separate

Certificate and signature growth is a separate, additional measurement term. Do not add an assumed certificate increase to these key-share deltas.

Measure independently:

- Leaf certificate DER length.
- Each intermediate certificate DER length.
- Total transmitted certificate-chain length.
- Public-key encoding length.
- Certificate signature length.
- TLS Certificate message length.
- TLS CertificateVerify signature and message length.

The result depends on the selected signature scheme, certificate profile, chain composition, encoding, and implementation. This repository does not publish a universal ML-DSA certificate-growth number.

## What these deltas exclude

The arithmetic above excludes:

- TLS handshake message framing.
- TLS record headers.
- Other extensions and handshake fields.
- Certificate and CertificateVerify messages.
- Finished messages.
- Session tickets.
- TCP/IP headers.
- Retransmissions and fragmentation.
- Application data.

A packet capture can therefore show a different total network-byte delta.

## Calculation rules

For identical measurement boundaries:

`delta_bytes = candidate_bytes - baseline_bytes`

`relative_increase_percent = (delta_bytes / baseline_bytes) * 100`

Only calculate a relative increase when the baseline is non-zero. Record direction and measurement boundary. Never combine a key-share value with a full-record or packet total.

Any number without a named baseline is incomplete.

## References

- [RFC 10024, Section 4 — Negotiated Groups](https://www.rfc-editor.org/rfc/rfc10024.html)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)

**Evidence status:** Specification-derived arithmetic only. No implementation or network measurement is claimed.
