# Sample Cost Row

**Author:** Ajay Salunkhe

## Purpose

The row below demonstrates the required recording structure. Its values are an illustrative, specification-derived example, not an observation from a packet capture or running implementation.

## Example: combined key-share size

| Field | Recorded value |
|---|---|
| Measurement ID | `EXAMPLE-KX-001` |
| Category | TLS 1.3 key-exchange encoded share size |
| Path | Client key share plus server key share |
| Baseline | X25519 |
| Baseline method | 32-byte client share + 32-byte server share |
| Baseline result | 64 bytes |
| Candidate | X25519MLKEM768 |
| Candidate method | 1,216-byte client share + 1,120-byte server share |
| Candidate result | 2,336 bytes |
| Result | +2,272 bytes |
| Evidence status | Specification-derived arithmetic; not measured |
| Source | RFC 10024, Section 4 |
| Limit | Excludes TLS framing, certificates, signatures, tickets, records, transport headers, retransmissions, and application data |

## Interpretation

This example compares the encoded key-exchange values in both directions. It does not measure a complete TLS handshake, a TLS record, or total network traffic.

A real measurement row must replace the example with the actual client and server versions, exact path, capture or instrumentation method, observed values, sample count, and limitations.

**Lab view. The label is not the measurement.**
