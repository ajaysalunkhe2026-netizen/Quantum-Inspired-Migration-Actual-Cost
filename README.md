# Measuring Actual Cost of PQC Migration

**Independent lab work by Ajay Salunkhe**

This repository is a documentation-first lab for measuring the engineering and operational cost of migrating deployed cryptographic systems toward post-quantum cryptography (PQC).

The working rule is simple: measure the change against a named baseline, on a documented path, using a reproducible method. Do not substitute algorithm labels, configuration flags, or dashboard status for evidence.

**Lab view. The label is not the measurement.**

## What is measured

The repository defines a method for recording four categories of evidence:

1. **Key-exchange wire size**
   - Client and server key-share lengths.
   - Classical-to-hybrid byte deltas.
   - TLS handshake, record, and transport bytes when captured separately.
2. **Certificate and signature growth**
   - Individual certificate DER sizes and total transmitted chain size.
   - Public-key encoding and signature sizes.
   - TLS Certificate and CertificateVerify message sizes.
3. **Handshake behaviour**
   - Full versus resumed TLS sessions.
   - Offered and selected groups.
   - Handshake completion, timing, failures, retransmissions, and fragmentation.
4. **Operational effects**
   - Client/server CPU time and memory use.
   - Network bytes and latency distributions.
   - Session-ticket size and resumption behaviour.
   - Compatibility observations across clients, proxies, load balancers, and middleboxes.

A measurement is published only with its baseline, path, method, result, and limits. Specification-derived arithmetic is identified as such; it is not presented as a packet-capture result.

## What is not measured

This repository does not currently publish implementation benchmarks or operational measurements. It does not estimate quantum attack cost, cryptographic security strength, organisation-wide migration budgets, or the probability of compromise.

It does not claim complete cryptographic discovery, complete CBOM coverage, compliance, certification, or migration readiness.

## What this is not

- A quantum-computer simulator.
- A quantum-inspired optimiser.
- A migration automation engine.
- A vulnerability scanner.
- A production monitoring service or dashboard.
- A source of synthetic benchmark results or assumed cost savings.
- A certification or proof that a system is quantum-safe.

No random data, dummy migrations, or fabricated measurements are used.

## How to use

1. Read [Scope and limits](docs/scope-and-limits.md) before interpreting a number.
2. Review [Wire-size notes](docs/wire-size-notes.md) for specification-derived share sizes and comparison boundaries.
3. Use [Handshake and operational notes](docs/handshake-and-operational-notes.md) to define the test path and logging.
4. Record observations using [the sample cost row](examples/sample-cost-row.md).
5. Replace illustrative fields with evidence from a real, reproducible test environment before publishing a measured result.

No runtime installation is required. This repository currently contains documentation only.

## Evidence status

The wire-size arithmetic in this repository is derived from published protocol specifications and explicitly stated baselines. No TLS implementation benchmark, packet capture, latency result, CPU result, or operational compatibility result is claimed here.

## References

- [RFC 10024 — Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024.html)
- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)

---

**Author:** Ajay Salunkhe  
**Purpose:** Independent PQC migration-cost measurement  
**Evidence policy:** Measurement over labels.
