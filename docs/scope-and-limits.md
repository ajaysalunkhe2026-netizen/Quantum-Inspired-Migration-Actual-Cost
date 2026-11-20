# Scope and Limits

**Author:** Ajay Salunkhe

## Purpose

This document defines the evidence required to discuss the engineering cost of migrating a cryptographic deployment toward post-quantum cryptography (PQC).

The lab separates three things that are often conflated:

- Protocol-defined sizes and behaviour.
- Values calculated from stated inputs.
- Observations made on a real implementation and network path.

A value derived from a standard is not an implementation measurement.

## In scope

### Key-exchange size

Record the selected group and the encoded client and server key-share lengths. Where available, separately record the containing TLS handshake message, TLS record, TCP payload, and total network traffic. These are different measurement boundaries.

### Certificate and signature growth

Record each transmitted certificate's DER length, the total transmitted chain length, public-key encoding length, CertificateVerify signature length, and the relevant TLS handshake message lengths.

Keep certificate-chain composition and unrelated certificate fields constant when attributing a difference to a cryptographic algorithm. If they are not constant, document the differences.

### Handshake behaviour

Distinguish full handshakes from resumed sessions. Record offered groups, the selected group, the PSK key-exchange mode where applicable, handshake completion, failure stage, and timing boundaries.

### Operational effects

Where an actual test environment exists, measure CPU time, memory use, latency distribution, bytes transferred, retransmissions, fragmentation, session-ticket sizes, and compatibility outcomes. Identify the instrumentation and sampling method for each metric.

## Out of scope

Unless a separately scoped experiment is added, this repository does not measure:

- Quantum-computer capability or quantum attack cost.
- Formal cryptographic security proofs or algorithm security strength.
- Complete enterprise cryptographic inventories.
- Complete software dependency or CBOM coverage.
- Organisation-wide labour, procurement, licensing, or migration budgets.
- Regulatory compliance or certification.
- The probability of compromise.
- General PQC readiness.
- The behaviour of every client, server, proxy, CDN, firewall, or load balancer.

A small test sample must not be extrapolated to an organisation-wide cost without a separately justified sampling plan and cost model.

## What a clean number requires

Every reported number must identify a baseline, a path, and a method. It must also state the result and its limits.

### Baseline

Name the exact configuration used for comparison. Examples include TLS 1.3 with X25519, TLS 1.3 with secp256r1 (P-256), or a specific existing certificate chain.

Record protocol version, group, authentication configuration, and relevant implementation settings. An algorithm name alone is not a sufficient baseline.

### Path

Identify the actual client-to-server path:

- Client application, version, and TLS library.
- Server application, version, and TLS library.
- Operating system and hardware.
- Network topology and test location.
- Proxy, load balancer, CDN, TLS inspection device, or other intermediary.
- Whether the observation was direct or traversed intermediaries.

State explicitly when an intermediary is absent or when part of the path is unknown.

### Method

Describe how the value was obtained. Examples include:

- Packet capture with documented capture points and filters.
- TLS library handshake trace.
- Certificate DER byte counting.
- Client- or server-side timing instrumentation.
- Operating-system resource instrumentation.

Define the measurement boundary, units, sample count, and any exclusions. For timing, state the statistic reported and the treatment of failures and outliers.

### Result

Report the observed value, unit, sample count, summary statistic, baseline value, absolute delta, and relative delta when meaningful.

Do not report a percentage increase when the baseline is zero. Do not combine values measured at different boundaries.

### Limits

State what the result cannot establish. For example, a key-share delta does not establish the total handshake delta, and a successful handshake does not establish compatibility across other network paths.

## Evidence labels

Use one of the following labels for each published value:

- **Specification-derived:** directly stated in a specification or calculated from specification-defined values.
- **Measured:** observed on the documented implementation and path.
- **Calculated:** derived from explicitly stated measured or specification-derived inputs.
- **Example:** illustrative value, not an observation.
- **Planning bound:** assumption used for planning, not an observation.
- **Incomplete:** missing one or more required fields.

Never relabel an example, planning bound, or specification calculation as a measured result.

**Lab view. The label is not the measurement.**
