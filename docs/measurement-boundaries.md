# Measurement boundaries

## Current live adapter

The adapter makes a real TCP/TLS connection using openssl s_client, saves the combined output, records tool version and command, extracts DER sizes from peer certificates printed as PEM, and measures local process wall-clock duration.

The adapter intentionally does not claim to parse raw TLS structures. Key-share lengths, CertificateVerify signature lengths, handshake-message bytes, TLS-record bytes, TCP/IP bytes, and resumption state remain null with an explicit reason.

## Three byte domains

1. Handshake-message bytes: serialized TLS Handshake messages, excluding TLS record headers.
2. TLS-record bytes: TLS record headers and payloads carrying handshake messages, excluding TCP/IP headers.
3. TCP/IP bytes: captured network-layer packet bytes under a documented capture-point policy. State whether retransmissions, Ethernet headers, VLAN tags, IP/TCP headers, and offload artefacts are included.

Never derive one domain by adding guessed headers to another.

## TLS 1.3 encryption

ClientHello and ServerHello are visible in a passive capture. Most subsequent handshake messages, including Certificate and CertificateVerify, are encrypted after ServerHello. Decryption requires session secrets (for example an NSS key log); the server private key alone is not sufficient for TLS 1.3 ephemeral key exchange.

## Timing and resumption

client_process_duration wraps process launch, DNS, TCP/TLS negotiation, and shutdown. It is not pure handshake RTT or CPU time. A second TCP connection is not automatically resumed; protocol evidence such as PSK selection is required. The current adapter sets session kind to unknown.

## Evidence contract

Every metric carries label, baseline, path, method, limits, and provenance. Missing values are null with not_measured_reason. A requested group is not a negotiated group; only parsed server evidence may populate negotiated_group.
