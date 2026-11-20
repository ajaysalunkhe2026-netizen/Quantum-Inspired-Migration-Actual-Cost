# Handshake and Operational Notes

**Author:** Ajay Salunkhe

## Purpose

PQC migration measurements must distinguish configuration, negotiation, and successful operation. A dashboard label such as "PQC enabled" does not prove that an individual connection selected a hybrid group or completed a handshake using it.

Inspect the actual handshake and record the path.

## Full TLS 1.3 handshake

A typical certificate-authenticated full TLS 1.3 handshake includes:

1. ClientHello.
2. ServerHello.
3. EncryptedExtensions.
4. Certificate.
5. CertificateVerify.
6. Finished messages.
7. Application data after the handshake completes.

The precise message sequence depends on authentication and negotiated options.

For a hybrid key exchange, record the client-offered groups, the key shares actually sent, and the group selected by the server. Record handshake success only after the relevant Finished processing has completed successfully.

A ServerHello that selects a group is evidence of negotiation. It is not, on its own, evidence that the handshake completed.

## Resumed sessions

TLS 1.3 resumption uses pre-shared keys (PSKs). Two PSK key-exchange modes matter:

- `psk_ke`: PSK-only key exchange.
- `psk_dhe_ke`: PSK combined with a fresh ephemeral Diffie-Hellman key exchange.

These modes do not exercise the same work.

A PSK-only resumed handshake does not perform a fresh ephemeral key exchange. A resumed handshake using `psk_dhe_ke` does. Certificate messages are generally not sent again during a resumed PSK handshake.

Record full and resumed sessions as separate populations. For resumed sessions, record the selected PSK mode and whether a fresh key share was present. Do not attribute a full-handshake key-share delta to a PSK-only resumption.

## Session tickets

TLS 1.3 servers can send NewSessionTicket messages after a handshake. Ticket length is implementation- and configuration-dependent; it is not determined solely by the selected key-exchange group.

Record:

- NewSessionTicket handshake message length.
- Ticket opaque value length.
- Number of tickets issued.
- Ticket lifetime.
- Whether the client stored and reused the ticket.
- Whether the server uses stateless tickets or server-side session state, if known.
- Resumption success or failure.

Do not treat ticket bytes as certificate bytes or key-share bytes.

## Middlebox and path behaviour

A larger handshake can interact differently with firewalls, reverse proxies, TLS inspection devices, load balancers, CDNs, and legacy clients.

Possible observations include resets, timeouts, fragmentation, dropped messages, fallback, or implementation incompatibility. These are possible test outcomes, not assumed consequences.

Record the exact path and the location of each capture. A direct client-to-server test does not establish behaviour through an intermediary.

## Why "PQC enabled" is not a measurement

A server may be configured to support a hybrid group, while a particular connection negotiates another group.

Keep these distinct:

1. Groups configured on the client and server.
2. Groups offered in ClientHello.
3. Key shares sent by the client.
4. Group selected in ServerHello.
5. Handshake completion, including Finished processing.
6. Full or resumed session and PSK mode.

For a full handshake, inspect the ServerHello key_share selection and the handshake trace. For a resumed handshake, also inspect the PSK key-exchange mode. A group in a supported-groups list is not proof that it was selected.

## What to log

### Test identity and path

- Run ID and timestamp.
- Client and server identifiers.
- Source and destination network path.
- Capture point and test location.
- Proxy, load balancer, CDN, firewall, or TLS inspection device on the path.

### Software and platform

- Client application and version.
- Server application and version.
- TLS library and version.
- Operating system and version.
- Hardware and relevant runtime configuration.

### Negotiation

- TLS protocol version.
- Cipher suite.
- Client-offered groups.
- Client key shares and lengths.
- Selected group and server key-share length.
- Full or resumed handshake.
- PSK mode, if resumed.
- Authentication method.

### Completion and timing

- Handshake start and end boundaries.
- Handshake completion result.
- Finished processing result.
- Failure stage and TLS alert, if any.
- Timing measurement point and clock source.

### Network

- Client-to-server handshake bytes.
- Server-to-client handshake bytes.
- TLS record bytes.
- TCP payload bytes.
- Retransmissions.
- Fragmentation observations.
- Resets and timeouts.

### Certificates and tickets

- Certificate-chain composition.
- Individual certificate DER lengths.
- Total transmitted chain length.
- CertificateVerify signature length.
- Certificate and CertificateVerify message lengths.
- NewSessionTicket message and ticket-value lengths.
- Ticket count and lifetime.

### Resource use

- Client CPU time.
- Server CPU time.
- Memory metric and sampling method.
- Instrumentation tool and version.

## Experimental discipline

Compare configurations with the same client, server, protocol settings, authentication profile, and network path wherever possible. Document unavoidable differences.

Report the number of trials, the statistic used, and the handling of failed attempts. Do not silently discard failures or combine full and resumed sessions.

A successful hybrid handshake proves only that the tested connection succeeded under the recorded conditions. It does not establish universal compatibility or complete application migration.

**Lab view. The label is not the measurement.**

## References

- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 10024 — Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3](https://www.rfc-editor.org/rfc/rfc10024.html)
