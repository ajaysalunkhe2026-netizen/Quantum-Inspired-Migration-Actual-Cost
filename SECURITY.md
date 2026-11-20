# Security policy

## Reporting a vulnerability

Do not publish exploit details, credentials, private keys, TLS key logs, or sensitive PCAPs in public issues. Report suspected vulnerabilities privately through the repository owner's GitHub security reporting channel where enabled.

## Operational safeguards

- Treat NSS TLS key-log files and packet captures as sensitive material.
- Use least-privilege filesystem permissions and non-root containers.
- Do not expose the optional API publicly without authentication, authorization, rate limiting and TLS termination.
- Keep audit logs in independently controlled immutable storage for high-assurance environments.
- Review dependencies and container images before each deployment.
- Never use this tool to probe systems without authorization.

## Evidence integrity

Measurements must preserve provenance and boundaries. A parser that cannot prove a field must emit null with a reason; never substitute estimates or defaults.
