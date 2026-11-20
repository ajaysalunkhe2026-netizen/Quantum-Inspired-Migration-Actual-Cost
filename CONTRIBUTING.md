# Contributing

- Keep every metric evidence-backed. Never add defaults or placeholder values.
- Every metric needs a named baseline, path, method, limits, and provenance.
- Use null plus a reason when a parser cannot prove a value.
- Add parser fixtures only from genuine tool output and retain provenance.
- Requested protocol settings must never be reported as negotiated outcomes.
- Run pytest, ruff check ., black --check ., and mypy src/pqtls before submitting.
