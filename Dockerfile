FROM python:3.12-slim AS build
ENV VIRTUAL_ENV=/opt/venv PATH="/opt/venv/bin:$PATH" PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

FROM python:3.12-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates tshark \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 pqtls \
    && useradd --system --uid 10001 --gid pqtls --home-dir /app --create-home pqtls
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["pqtls"]
