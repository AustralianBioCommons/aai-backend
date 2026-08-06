FROM ghcr.io/astral-sh/uv:python3.13-alpine
# Force latest Alpine security patches (e.g. libssl3/libcrypto3 OpenSSL fixes)
# at build time, independent of how stale the cached base image layer is.
RUN apk update && apk upgrade --no-cache
ADD . /app
WORKDIR /app
ENV PYTHONPATH=/app \
    UVICORN_APP_DIR=/app
RUN uv sync --locked
CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
