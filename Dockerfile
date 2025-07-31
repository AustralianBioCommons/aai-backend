FROM ghcr.io/astral-sh/uv:python3.13-alpine
ADD . /app
WORKDIR /app
RUN uv sync --locked
CMD ["uv", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
