FROM ghcr.io/astral-sh/uv:python3.13-alpine
ADD . /app
WORKDIR /app
RUN uv sync --locked
CMD ["uv", "run", "fastapi", "run", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]