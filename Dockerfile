# syntax=docker/dockerfile:1.6
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:/root/.local/bin:/root/.cargo/bin:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    curl \
    libxml2-dev \
    libxslt1-dev \
    libjpeg62-turbo-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv (https://github.com/astral-sh/uv)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    (ln -sf /root/.local/bin/uv /usr/local/bin/uv || true) && \
    (ln -sf /root/.cargo/bin/uv /usr/local/bin/uv || true) && \
    uv --version

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev

COPY . .

# Copy the entrypoint script explicitly AFTER COPY . . and fix line endings
# This ensures we always get the correct version with LF endings
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Ensure the entrypoint has Unix line endings (fixes CRLF issues when building on Windows)
# then make it executable
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh && \
    chmod +x /app/docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
