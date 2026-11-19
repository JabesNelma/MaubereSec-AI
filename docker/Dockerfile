# MaubereSec AI CLI runtime (v0.1)
# Non-root, read-only-rootfs compatible, no Docker socket, no scanners yet.
FROM python:3.12-slim-bookworm

# Pin pip behavior and avoid cache writes for read-only friendliness.
# Retries/longer timeouts keep image builds resilient on slow networks.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=10

WORKDIR /app

# Install as a regular user.
COPY pyproject.toml README.md ./
COPY mauberesec ./mauberesec
RUN pip install --no-cache-dir .

RUN useradd --system --create-home --shell /usr/sbin/nologin msai
USER msai

# Writable tmp only; root filesystem can be mounted read-only.
VOLUME ["/tmp"]

ENTRYPOINT ["mauberesec"]
CMD ["--help"]
