# One image for every knok process: the hub, a bridge, or the CLI. The role is chosen by the
# command, not by the image, so a hub and an agent run byte-identical code.
FROM python:3.12-slim

# The only runtime dependency is `cryptography` for Ed25519/X25519. It arrives as a wheel, so no
# compiler or build toolchain is needed in the image — which keeps the finished layer small and
# free of anything an agent could shell out to.
RUN useradd --create-home --uid 10001 knok \
 && pip install --no-cache-dir "cryptography==50.0.2"

WORKDIR /app
COPY pyproject.toml /app/
COPY src /app/src
ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# State lives on a volume: keys, queue and policy for a bridge; the mailbox store for a hub.
RUN mkdir -p /app/state && chown -R knok:knok /app
USER knok

ENTRYPOINT ["python", "-m"]
