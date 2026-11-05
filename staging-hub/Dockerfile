# Staging-hub image. Staging only; not release evidence.
# This image does not prove release readiness.
#
# Base image is the current reviewed stable CPython slim, pinned by the
# immutable OCI image-index digest in staging-hub/base-image.pin. The index
# covers linux/amd64 and linux/arm64; pull selects the matching platform.
FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

WORKDIR /srv/app

# PIP_CONFIG_FILE=/dev/null ignores ambient pip.conf extra-index substitution.
# Empty PIP_EXTRA_INDEX_URL / PIP_FIND_LINKS prevent extra indexes.
# PIP_INDEX_URL is the single allowed index; hashes still bind every wheel.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_CONFIG_FILE=/dev/null \
    PIP_INDEX_URL=https://pypi.org/simple \
    PIP_EXTRA_INDEX_URL="" \
    PIP_FIND_LINKS="" \
    DEBIAN_FRONTEND=noninteractive \
    DEBIAN_SNAPSHOT=20260823T000000Z

# Build context is the REPO ROOT (the image needs tools/winn3_descriptor_ring_defines.py,
# which a staging-hub/-only context cannot reach):
#   docker build -t wins-staging-hub -f staging-hub/Dockerfile .
COPY staging-hub/requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
      --index-url https://pypi.org/simple \
      --no-input \
      -r requirements.lock

COPY staging-hub/app.py staging-hub/nodes.json ./
COPY staging-hub/descriptors ./descriptors
# The pinned descriptor ring define (single source of truth), staged beside
# app.py so F-06 serve-time signature verification can load it.
COPY tools/winn3_descriptor_ring_defines.py ./winn3_descriptor_ring_defines.py

# openssl CLI is not in python slim. Install it from a frozen Debian snapshot
# so apt cannot float to current-mirror latest. Staging only; not release
# evidence. Default debian.sources is removed so snapshot is the only input.
RUN printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} trixie-security main" \
    > /etc/apt/sources.list \
 && rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends \
      --no-upgrade \
      openssl \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /srv/hub

EXPOSE 8080

# D-3: --no-access-log keeps client source addresses out of uvicorn's
# request log; /nodes, /health and app-level logs stay intact.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
