# Keep the FROM line identical to the non-comment line in router/base-image.pin.
FROM python:3.14.7-slim-trixie@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8090 \
    SMART_ROUTER_NONCE_JOURNAL_PATH=/var/lib/winsvpn-router/replay-nonces.sqlite3 \
    DECISIONS_FILE=/var/lib/winsvpn-router/router-decisions.jsonl

# Runtime hashed closure only. Deploy-time secrets stay in the process
# environment and are never copied into the image.
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r requirements.lock

COPY schemas.py provider_common.py local_gemma_client.py gemini_client.py security.py fallback.py main.py ./

# Replay admission is durable and fail-closed.  The process therefore runs as a
# dedicated non-root user with exactly one private writable state directory.
RUN groupadd --system winsrouter \
    && useradd --system --gid winsrouter --home-dir /nonexistent --shell /usr/sbin/nologin winsrouter \
    && install -d -o winsrouter -g winsrouter -m 0700 /var/lib/winsvpn-router

USER winsrouter:winsrouter

EXPOSE 8090

HEALTHCHECK --interval=15s --timeout=2s --start-period=10s --retries=3 \
    CMD python -I -c "import json,os,urllib.request; port=os.environ.get('PORT','8090'); opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); response=opener.open('http://127.0.0.1:%s/ready'%port, timeout=1); body=json.loads(response.read(4096)); raise SystemExit(0 if response.status==200 and body.get('ok') is True and set(body)=={'ok','version'} else 1)"

CMD ["sh", "-c", "exec uvicorn main:app --host 0.0.0.0 --port ${PORT} --no-access-log"]
