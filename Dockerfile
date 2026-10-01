# syntax=docker/dockerfile:1
#
# Production image for QRShare.
#
#   docker build -t qrshare .
#   docker run -p 8000:8000 --env-file .env \
#     -v qrshare-storage:/data/storage -v qrshare-db:/data/db qrshare
#
# Both volumes matter: the encrypted blobs and the database must survive a
# container restart, and losing either one makes existing shares unusable.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Build tools are needed for argon2-cffi's C extension but not at runtime, so
# they are installed and removed within a single layer.
COPY requirements.txt .
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libffi-dev \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir "gunicorn==22.0.0" \
 && apt-get purge -y gcc libffi-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY app/ ./app/
COPY run.py manage.py ./

# Never run as root: an upload handler that is also uid 0 turns any file-write
# bug into a host compromise.
RUN useradd --create-home --shell /usr/sbin/nologin qrshare \
 && mkdir -p /data/storage /data/db /app/instance \
 && chown -R qrshare:qrshare /data /app

USER qrshare

ENV FLASK_ENV=production \
    STORAGE_PATH=/data/storage \
    DATABASE_URL=sqlite:////data/db/qrshare.db \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"

# One worker with threads, deliberately: the default rate limiter and the
# cleanup scheduler are per-process. Scale to several workers only after
# pointing RATE_LIMIT_STORAGE_URI at a shared store (e.g. redis://...).
CMD ["gunicorn", "--bind", "0.0.0.0:8000", \
     "--workers", "1", "--threads", "8", \
     "--timeout", "300", \
     "--access-logfile", "-", "--error-logfile", "-", \
     "run:app"]
