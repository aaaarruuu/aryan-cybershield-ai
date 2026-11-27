# Build context is the repository root (the backend reads ../sample_data at runtime):
#   docker build -f backend/Dockerfile -t cybershield-backend .
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 ANONYMIZED_TELEMETRY=False

RUN useradd --create-home --uid 10001 appuser
WORKDIR /srv/backend

COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/ /srv/backend/
COPY sample_data/ /srv/sample_data/
RUN chmod +x /srv/backend/entrypoint.sh \
 && mkdir -p /data/chroma /srv/backend/app/ml/artifacts \
 && chown -R appuser:appuser /data /srv/backend/app/ml/artifacts

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"
ENTRYPOINT ["/srv/backend/entrypoint.sh"]
