FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt .
RUN pip install -r requirements.txt

# Fetch the official MITRE ATT&CK Enterprise STIX bundle at build time (cached layer).
COPY scripts ./scripts
RUN python scripts/fetch_stix.py data/enterprise-attack.json

COPY app ./app
COPY eval ./eval
COPY tests ./tests

RUN useradd --system --uid 10001 rakshak && chown -R rakshak /srv
USER rakshak

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
