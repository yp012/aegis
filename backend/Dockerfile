# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-deps -r requirements.txt

FROM python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"
RUN groupadd --system --gid 10001 aegis \
    && useradd --system --uid 10001 --gid aegis --home-dir /app --shell /usr/sbin/nologin aegis
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --chown=aegis:aegis app ./app
COPY --chown=aegis:aegis alembic ./alembic
COPY --chown=aegis:aegis alembic.ini ./alembic.ini
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
