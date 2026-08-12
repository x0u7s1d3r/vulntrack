# ---------- Stage 1 : build des dépendances ----------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---------- Stage 2 : image finale ----------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r vulntrack && useradd -r -g vulntrack -d /app -s /sbin/nologin vulntrack

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --chown=vulntrack:vulntrack app/ ./app/
COPY --chown=vulntrack:vulntrack alembic/ ./alembic/
COPY --chown=vulntrack:vulntrack alembic.ini .

USER vulntrack

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
