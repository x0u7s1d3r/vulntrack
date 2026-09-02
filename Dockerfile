# ---------- Stage 1 : build des dépendances ----------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---------- Stage 2 : image finale ----------
FROM python:3.12-slim AS runtime

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    libpq5 curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r vulntrack && useradd -r -g vulntrack -d /app -s /sbin/nologin vulntrack

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --chown=vulntrack:vulntrack app/ ./app/
COPY --chown=vulntrack:vulntrack alembic/ ./alembic/
COPY --chown=vulntrack:vulntrack alembic.ini .
COPY --chown=vulntrack:vulntrack worker.py .
# /data/reports : volume des rapports bruts (persistant).
# /data/prometheus : fichiers de metriques multi-process, local au conteneur
# et ephemere (jamais monte en volume) - chaque worker uvicorn y ecrit.
RUN mkdir -p /data/reports /data/prometheus && chown -R vulntrack:vulntrack /data

USER vulntrack

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1


# Forme shell + exec (pas la forme exec-array) pour permettre la
# substitution de UVICORN_WORKERS par le nombre de replicas voulu (voir
# docker-compose.yml, etape 10 - haute disponibilite). `exec` est essentiel :
# sans lui, ce serait le shell qui recevrait SIGTERM en PID 1, pas uvicorn,
# et l'arret gracieux de l'etape 7 cesserait de fonctionner silencieusement.
#
# Le repertoire de metriques multi-process est vide au demarrage : sans ca,
# des fichiers d'une execution precedente (workers a PID different) seraient
# agreges par erreur. Fait avant le lancement du master uvicorn, une seule
# fois pour tous ses workers.
CMD ["sh", "-c", "rm -f ${PROMETHEUS_MULTIPROC_DIR:-/data/prometheus}/* 2>/dev/null; exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-server-header --workers ${UVICORN_WORKERS:-4} --timeout-graceful-shutdown 20"]

# ---------- Stage 3 : image du worker (avec les scanners) ----------
# Les scanners ne vivent QUE dans l'image du worker (composant NON expose),
# jamais dans l'API. Trivy telecharge lui-meme les images via son propre
# client de registre -> AUCUN acces au socket Docker necessaire.
FROM runtime AS worker
USER root
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
# Trivy (binaire epingle)
RUN TRIVY_VERSION=0.74.0 \
    && curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
       | tar -xz -C /usr/local/bin trivy
# Gitleaks (binaire epingle)
RUN GITLEAKS_VERSION=8.18.4 \
    && curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
       | tar -xz -C /usr/local/bin gitleaks
# Semgrep (paquet Python, version epinglee pour des builds reproductibles)
RUN pip install --no-cache-dir semgrep==1.176.0
# Caches accessibles en non-root (Trivy: base de vulns ; HOME: cache Semgrep/git)
RUN mkdir -p /data/trivy-cache && chown -R vulntrack:vulntrack /data/trivy-cache
ENV TRIVY_CACHE_DIR=/data/trivy-cache
ENV HOME=/tmp
USER vulntrack
