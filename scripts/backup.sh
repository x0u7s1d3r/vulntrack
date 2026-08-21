#!/usr/bin/env bash
#
# Sauvegarde la base VulnTrack depuis le conteneur db du stack Docker Compose.
# Ne necessite pas de client PostgreSQL sur l'hote : pg_dump s'execute dans
# le conteneur. Format custom (-Fc), compresse et restaurable selectivement
# via pg_restore.
#
# Usage : ./scripts/backup.sh
# Variable optionnelle : BACKUP_DIR (defaut: backups/), BACKUP_RETENTION (defaut: 14)

set -euo pipefail

# Se placer a la racine du projet (le script est dans scripts/).
cd "$(dirname "$0")/.."

# Charger les identifiants de la base depuis .env.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

: "${POSTGRES_USER:?POSTGRES_USER manquant (verifier .env)}"
: "${POSTGRES_DB:?POSTGRES_DB manquant (verifier .env)}"

BACKUP_DIR="${BACKUP_DIR:-backups}"
RETENTION="${BACKUP_RETENTION:-14}"
mkdir -p "$BACKUP_DIR"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/vulntrack-${STAMP}.dump"

echo "Sauvegarde de la base '${POSTGRES_DB}' -> ${OUT}"
# -T : pas de pseudo-terminal, indispensable pour rediriger la sortie binaire.
docker compose exec -T db pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB" > "$OUT"

echo "Termine : $(du -h "$OUT" | cut -f1)"

# Retention : ne garder que les N sauvegardes les plus recentes.
ls -1t "$BACKUP_DIR"/vulntrack-*.dump 2>/dev/null | tail -n +"$((RETENTION + 1))" | while read -r old; do
  echo "Suppression de l'ancienne sauvegarde : $old"
  rm -f "$old"
done
