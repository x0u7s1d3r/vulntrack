#!/usr/bin/env bash
#
# Restaure la base VulnTrack depuis une sauvegarde produite par backup.sh.
# ATTENTION : ecrase les donnees actuelles.
#
# Usage : ./scripts/restore.sh backups/vulntrack-YYYYmmdd-HHMMSS.dump
#
# Recommande : arreter api et worker pendant la restauration pour eviter
# qu'ils ecrivent en base au milieu de l'operation :
#   docker compose stop api worker && ./scripts/restore.sh <dump> && docker compose start api worker

set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

: "${POSTGRES_USER:?POSTGRES_USER manquant (verifier .env)}"
: "${POSTGRES_DB:?POSTGRES_DB manquant (verifier .env)}"

DUMP="${1:-}"
if [ -z "$DUMP" ]; then
  echo "Usage : $0 <fichier.dump>"
  exit 1
fi
if [ ! -f "$DUMP" ]; then
  echo "Fichier introuvable : $DUMP"
  exit 1
fi

echo "ATTENTION : la base '${POSTGRES_DB}' va etre restauree depuis ${DUMP}."
echo "Les donnees actuelles seront ecrasees."
read -r -p "Continuer ? (oui/non) " answer
if [ "$answer" != "oui" ]; then
  echo "Annule."
  exit 0
fi

# --clean --if-exists : supprime les objets existants avant de les recreer,
# sans erreur si un objet n'existe pas encore (premiere restauration).
docker compose exec -T db pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  --clean --if-exists --no-owner < "$DUMP"

echo "Restauration terminee."
