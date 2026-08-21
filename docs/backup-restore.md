# Sauvegarde et restauration

VulnTrack persiste ses données dans PostgreSQL (assets, scans, findings,
utilisateurs). Cette base est le seul état critique : les rapports bruts
stockés sur disque sont régénérables en rescannant, et le cache Redis est
volatil par conception.

## Sauvegarde

    ./scripts/backup.sh

Le script exécute `pg_dump` **dans le conteneur `db`** (pas besoin d'un client
PostgreSQL sur l'hôte) et écrit un fichier horodaté dans `backups/`, au format
custom compressé (`-Fc`). Les 14 dernières sauvegardes sont conservées, les
plus anciennes sont supprimées automatiquement (réglable via `BACKUP_RETENTION`).

Pour automatiser une sauvegarde quotidienne, une entrée cron sur l'hôte suffit :

    0 2 * * * cd /chemin/vers/vulntrack && ./scripts/backup.sh >> backups/backup.log 2>&1

## Restauration

    docker compose stop api worker
    ./scripts/restore.sh backups/vulntrack-YYYYmmdd-HHMMSS.dump
    docker compose start api worker

Le script demande une confirmation explicite avant d'écraser les données. On
arrête `api` et `worker` pendant l'opération pour qu'aucune écriture ne se
produise au milieu de la restauration. `pg_restore --clean --if-exists`
supprime les objets existants avant de les recréer : la base est ramenée
exactement à l'état du dump, schéma Alembic compris.

## Test de la procédure (à faire au moins une fois)

Une sauvegarde qu'on n'a jamais restaurée n'est pas une sauvegarde. Procédure
de vérification de bout en bout :

1. **Sauvegarder** l'état courant :

       ./scripts/backup.sh

2. **Noter** un repère vérifiable, par exemple le nombre d'assets :

       docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
         -c "SELECT count(*) FROM assets;"

3. **Simuler une perte** en supprimant des données :

       docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
         -c "DELETE FROM findings; DELETE FROM scans; DELETE FROM assets;"

4. **Restaurer** depuis la sauvegarde :

       docker compose stop api worker
       ./scripts/restore.sh backups/vulntrack-<le-plus-recent>.dump
       docker compose start api worker

5. **Vérifier** que le repère de l'étape 2 est revenu à l'identique.

Si le compte correspond, la chaîne sauvegarde → perte → restauration est
validée. Consigner la date du dernier test réussi ici :

- Dernier test de restauration réussi : _à compléter après exécution_

## Ce qui n'est pas couvert

- **Rapports bruts** (`/data/reports`) : non inclus dans le dump SQL. Ils sont
  régénérables (rescan), mais peuvent être sauvegardés séparément si besoin
  via le volume Docker `vulntrack-reports`.
- **Sauvegarde hors-site** : les dumps restent sur la même machine. Pour une
  vraie résilience, les copier vers un stockage distant (objet S3, autre hôte).
- **PITR (restauration à un instant précis)** : hors périmètre. `pg_dump`
  fournit des instantanés, pas une restauration continue par journaux WAL.
