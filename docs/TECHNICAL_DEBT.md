# Dette technique

| # | Sujet | Impact | Résolution prévue |
|---|---|---|---|
| 1 | Les tests écrivent dans la base de développement | Pollution des données, tests non reproductibles | Étape 3 : base de test dédiée et fixtures pytest |
# Dépannage

## "address already in use" sur un port Docker

1. sudo ss -tlnp | grep <port>
2. Si docker-proxy sans conteneur associé : sudo pkill -f "docker-proxy.*<port>"
3. Si un conteneur le publie : docker rm -f <nom>
4. Vérifier qu'aucun processus local ne tourne : ps aux | grep uvicorn

## Conflit de nom de conteneur

docker ps -aq --filter "name=vulntrack" | xargs -r docker rm -f

## La stack repart seule après reboot

Les conteneurs en `restart: unless-stopped` remontent avec le daemon.
Pour arrêter une autre stack : docker stop $(docker ps -q --filter "name=<prefixe>")

## Comportement incohérent entre deux outils

Vérifier la config EFFECTIVE, pas la config supposée :
  python3 -c "import os; from dotenv import load_dotenv; load_dotenv(); print(os.getenv('VAR'))"
  docker compose config
  grep -c VAR .env    # detecte les doublons
