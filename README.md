# VulnTrack

Plateforme légère de centralisation et de suivi des vulnérabilités applicatives.

VulnTrack agrège les rapports de plusieurs scanners de sécurité (Trivy, pip-audit, Bandit, OWASP ZAP), déduplique les résultats et suit le cycle de vie de chaque vulnérabilité dans le temps.

---

## Le problème

Scanner est facile. Exploiter les résultats ne l'est pas.

Chaque exécution de pipeline republie les mêmes milliers de lignes de JSON. Trois scanners différents remontent la même CVE sous trois formats différents. Sans consolidation, le bruit noie les vulnérabilités qui comptent réellement, et personne ne corrige rien.

VulnTrack transforme ce flux brut en findings uniques, priorisés et suivis dans la durée.

---

## Fonctionnalités

- Ingestion de rapports multi-scanners au format JSON : Trivy (SCA/images), Semgrep (SAST), Gitleaks (secrets)
- Déduplication par empreinte SHA-256, scopée par scanner (CVE + composant pour Trivy, règle + emplacement dans le code pour Semgrep/Gitleaks)
- Score EPSS (probabilité d'exploitation réelle, FIRST.org) sur les findings avec CVE, en complément de la sévérité CVSS
- Suivi du cycle de vie : `open`, `in_progress`, `fixed`, `accepted`, `false_positive`
- Détection automatique des vulnérabilités corrigées entre deux scans
- Ingestion asynchrone via file de messages, conçue pour absorber les pics de charge
- API REST documentée automatiquement (OpenAPI / Swagger)
- Authentification par clé d'API (ingestion machine-à-machine) et par comptes utilisateurs JWT avec rôles (admin / analyst / viewer)
- Limitation de débit par client
- Observabilité : métriques RED et métier au format Prometheus, tableau de bord Grafana provisionné

---

## Stack technique

| Domaine | Technologies |
| --- | --- |
| API | Python 3.12, FastAPI, SQLAlchemy, Pydantic |
| Données | PostgreSQL 16, Redis |
| Conteneurisation | Docker, Docker Compose |
| CI/CD | GitLab CI |
| Sécurité | Bandit, pip-audit, Trivy, gitleaks, OWASP ZAP |
| Répartition de charge | Traefik |
| Déploiement | Ansible, Kubernetes (k3s) |
| Observabilité | Prometheus, Grafana |
| Tests de charge | k6 |

---

## Architecture

    +-------------+        +--------------+        +--------------+
    |   Client    | -----> |   Traefik    | -----> |  API FastAPI |
    |  (CI, dev)  |        | load balancer|        |  (N replicas)|
    +-------------+        +--------------+        +------+-------+
                                                          |
                                    +---------------------+---------------------+
                                    |                                           |
                             +------v------+                             +------v------+
                             |    Redis    |                             | PostgreSQL  |
                             | file + cache|                             |  PgBouncer  |
                             +------+------+                             +-------------+
                                    |
                             +------v------+
                             |   Worker    | ---> scanners (Trivy, ZAP, pip-audit)
                             +-------------+

    Supervision : Prometheus scrape l'API et le worker, Grafana affiche les metriques RED.

---

## Modèle de données

| Table | Rôle | Champs clés |
| --- | --- | --- |
| `assets` | Élément surveillé (image, dépôt, URL) | `id`, `name`, `type`, `created_at` |
| `scans` | Exécution d'un scanner sur un asset | `id`, `asset_id`, `scanner`, `status`, `started_at` |
| `findings` | Vulnérabilité constatée | `id`, `asset_id`, `scanner`, `fingerprint`, `severity`, `cve`, `component`, `rule_id`, `file_path`, `line_number`, `epss_score`, `status`, `first_seen`, `last_seen` |

Le champ `fingerprint` est un hash SHA-256 qui identifie une trouvaille de façon stable d'un scan à l'autre. Sa formule dépend du scanner :

- **Trivy** : `asset + CVE + composant` (une vulnérabilité connue sur un package donné)
- **Semgrep / Gitleaks** : `asset + scanner + règle + fichier + ligne` (une règle déclenchée à un endroit précis du code, il n'y a ni CVE ni composant)

C'est cette empreinte qui permet de rescanner en continu sans créer de doublons : une trouvaille déjà connue voit simplement son `last_seen` mis à jour. La détection des findings corrigés (passage automatique à `fixed`) est elle aussi scopée par scanner : un scan Semgrep ne peut jamais marquer comme corrigée une vulnérabilité remontée par Trivy sur le même asset, et inversement.

Pour Gitleaks, le secret détecté lui-même n'est jamais stocké : seuls la règle, le fichier et la ligne le sont. Un finding consultable par un rôle `viewer` ou `analyst` ne doit jamais exposer un credential en clair, même déjà compromis.

---

## Prérequis

- Python 3.12 ou supérieur
- Docker et Docker Compose
- Git

---

## Démarrage rapide

Cloner et préparer l'environnement Python :

    git clone <url-du-depot> vulntrack
    cd vulntrack
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Configurer les variables d'environnement :

    cp .env.example .env

Lancer la base de données :

    docker run -d --name vulntrack-db \
      -e POSTGRES_USER=vulntrack \
      -e POSTGRES_PASSWORD=changeme \
      -e POSTGRES_DB=vulntrack \
      -p 5433:5432 \
      postgres:16-alpine

Démarrer l'API :

    uvicorn app.main:app --reload --port 8001

Documentation interactive : http://localhost:8001/docs

---

## Ports utilisés

| Service | Port hôte | Port conteneur |
| --- | --- | --- |
| Traefik (entrée principale, répartit vers les replicas api) | 8001 | 80 |
| PostgreSQL | 5433 | 5432 |
| Redis | 6380 | 6379 |
| Prometheus | 9091 | 9090 |
| Grafana | 3001 | 3000 |
| Traefik (dashboard, sans authentification — usage home-lab uniquement) | 8090 | 8080 |

Depuis l'étape 10 (haute disponibilité), l'API n'est plus publiée directement sur l'hôte : `docker-compose.yml` ne mappe plus `8001:8000` sur le service `api`. Tout le trafic passe par Traefik, seul point d'entrée du réseau, qui répartit vers les instances `api` disponibles.

---

## Variables d'environnement

| Variable | Description | Exemple |
| --- | --- | --- |
| `APP_PORT` | Port d'écoute de l'API | `8001` |
| `DATABASE_URL` | Chaîne de connexion PostgreSQL | `postgresql://user:password@localhost:5433/vulntrack` |
| `UVICORN_WORKERS` | Workers uvicorn par instance `api` (voir [Répartition de charge](#répartition-de-charge-et-réplicas)) | `2` |

Le fichier `.env` n'est jamais versionné. Le fichier `.env.example` documente les variables attendues sans exposer de valeur réelle.

---

## Utilisation

Vérifier que l'API répond :

    curl http://localhost:8001/health

Se connecter et récupérer un jeton (voir [Authentification et rôles](#authentification-et-rôles) pour créer le premier compte) :

    TOKEN=$(curl -s -X POST http://localhost:8001/auth/login \
      -d "username=amiir&password=un-mot-de-passe-solide" | jq -r .access_token)

Créer un asset (rôle `admin` ou `analyst`) :

    curl -X POST http://localhost:8001/assets \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"name":"nginx:1.25-alpine","type":"image"}'

Lister les assets :

    curl http://localhost:8001/assets -H "Authorization: Bearer $TOKEN"

Lister les findings d'un asset :

    curl http://localhost:8001/assets/1/findings -H "Authorization: Bearer $TOKEN"

Ingérer un rapport de scan (clé d'API, pas de jeton JWT — voir [Authentification et rôles](#authentification-et-rôles)). Le champ `scanner` accepte `trivy`, `semgrep` ou `gitleaks` :

    curl -X POST http://localhost:8001/scans/ingest \
      -H "X-API-Key: $API_KEY" \
      -F "asset_name=vulntrack-repo" \
      -F "asset_type=repository" \
      -F "scanner=semgrep" \
      -F "report=@semgrep-report.json;type=application/json"

---

## Endpoints

| Méthode | Route | Description | Authentification |
| --- | --- | --- | --- |
| `GET` | `/health` | État de santé du service | Aucune |
| `GET` | `/ready` | Sonde de disponibilité (dépendances) | Aucune |
| `POST` | `/auth/login` | Connexion, retourne un jeton JWT | Identifiants |
| `POST` | `/users` | Créer un compte utilisateur | JWT, rôle admin |
| `GET` | `/users` | Lister les comptes utilisateurs | JWT, rôle admin |
| `POST` | `/assets` | Créer un asset | JWT, rôle admin ou analyst |
| `GET` | `/assets` | Lister les assets | JWT, tout rôle |
| `GET` | `/assets/{id}/findings` | Lister les findings d'un asset | JWT, tout rôle |
| `POST` | `/scans/ingest` | Ingérer un rapport de scan | Clé d'API |
| `GET` | `/scans/{id}` | Consulter un scan | JWT, tout rôle |

## Authentification et rôles

Deux mécanismes distincts, pour deux usages distincts :

- **Clé d'API** (`X-API-Key`) : réservée à `/scans/ingest`, l'ingestion machine-à-machine depuis un pipeline CI/CD. Pas de notion d'utilisateur ni de rôle ici.
- **Comptes utilisateurs (JWT)** : pour les humains qui consultent et gèrent les données via l'API. Trois rôles :

| Rôle | Peut lire (assets, findings, scans) | Peut créer des assets | Peut gérer les utilisateurs |
| --- | --- | --- | --- |
| `viewer` | Oui | Non | Non |
| `analyst` | Oui | Oui | Non |
| `admin` | Oui | Oui | Oui |

Il n'y a pas d'auto-inscription : un compte est toujours créé par un admin via `POST /users`. Le tout premier compte admin, avant qu'aucun n'existe, se crée directement en base :

    python -m scripts.create_admin --username amiir --password "un-mot-de-passe-solide"

Récupérer un jeton :

    curl -X POST http://localhost:8001/auth/login \
      -d "username=amiir&password=un-mot-de-passe-solide"

Puis l'utiliser :

    curl http://localhost:8001/assets \
      -H "Authorization: Bearer <token>"

---

## Tests

Lancer la suite de tests :

    pytest -v

Avec le taux de couverture :

    pytest --cov=app --cov-report=term-missing

---

## Sécurité

La sécurité est traitée à deux niveaux distincts.

**Sécurité de l'application**

- Aucun secret dans le code, configuration exclusivement par variables d'environnement
- Validation stricte de toutes les entrées via Pydantic
- Séparation des modèles de persistance et des schémas d'exposition
- Clé d'API pour l'ingestion machine-à-machine, comptes utilisateurs JWT avec RBAC (admin / analyst / viewer) pour tout le reste
- Mots de passe hachés avec bcrypt, jamais stockés ni exposés en clair
- Pas d'auto-inscription : les comptes sont créés par un admin
- Limitation de débit par client, y compris sur la connexion (anti bruteforce)
- Conteneurs exécutés avec un utilisateur non privilégié

**Sécurité de la chaîne de production**

| Moment | Contrôle | Outil |
| --- | --- | --- |
| Avant chaque commit | Détection de secrets, analyse statique | gitleaks, bandit |
| À chaque Pull Request | Dépendances, image, tests | pip-audit, Trivy, pytest |
| Chaque nuit | Rescan complet, test dynamique | Trivy, OWASP ZAP |

Politique de blocage : les vulnérabilités de sévérité critique et haute font échouer le pipeline. Les sévérités moyenne et basse sont enregistrées et suivies sans bloquer la livraison.

---

## Haute disponibilité

L'architecture est conçue pour rester disponible sous forte charge.

| Mécanisme | Problème traité |
| --- | --- |
| API sans état | Permet de multiplier les instances à l'identique |
| Répartition de charge Traefik | Distribue le trafic et écarte automatiquement les instances défaillantes (healthcheck actif sur `/health`) |
| Ingestion asynchrone via Redis | Les pics de trafic remplissent la file au lieu de saturer l'API |
| Pool de connexions PgBouncer | Évite l'épuisement des connexions PostgreSQL |
| Cache Redis sur les lectures | Décharge la base sur les endpoints les plus sollicités |
| Sondes de vivacité et de disponibilité | Permettent à Traefik de router uniquement vers les instances prêtes |
| Arrêt gracieux | Aucune requête perdue pendant un déploiement |

Les résultats des campagnes de tests de charge k6 sont documentés dans `docs/load-testing.md`.

### Répartition de charge et réplicas

Traefik répartit le trafic entre toutes les instances `api` en cours d'exécution. Pour en lancer plusieurs :

    docker compose up -d --scale api=3

Chaque instance tourne avec `UVICORN_WORKERS` workers uvicorn (`2` par défaut, réglable dans `.env`) : avec 3 replicas à 2 workers, la capacité totale (6 workers) dépasse déjà l'instance unique à 4 workers de l'étape 6-7. Ajuster `UVICORN_WORKERS` et le nombre de replicas selon le nombre de vCPU réellement disponibles sur la VM plutôt que de les augmenter aveuglément.

Un replica qui échoue son healthcheck (`/health`) est retiré de la rotation par Traefik sans intervention manuelle — c'est ce qui transforme "plusieurs instances" en "haute disponibilité" : tuer un conteneur `api` à la main pendant que le trafic continue est le test le plus parlant.

Entre l'instant où un replica meurt et sa détection par le healthcheck (jusqu'à 10 s), une requête peut encore lui être routée et tomber sur un refus de connexion. Un *retry middleware* rejoue alors cette requête sur un autre replica plutôt que de renvoyer une erreur au client. Traefik ne rejoue que tant qu'aucune réponse n'a été émise, donc sans risque de double exécution côté serveur. Résultat mesuré en tuant un replica sous charge continue : sans retry, une seule requête sur ~130 renvoyait un `504` au moment exact du kill ; avec le retry, la bascule est invisible côté client.

**Limitation connue** : le tableau de bord Traefik (port 8090) tourne en mode `--api.insecure=true`, sans authentification. Acceptable en home-lab isolé, à ne jamais exposer tel quel sur un réseau non maîtrisé. Traefik a également besoin d'un accès en lecture au socket Docker (`/var/run/docker.sock`) pour découvrir les conteneurs `api` : c'est un accès équivalent à root sur l'hôte, un compromis assumé ici et documenté plutôt que caché — à durcir avec un proxy dédié (ex. `tecnativa/docker-socket-proxy`) avant tout déploiement au-delà du home-lab.

**Piège rencontré en déploiement réel** : sur un moteur Docker récent (testé avec Docker Engine 29.x, API 1.55), Traefik v3.3 échoue silencieusement à découvrir les conteneurs avec `Error response from daemon: client version 1.24 is too old`. Traefik v3.3 fige en dur la version d'API de son client Docker (1.24), que les moteurs récents rejettent — et il **ignore la variable `DOCKER_API_VERSION`** (vérifié : la variable était bien présente dans le conteneur, sans effet). Le correctif est de monter Traefik en v3.7+ (ici `v3.7.11`), qui négocie correctement la version d'API. Symptôme caractéristique : `curl http://localhost:8001/...` répond `404 page not found` (la page 404 de Traefik lui-même, pas celle de l'API) ; confirmer avec `docker compose logs traefik`.

---

## Observabilité

L'observabilité repose sur les métriques RED (Rate, Errors, Duration), complétées par des métriques métier. Prometheus collecte, Grafana affiche un tableau de bord provisionné en code.

**Où sont exposées les métriques**

| Source | Métriques | Endpoint |
| --- | --- | --- |
| API (chaque replica) | RED : `vulntrack_http_requests_total`, `vulntrack_http_request_duration_seconds` | `/metrics` sur le port interne 8000 |
| Worker | État métier : `vulntrack_ingest_queue_depth`, `vulntrack_findings{severity,status}` | serveur dédié, port 9100 |

Les métriques métier sont des jauges calculées à la volée au moment du scrape (état courant de la file et des findings), pas des compteurs incrémentés dans le code.

**Le piège du multi-process.** Chaque conteneur `api` fait tourner plusieurs workers uvicorn, c'est-à-dire plusieurs processus derrière un seul port. Un scrape Prometheus tomberait sur un worker au hasard et ne verrait que ses compteurs — des métriques fausses et sous-comptées. La parade est le mode multi-process de `prometheus_client` : chaque worker écrit ses métriques dans un répertoire partagé (`PROMETHEUS_MULTIPROC_DIR`), et l'endpoint `/metrics` les agrège à la lecture. Le répertoire est vidé au démarrage du conteneur pour ne pas agréger les fichiers d'une exécution précédente. Le worker, lui, est mono-process : pas de cette complexité, un simple serveur de métriques.

**Découverte des replicas.** Prometheus ne connaît pas à l'avance le nombre de replicas `api`. Il les découvre via le DNS interne de Docker Compose (`dns_sd_configs` sur le nom de service `api`, qui résout vers toutes les IP des replicas) — sans avoir besoin du socket Docker cette fois. Quand on scale l'API, les nouveaux replicas sont scrapés au cycle suivant sans reconfiguration.

**Accès**

Grafana est disponible sur `http://localhost:3001` (identifiants par défaut `admin` / `admin`, à changer via `GRAFANA_USER` / `GRAFANA_PASSWORD`). La datasource Prometheus et le tableau de bord sont provisionnés automatiquement depuis `observability/grafana/` : rien à configurer à la main. Prometheus est sur `http://localhost:9091`.

Le tableau de bord couvre : débit par classe de statut, taux d'erreur 5xx, latence p50/p95/p99, débit par route, profondeur de la file d'ingestion, et répartition des findings par sévérité et par statut.

**Limitation connue** : l'endpoint `/metrics` n'est pas authentifié — il est scrapé sur le réseau interne et ne doit jamais être exposé publiquement via Traefik en production (à bloquer au niveau du reverse proxy ou à protéger). Les identifiants Grafana par défaut sont ceux d'un home-lab et doivent être changés avant toute exposition.

---

## Feuille de route

- [x] Squelette de l'API et modèle de données
- [x] Conteneurisation et durcissement de l'image
- [x] Orchestration locale via Docker Compose
- [x] Sécurité applicative : authentification par clé d'API, limitation de débit, en-têtes
- [x] Worker asynchrone et file de messages
- [x] Première campagne de tests de charge
- [x] Cache, pool de connexions, arrêt gracieux
- [x] Comptes utilisateurs et rôles (RBAC)
- [x] Ingestion multi-scanner (Trivy, Semgrep, Gitleaks) et score EPSS
- [x] Répartition de charge et réplicas
- [x] Supervision Prometheus et Grafana
- [ ] Notifications (webhook/Slack) et sauvegarde documentée
- [ ] Frontend simple
- [ ] Pipeline d'intégration continue et gates de sécurité
- [ ] Documentation finale et section limitations connues
- [ ] Manifests Kubernetes / Helm chart

---

## Structure du dépôt

    vulntrack/
    ├── app/
    │   ├── __init__.py
    │   ├── main.py          points d'entree HTTP
    │   ├── auth.py          JWT, hachage de mot de passe, RBAC
    │   ├── config.py        variables d'environnement (pydantic-settings)
    │   ├── database.py      connexion et session PostgreSQL
    │   ├── models.py        tables SQLAlchemy
    │   ├── schemas.py       validation Pydantic
    │   ├── parsers.py       parseurs Trivy / Semgrep / Gitleaks
    │   ├── epss.py          enrichissement EPSS (FIRST.org)
    │   ├── jobs.py          traitement asynchrone d'un scan (worker)
    │   ├── queue.py         file Redis / RQ
    │   ├── storage.py       persistance des rapports bruts
    │   ├── cache.py         cache Redis en lecture
    │   ├── middleware.py    en-tetes de securite
    │   ├── security.py      cle d'API machine-a-machine
    │   ├── metrics.py       metriques RED (Prometheus, multi-process)
    │   └── metrics_state.py jauges d'etat metier (exposees par le worker)
    ├── observability/
    │   ├── prometheus.yml   configuration de collecte
    │   └── grafana/
    │       ├── provisioning/  datasource + provider de dashboards
    │       └── dashboards/    tableau de bord VulnTrack (JSON versionne)
    ├── scripts/
    │   └── create_admin.py  creation du tout premier compte admin
    ├── tests/
    │   ├── __init__.py
    │   ├── conftest.py
    │   ├── test_api.py
    │   ├── test_auth.py
    │   ├── test_parsers.py
    │   ├── test_epss.py
    │   ├── test_jobs.py
    │   ├── test_security.py
    │   └── test_metrics.py
    ├── docs/
    ├── worker.py            worker RQ + serveur de metriques d'etat
    ├── .env.example
    ├── .gitignore
    ├── requirements.txt
    └── README.md

---

## Licence

MIT
