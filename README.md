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

- Ingestion de rapports multi-scanners au format JSON
- Déduplication par empreinte SHA-256 (asset + CVE + composant)
- Suivi du cycle de vie : `open`, `in_progress`, `fixed`, `accepted`, `false_positive`
- Détection automatique des vulnérabilités corrigées entre deux scans
- Ingestion asynchrone via file de messages, conçue pour absorber les pics de charge
- API REST documentée automatiquement (OpenAPI / Swagger)
- Authentification par clé d'API et limitation de débit
- Métriques exposées au format Prometheus

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
| `findings` | Vulnérabilité constatée | `id`, `asset_id`, `fingerprint`, `severity`, `cve`, `status`, `first_seen`, `last_seen` |

Le champ `fingerprint` est un hash SHA-256 de `asset + CVE + composant`. C'est lui qui permet de rescanner en continu sans créer de doublons : une vulnérabilité déjà connue voit simplement son `last_seen` mis à jour.

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
| API VulnTrack | 8001 | 8000 |
| PostgreSQL | 5433 | 5432 |
| Redis | 6380 | 6379 |
| Prometheus | 9091 | 9090 |
| Grafana | 3001 | 3000 |
| Traefik (dashboard) | 8090 | 8080 |

---

## Variables d'environnement

| Variable | Description | Exemple |
| --- | --- | --- |
| `APP_PORT` | Port d'écoute de l'API | `8001` |
| `DATABASE_URL` | Chaîne de connexion PostgreSQL | `postgresql://user:password@localhost:5433/vulntrack` |

Le fichier `.env` n'est jamais versionné. Le fichier `.env.example` documente les variables attendues sans exposer de valeur réelle.

---

## Utilisation

Vérifier que l'API répond :

    curl http://localhost:8001/health

Créer un asset :

    curl -X POST http://localhost:8001/assets \
      -H "Content-Type: application/json" \
      -d '{"name":"nginx:1.25-alpine","type":"image"}'

Lister les assets :

    curl http://localhost:8001/assets

Lister les findings d'un asset :

    curl http://localhost:8001/assets/1/findings

---

## Endpoints

| Méthode | Route | Description |
| --- | --- | --- |
| `GET` | `/health` | État de santé du service |
| `POST` | `/assets` | Créer un asset |
| `GET` | `/assets` | Lister les assets |
| `GET` | `/assets/{id}/findings` | Lister les findings d'un asset |

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
- Authentification par clé d'API sur les endpoints d'écriture
- Limitation de débit par client
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
| Répartition de charge Traefik | Distribue le trafic et écarte les instances défaillantes |
| Ingestion asynchrone via Redis | Les pics de trafic remplissent la file au lieu de saturer l'API |
| Pool de connexions PgBouncer | Évite l'épuisement des connexions PostgreSQL |
| Cache Redis sur les lectures | Décharge la base sur les endpoints les plus sollicités |
| Sondes de vivacité et de disponibilité | Permettent à l'orchestrateur de router uniquement vers les instances prêtes |
| Limites de ressources et autoscaling | Ajoute des réplicas automatiquement selon la charge |
| Arrêt gracieux | Aucune requête perdue pendant un déploiement |

Les résultats des campagnes de tests de charge k6 sont documentés dans `docs/load-testing.md`.

---

## Feuille de route

- [x] Squelette de l'API et modèle de données
- [ ] Conteneurisation et durcissement de l'image
- [ ] Orchestration locale via Docker Compose
- [ ] Sécurité applicative : authentification, limitation de débit, en-têtes
- [ ] Worker asynchrone et file de messages
- [ ] Première campagne de tests de charge
- [ ] Cache, pool de connexions, arrêt gracieux
- [ ] Répartition de charge et réplicas
- [ ] Pipeline d'intégration continue
- [ ] Gates de sécurité et hooks pre-commit
- [ ] Tests dynamiques et scans planifiés
- [ ] Déploiement Ansible puis Kubernetes
- [ ] Supervision Prometheus et Grafana
- [ ] Documentation finale et guidelines développeurs

---

## Structure du dépôt

    vulntrack/
    ├── app/
    │   ├── __init__.py
    │   ├── main.py          points d'entree HTTP
    │   ├── database.py      connexion et session PostgreSQL
    │   ├── models.py        tables SQLAlchemy
    │   └── schemas.py       validation Pydantic
    ├── tests/
    │   ├── __init__.py
    │   └── test_api.py
    ├── docs/
    ├── .env.example
    ├── .gitignore
    ├── requirements.txt
    └── README.md

---

## Licence

MIT
