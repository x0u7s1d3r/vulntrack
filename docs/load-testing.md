# Tests de charge

Outil : k6. Scénario : montée à 300 utilisateurs simultanés sur GET /assets pendant 70 s.
Environnement : VM Ubuntu 24.04, 4 vCPU, 5,7 Go RAM, stack Docker Compose.

## Campagne 1 : configuration initiale

| Métrique | Valeur |
| --- | --- |
| Débit soutenu | 96 req/s |
| Taux d'erreur | 14,66 % |
| p95 | 10 s (timeout) |
| p95 des requêtes abouties | 285 ms |

### Goulots identifiés

Deux saturations simultanées, mesurées pendant le tir :

1. **Processus applicatif unique.** CPU du conteneur API à 99,7 %, soit un seul coeur
   saturé sur les quatre disponibles. Le verrou global de l'interpréteur Python
   empêche un processus unique d'exploiter plusieurs coeurs.
2. **Pool de connexions à la base plafonné.** 16 connexions constantes vers
   PostgreSQL, correspondant exactement à la configuration SQLAlchemy par défaut
   (pool_size 5 + max_overflow 10). Au-delà, les requêtes attendaient indéfiniment.

## Corrections appliquées

| Correction | Effet attendu |
| --- | --- |
| 4 workers uvicorn | Exploiter les 4 vCPU |
| pool_size 20, max_overflow 10 | 30 connexions par worker |
| max_connections 200 sur PostgreSQL | Absorber 4 x 30 connexions |
| pool_timeout 5 s | Echouer rapidement plutot que faire attendre |

## Campagne 2 : apres optimisation

| Métrique | Campagne 1 | Campagne 2 | Evolution |
| --- | --- | --- | --- |
| Débit soutenu | 96 req/s | 542 req/s | x 5,6 |
| Taux d'erreur | 14,66 % | 0,18 % | x 80 |
| Requetes servies | 7 568 | 38 000 | x 5 |
| p95 | 10 s | 630 ms | x 16 |
| Mediane | 143 ms | 204 ms | +42 % |

La mediane augmente legerement : le systeme sert desormais cinq fois plus de
requetes avec les memes ressources, chacune disposant donc de moins de capacite
instantanee. Le compromis est favorable puisque la capacite totale est multipliee
par 5,6 et que les erreurs disparaissent.

## Limites connues

- Le dimensionnement workers x pool doit rester inferieur a max_connections.
  Ce couplage manuel sera supprime a l'etape 7 par l'introduction de PgBouncer.
- Aucun cache de lecture n'est en place.
- L'instance applicative est unique : aucune tolerance a la panne.
