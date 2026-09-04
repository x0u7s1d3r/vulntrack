# Vérification de signature à l'admission (cosign + policy-controller)

Les images sont signées en CI (keyless OIDC, voir `.github/workflows/ci-security.yml`,
étape 17h-1). Ce dossier ajoute la vérification côté cluster : un namespace
étiqueté refuse toute image non signée par notre pipeline.

## Installation du contrôleur d'admission

```bash
helm repo add sigstore https://sigstore.github.io/helm-charts
helm repo update
helm install policy-controller sigstore/policy-controller \
  -n cosign-system --create-namespace
```

## Application de la politique

```bash
kubectl apply -f deploy/cosign/clusterimagepolicy.yaml
```

## Activer la vérification sur un namespace (opt-in)

```bash
kubectl label namespace <ns> policy.sigstore.dev/include=true
```

Sans ce label, le namespace n'est pas vérifié (c'est pourquoi `vulntrack`
tourne intact avec ses images locales). Une image non signée dans un
namespace étiqueté est **refusée à l'admission** (`no signatures found`).
