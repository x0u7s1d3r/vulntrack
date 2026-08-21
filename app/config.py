from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str
    redis_url: str = "redis://localhost:6379/0"

    api_keys: str = ""
    rate_limit_default: str = "100/minute"
    rate_limit_write: str = "20/minute"
    rate_limit_auth: str = "10/minute"

    # Cle de signature des JWT utilisateur. Doit etre longue et aleatoire en
    # production (ex: openssl rand -hex 32), distincte des cles d'API machine.
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30

    cors_origins: str = ""
    environment: str = "development"

    report_storage_path: str = "/data/reports"

    # Notifications (etape 12). Vides par defaut : aucune notification n'est
    # envoyee tant qu'aucune URL n'est configuree. Le worker alerte quand un
    # scan produit de nouveaux findings de severite >= notify_min_severity.
    slack_webhook_url: str = ""
    notify_webhook_url: str = ""
    notify_min_severity: str = "high"
    notify_timeout_seconds: int = 5

    @property
    def api_key_list(self) -> list[str]:
        return [k.strip() for k in self.api_keys.split(",") if k.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
