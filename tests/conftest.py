import os

os.environ["API_KEYS"] = "test-key"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-do-not-use-in-production"
# Les fixtures se connectent a chaque test ; le TestClient partage la meme
# adresse "cliente" pour toutes les requetes, la limite par defaut (10/minute)
# serait donc atteinte artificiellement des la 3e ou 4e fixture utilisee.
os.environ["RATE_LIMIT_AUTH"] = "1000/minute"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.config import get_settings  # noqa: E402

get_settings.cache_clear()

from app import models  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

TEST_PASSWORD = "un-mot-de-passe-solide-123"

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture()
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def auth_headers():
    """Cle d'API : reservee a /scans/ingest (ingestion machine-a-machine)."""
    return {"X-API-Key": "test-key"}


def _make_user_and_login(client, db_session, username: str, role: str) -> dict:
    user = models.User(
        username=username,
        hashed_password=hash_password(TEST_PASSWORD),
        role=role,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/auth/login",
        data={"username": username, "password": TEST_PASSWORD},
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_headers(client, db_session):
    """Jeton JWT d'un utilisateur role admin."""
    return _make_user_and_login(client, db_session, "admin-test", "admin")


@pytest.fixture()
def analyst_headers(client, db_session):
    """Jeton JWT d'un utilisateur role analyst."""
    return _make_user_and_login(client, db_session, "analyst-test", "analyst")


@pytest.fixture()
def viewer_headers(client, db_session):
    """Jeton JWT d'un utilisateur role viewer."""
    return _make_user_and_login(client, db_session, "viewer-test", "viewer")
