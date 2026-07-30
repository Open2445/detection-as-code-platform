"""Shared pytest fixtures for all tests."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import log, rule, alert  # noqa: F401 — register models


from sqlalchemy.pool import StaticPool


@pytest.fixture(scope="session")
def engine():
    """In-memory SQLite engine for testing with shared StaticPool."""
    eng = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=eng)
    yield eng
    Base.metadata.drop_all(bind=eng)


@pytest.fixture
def db(engine):
    """Per-test database session with rollback isolation."""
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def client(db):
    """FastAPI TestClient configured with test database session."""
    from fastapi.testclient import TestClient
    from app.main import app
    from app.database import get_db

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


