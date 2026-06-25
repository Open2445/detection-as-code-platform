"""Shared pytest fixtures for all tests."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import log, rule, alert  # noqa: F401 — register models


@pytest.fixture(scope="session")
def engine():
    """In-memory SQLite engine for testing."""
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
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
