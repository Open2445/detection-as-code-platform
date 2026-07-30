"""Database engine and session management."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from typing import Generator

from app.config import settings


if settings.database_url.startswith("sqlite"):
    engine = create_engine(
        settings.database_url,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


from sqlalchemy import inspect, text


def create_tables() -> None:
    """Create all tables defined in models and migrate missing columns for existing tables."""
    # Import models to register them with Base metadata
    from app.models import log, rule, alert, rule_change  # noqa: F401
    Base.metadata.create_all(bind=engine)

    inspector = inspect(engine)

    # Check alerts table columns
    if inspector.has_table("alerts"):
        columns = {c["name"] for c in inspector.get_columns("alerts")}
        with engine.begin() as conn:
            if "classification" not in columns:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN classification VARCHAR(50) DEFAULT 'unclassified' NOT NULL"))
            if "triage_status" not in columns:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN triage_status VARCHAR(50) DEFAULT 'open' NOT NULL"))
            if "analyst_notes" not in columns:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN analyst_notes TEXT"))
            if "primary_alert_id" not in columns:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN primary_alert_id INTEGER REFERENCES alerts(id)"))
            if "reviewed_at" not in columns:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN reviewed_at DATETIME"))
            if "reviewed_by" not in columns:
                conn.execute(text("ALTER TABLE alerts ADD COLUMN reviewed_by VARCHAR(255) DEFAULT 'local analyst'"))

    # Check sigma_rules table columns
    if inspector.has_table("sigma_rules"):
        columns = {c["name"] for c in inspector.get_columns("sigma_rules")}
        with engine.begin() as conn:
            if "validation_status" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN validation_status VARCHAR(50) DEFAULT 'unvalidated' NOT NULL"))
            if "validated_at" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN validated_at DATETIME"))
            if "validation_notes" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN validation_notes TEXT"))
            if "validation_evidence_batch_id" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN validation_evidence_batch_id INTEGER REFERENCES upload_batches(id)"))
            if "validation_evidence_filename" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN validation_evidence_filename VARCHAR(255)"))
            if "primary_validated_rule" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN primary_validated_rule BOOLEAN DEFAULT 0 NOT NULL"))
            if "rule_format" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN rule_format VARCHAR(50) DEFAULT 'yaml' NOT NULL"))
            if "json_content" not in columns:
                conn.execute(text("ALTER TABLE sigma_rules ADD COLUMN json_content TEXT"))

    # Check rule_changes table columns
    if inspector.has_table("rule_changes"):
        columns = {c["name"] for c in inspector.get_columns("rule_changes")}
        with engine.begin() as conn:
            if "parent_change_id" not in columns:
                conn.execute(text("ALTER TABLE rule_changes ADD COLUMN parent_change_id INTEGER REFERENCES rule_changes(id)"))

