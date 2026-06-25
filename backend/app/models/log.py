"""Log upload batch and individual log entry models."""
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey, func, Boolean
)
from sqlalchemy.orm import relationship

from app.database import Base


class UploadBatch(Base):
    """Represents a single file upload containing multiple log entries."""

    __tablename__ = "upload_batches"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    upload_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    log_count = Column(Integer, default=0, nullable=False)
    status = Column(String(50), default="pending", nullable=False)
    # status: pending | processed | error
    detections_run = Column(Boolean, default=False, nullable=False)
    detections_run_at = Column(DateTime, nullable=True)

    # Relationships
    log_entries = relationship(
        "LogEntry", back_populates="batch", cascade="all, delete-orphan"
    )
    alerts = relationship(
        "Alert", back_populates="batch", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<UploadBatch id={self.id} filename={self.filename!r}>"


class LogEntry(Base):
    """A single log event (Sysmon or Windows Event) stored as JSON."""

    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(
        Integer, ForeignKey("upload_batches.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Common fields extracted for filtering
    event_id = Column(Integer, nullable=True, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=True, index=True)

    # Full raw JSON stored as text
    raw_json = Column(Text, nullable=False)

    # Relationships
    batch = relationship("UploadBatch", back_populates="log_entries")
    alerts = relationship("Alert", back_populates="log_entry")

    def __repr__(self) -> str:
        return f"<LogEntry id={self.id} event_id={self.event_id} host={self.hostname!r}>"
