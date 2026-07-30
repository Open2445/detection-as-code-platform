"""Alert ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class Alert(Base):
    """An alert generated when a Sigma rule matches a log entry."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    # Foreign keys
    rule_id = Column(
        Integer, ForeignKey("sigma_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    log_entry_id = Column(
        Integer, ForeignKey("log_entries.id", ondelete="CASCADE"), nullable=False, index=True
    )
    batch_id = Column(
        Integer, ForeignKey("upload_batches.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Denormalized fields for fast filtering
    severity = Column(String(50), nullable=False, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    username = Column(String(255), nullable=True, index=True)
    rule_name = Column(String(255), nullable=False, index=True)

    # MITRE context
    technique_id = Column(String(50), nullable=True, index=True)   # e.g. "T1059.001"
    technique_name = Column(String(255), nullable=True)
    tactic = Column(String(100), nullable=True, index=True)         # e.g. "execution"
    tactic_id = Column(String(50), nullable=True)                   # e.g. "TA0002"

    # Event metadata
    event_id = Column(Integer, nullable=True)
    triggered_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Matched log context (snippet)
    details_json = Column(Text, nullable=True)

    # Triage metadata
    classification = Column(String(50), default="unclassified", nullable=False, index=True)
    triage_status = Column(String(50), default="open", nullable=False, index=True)
    analyst_notes = Column(Text, nullable=True)
    primary_alert_id = Column(
        Integer, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(String(255), nullable=True, default="local analyst")

    # Relationships
    rule = relationship("SigmaRule", back_populates="alerts")
    log_entry = relationship("LogEntry", back_populates="alerts")
    batch = relationship("UploadBatch", back_populates="alerts")
    triage_history = relationship(
        "AlertTriageHistory", back_populates="alert", cascade="all, delete-orphan", order_by="desc(AlertTriageHistory.created_at)"
    )

    def __repr__(self) -> str:
        return f"<Alert id={self.id} rule={self.rule_name!r} severity={self.severity!r} classification={self.classification!r}>"


class AlertTriageHistory(Base):
    """Immutable record of an alert triage update."""

    __tablename__ = "alert_triage_history"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(
        Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    previous_classification = Column(String(50), nullable=True)
    new_classification = Column(String(50), nullable=False)
    previous_triage_status = Column(String(50), nullable=True)
    new_triage_status = Column(String(50), nullable=False)
    analyst_notes = Column(Text, nullable=True)
    primary_alert_id = Column(Integer, nullable=True)
    reviewed_by = Column(String(255), nullable=False, default="local analyst")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    alert = relationship("Alert", back_populates="triage_history")

    def __repr__(self) -> str:
        return f"<AlertTriageHistory id={self.id} alert_id={self.alert_id} new_class={self.new_classification!r}>"

