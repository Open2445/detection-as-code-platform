"""Sigma rule ORM model."""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import relationship

from app.database import Base


class SigmaRule(Base):
    """A Sigma detection rule stored with parsed MITRE metadata."""

    __tablename__ = "sigma_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Severity: critical | high | medium | low | informational
    severity = Column(String(50), default="medium", nullable=False, index=True)

    # Raw YAML content
    yaml_content = Column(Text, nullable=False)

    # MITRE metadata parsed from rule tags (comma-separated lists)
    mitre_tactics = Column(String(500), nullable=True)      # e.g. "execution,persistence"
    mitre_techniques = Column(String(500), nullable=True)   # e.g. "T1059.001,T1053"
    mitre_tactic_ids = Column(String(500), nullable=True)   # e.g. "TA0002,TA0003"

    # Sigma tags raw
    tags = Column(Text, nullable=True)

    # Audit
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    enabled = Column(Boolean, default=True, nullable=False)

    # Relationships
    alerts = relationship("Alert", back_populates="rule")

    def __repr__(self) -> str:
        return f"<SigmaRule id={self.id} name={self.name!r} severity={self.severity!r}>"
