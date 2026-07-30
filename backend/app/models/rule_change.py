"""Rule Change audit and draft model."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class RuleChange(Base):
    """Immutable record of a rule change (draft, submitted, applied, reverted)."""

    __tablename__ = "rule_changes"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(
        Integer, ForeignKey("sigma_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    rule_format = Column(String(50), nullable=False)  # 'sigma_yaml' or 'json_logic'
    previous_content = Column(Text, nullable=True)
    new_content = Column(Text, nullable=False)
    
    change_reason = Column(Text, nullable=False)
    expected_outcome = Column(Text, nullable=True)
    
    changed_by = Column(String(255), nullable=False, default="local analyst")
    changed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    
    change_type = Column(String(50), nullable=False, index=True)
    # types: 'draft', 'submitted', 'applied', 'reverted'

    parent_change_id = Column(Integer, ForeignKey("rule_changes.id"), nullable=True)
    
    # Relationships
    rule = relationship("SigmaRule", back_populates="changes")

    def __repr__(self) -> str:
        return f"<RuleChange id={self.id} rule_id={self.rule_id} type={self.change_type!r}>"
