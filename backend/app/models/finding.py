from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, JSON, DateTime
from sqlalchemy.orm import relationship
from backend.app.database import Base


class FindingRecord(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, index=True)  # UUIDv4
    assessment_id = Column(String(36), ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(256), nullable=False)
    category = Column(String(128), nullable=False)
    severity = Column(String(32), nullable=False)  # Critical, High, Medium, Low, Informational
    confidence = Column(String(32), nullable=False)  # High, Medium, Low
    detection_method = Column(String(128), nullable=False)
    byte_offset = Column(String(64), nullable=True)  # Primary byte offset e.g. 0x0001A4B0
    additional_offsets = Column(JSON, nullable=True)  # Deduplicated list of additional offsets
    section = Column(String(64), nullable=True)  # DROM, IROM, etc.
    evidence_masked = Column(Text, nullable=False)
    evidence_raw = Column(Text, nullable=True)  # Raw unredacted evidence snippet for authorized faculty/auditor demo inspection
    secret_token = Column(String(256), nullable=True)  # Extracted credential token for prominent UI highlight
    raw_occurrences = Column(Integer, nullable=False, default=1)
    fingerprint = Column(String(64), nullable=True, index=True)  # Stable deduplication fingerprint
    rationale = Column(Text, nullable=True)
    false_positive_cases = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    verification_limitations = Column(Text, nullable=True)
    is_potential = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    assessment = relationship("AssessmentRecord", back_populates="findings")
