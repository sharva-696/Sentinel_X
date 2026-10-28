from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class AssessmentRecord(Base):
    __tablename__ = "assessments"

    id = Column(String(36), primary_key=True, index=True)  # UUIDv4
    filename = Column(String(256), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    md5 = Column(String(32), nullable=False)
    image_type = Column(String(64), nullable=False, default="RAW_BINARY")
    status = Column(String(32), nullable=False, default="UPLOADED")  # UPLOADED, ANALYZING, COMPLETED, FAILED
    risk_score = Column(Integer, nullable=False, default=0)
    risk_rating = Column(String(32), nullable=False, default="Clean")
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    image_metadata = Column(JSON, nullable=True)
    score_breakdown = Column(JSON, nullable=True)  # Explainable score calculation breakdown
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)

    device = relationship("DeviceRecord", back_populates="assessments")
    findings = relationship("FindingRecord", back_populates="assessment", cascade="all, delete-orphan")
