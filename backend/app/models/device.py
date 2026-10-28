from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class DeviceRecord(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    port = Column(String(128), nullable=False)
    chip_family = Column(String(64), nullable=True)
    chip_revision = Column(Integer, nullable=True)
    mac_address = Column(String(32), nullable=True)
    crystal_freq = Column(String(32), nullable=True)
    flash_size = Column(String(32), nullable=True)
    flash_vendor_id = Column(String(32), nullable=True)
    flash_mode = Column(String(32), nullable=True)
    flash_speed = Column(String(32), nullable=True)
    sdk_version = Column(String(64), nullable=True)
    notes = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    assessments = relationship("AssessmentRecord", back_populates="device")
