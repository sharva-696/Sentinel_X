from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel


class FirmwareUploadResponse(BaseModel):
    assessment_id: str
    filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    detected_image_type: str
    created_at: datetime


class ImageMetadata(BaseModel):
    image_type: str
    header_magic: Optional[str] = None
    segments_count: Optional[int] = None
    spi_mode: Optional[str] = None
    spi_speed: Optional[str] = None
    spi_size: Optional[str] = None
    entry_point: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None
