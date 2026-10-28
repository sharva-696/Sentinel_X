from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict
from backend.app.schemas.finding import FindingResponse


class FindingsSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total_unique: int = 0


class AssessmentResponse(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    image_type: str
    status: str
    risk_score: int
    risk_rating: str
    image_metadata: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    findings_summary: Optional[FindingsSummary] = None

    model_config = ConfigDict(from_attributes=True)


class AssessmentDetailResponse(AssessmentResponse):
    findings: List[FindingResponse] = []


class AnalysisRunResponse(BaseModel):
    assessment_id: str
    status: str
    image_metadata: Optional[Dict[str, Any]] = None
    risk_score: int
    risk_rating: str
    findings_summary: FindingsSummary
