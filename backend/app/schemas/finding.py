from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict
from backend.app.modules.assessment.normalizer import FindingSeverity, FindingConfidence


class FindingEvidence(BaseModel):
    byte_offset: Optional[str] = None
    additional_offsets: List[str] = Field(default_factory=list)
    section: Optional[str] = None
    snippet_masked: str
    snippet_raw: Optional[str] = None
    secret_token: Optional[str] = None
    occurrences_count: int = 1


class FindingResponse(BaseModel):
    id: str
    assessment_id: str
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    detection_method: str
    evidence: FindingEvidence
    fingerprint: Optional[str] = None
    rationale: Optional[str] = None
    false_positive_cases: Optional[str] = None
    remediation: Optional[str] = None
    verification_limitations: Optional[str] = None
    is_potential: bool = True
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class FindingsListResponse(BaseModel):
    assessment_id: str
    total_findings: int
    findings: List[FindingResponse]
