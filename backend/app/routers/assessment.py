import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.config import UPLOADS_DIR
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord
from backend.app.schemas.assessment import (
    AssessmentResponse,
    AssessmentDetailResponse,
    AssessmentListResponse,
    FindingsSummary,
)
from backend.app.schemas.finding import (
    FindingResponse,
    FindingsListResponse,
    FindingEvidence,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/assessments", tags=["Assessment Management"])


def build_finding_response(f: FindingRecord) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        assessment_id=f.assessment_id,
        rule_id=f.rule_id,
        title=f.title,
        category=f.category,
        severity=f.severity,
        confidence=f.confidence,
        detection_method=f.detection_method,
        evidence=FindingEvidence(
            byte_offset=f.byte_offset,
            additional_offsets=f.additional_offsets or [],
            section=f.section,
            snippet_masked=f.evidence_masked,
            occurrences_count=f.raw_occurrences,
        ),
        fingerprint=f.fingerprint,
        rationale=f.rationale,
        false_positive_cases=f.false_positive_cases,
        remediation=f.remediation,
        verification_limitations=f.verification_limitations,
        is_potential=f.is_potential,
        created_at=f.created_at,
    )


def build_findings_summary(findings: List[FindingRecord]) -> FindingsSummary:
    return FindingsSummary(
        critical=sum(1 for f in findings if f.severity == "Critical"),
        high=sum(1 for f in findings if f.severity == "High"),
        medium=sum(1 for f in findings if f.severity == "Medium"),
        low=sum(1 for f in findings if f.severity == "Low"),
        informational=sum(1 for f in findings if f.severity == "Informational"),
        total_unique=len(findings),
    )


@router.get("", response_model=AssessmentListResponse)
def list_assessments(
    skip: int = Query(0, ge=0, description="Number of assessments to skip"),
    limit: int = Query(20, ge=1, le=100, description="Max number of assessments to return"),
    status: Optional[str] = Query(None, description="Filter by status e.g. COMPLETED"),
    risk_rating: Optional[str] = Query(None, description="Filter by risk rating e.g. High"),
    db: Session = Depends(get_db),
):
    """
    Retrieves a paginated list of historical security assessments.
    Supports filtering by execution status and risk rating band.
    """
    query = db.query(AssessmentRecord)

    if status:
        query = query.filter(AssessmentRecord.status == status)
    if risk_rating:
        query = query.filter(AssessmentRecord.risk_rating == risk_rating)

    total_count = query.count()
    assessments = query.order_by(desc(AssessmentRecord.created_at)).offset(skip).limit(limit).all()

    page = (skip // limit) + 1 if limit > 0 else 1

    items: List[AssessmentResponse] = []
    for a in assessments:
        summary = build_findings_summary(a.findings)
        items.append(
            AssessmentResponse(
                id=a.id,
                filename=a.filename,
                file_size_bytes=a.file_size_bytes,
                sha256=a.sha256,
                md5=a.md5,
                image_type=a.image_type,
                status=a.status,
                risk_score=a.risk_score,
                risk_rating=a.risk_rating,
                image_metadata=a.image_metadata,
                score_breakdown=a.score_breakdown,
                error_message=a.error_message,
                created_at=a.created_at,
                completed_at=a.completed_at,
                findings_summary=summary,
            )
        )

    return AssessmentListResponse(
        total_assessments=total_count,
        page=page,
        page_size=limit,
        assessments=items,
    )


@router.get("/{assessment_id}", response_model=AssessmentDetailResponse)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """Retrieves full details for an assessment including normalized findings and risk score breakdown."""
    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    summary = build_findings_summary(assessment.findings)
    findings_responses = [build_finding_response(f) for f in assessment.findings]

    return AssessmentDetailResponse(
        id=assessment.id,
        filename=assessment.filename,
        file_size_bytes=assessment.file_size_bytes,
        sha256=assessment.sha256,
        md5=assessment.md5,
        image_type=assessment.image_type,
        status=assessment.status,
        risk_score=assessment.risk_score,
        risk_rating=assessment.risk_rating,
        image_metadata=assessment.image_metadata,
        score_breakdown=assessment.score_breakdown,
        error_message=assessment.error_message,
        created_at=assessment.created_at,
        completed_at=assessment.completed_at,
        findings_summary=summary,
        findings=findings_responses,
    )


@router.get("/{assessment_id}/findings", response_model=FindingsListResponse)
def get_assessment_findings(
    assessment_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity: Critical, High, Medium, Low, Informational"),
    category: Optional[str] = Query(None, description="Filter by category"),
    db: Session = Depends(get_db),
):
    """Retrieves filtered findings for a specific assessment."""
    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    query = db.query(FindingRecord).filter(FindingRecord.assessment_id == assessment_id)
    if severity:
        query = query.filter(FindingRecord.severity == severity.capitalize())
    if category:
        query = query.filter(FindingRecord.category.ilike(f"%{category}%"))

    findings = query.all()
    results = [build_finding_response(f) for f in findings]

    return FindingsListResponse(
        assessment_id=assessment_id,
        total_findings=len(results),
        findings=results,
    )


@router.delete("/{assessment_id}", status_code=status.HTTP_200_OK)
def delete_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """Deletes an assessment and its associated findings from the database."""
    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    # Clean up uploaded binary file if present
    binary_path = UPLOADS_DIR / f"{assessment_id}.bin"
    if binary_path.is_file():
        try:
            binary_path.unlink(missing_ok=True)
        except Exception:
            pass

    db.delete(assessment)
    db.commit()

    return {"deleted": True, "assessment_id": assessment_id}
