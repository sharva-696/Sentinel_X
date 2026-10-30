import re
import logging
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.config import UPLOADS_DIR
from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord
from backend.app.modules.reporting import (
    build_report_data,
    generate_html_report,
    generate_pdf_report,
)
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


def build_finding_response(f: FindingRecord, reveal_secrets: bool = False) -> FindingResponse:
    snippet_raw = f.evidence_raw if reveal_secrets else None
    secret_token = f.secret_token if reveal_secrets else None
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
            snippet_raw=snippet_raw,
            secret_token=secret_token,
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
def get_assessment(
    assessment_id: str,
    reveal_secrets: bool = Query(False, description="Reveal unmasked secret tokens for authorized demo/auditor mode"),
    db: Session = Depends(get_db),
):
    """Retrieves full details for an assessment including normalized findings and risk score breakdown."""
    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    summary = build_findings_summary(assessment.findings)
    findings_responses = [build_finding_response(f, reveal_secrets=reveal_secrets) for f in assessment.findings]

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
    reveal_secrets: bool = Query(False, description="Reveal unmasked secret tokens for authorized demo/auditor mode"),
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
    results = [build_finding_response(f, reveal_secrets=reveal_secrets) for f in findings]

    return FindingsListResponse(
        assessment_id=assessment_id,
        total_findings=len(results),
        findings=results,
    )


def get_safe_assessment_file_path(assessment_id: str) -> Optional[Path]:
    """
    Validates and resolves the storage path for an assessment binary.
    Strictly confines resolution to UPLOADS_DIR, rejecting path traversal,
    symlinks, or directory escapes.
    """
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", assessment_id):
        raise ValueError(f"Invalid assessment identifier format: '{assessment_id}'.")

    uploads_dir = UPLOADS_DIR.resolve()
    candidate_path = (uploads_dir / f"{assessment_id}.bin").resolve()

    # Enforce containment strictly within uploads_dir
    try:
        candidate_path.relative_to(uploads_dir)
    except ValueError:
        raise ValueError("Path traversal attempt detected outside upload storage.")

    if candidate_path.parent != uploads_dir:
        raise ValueError("Path traversal attempt detected outside upload storage directory.")

    # Disallow symlinks to prevent target redirection outside uploads_dir
    if candidate_path.is_symlink():
        raise ValueError("Symlink encountered in storage directory.")

    return candidate_path


@router.delete("/{assessment_id}", status_code=status.HTTP_200_OK)
def delete_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """
    Safely deletes an assessment and its cascaded findings from the database,
    and unlinks the associated binary file strictly from the uploads storage.
    
    Guarantees:
    - Never deletes files outside UPLOADS_DIR (path-traversal safe).
    - Database deletion is atomic; failure will rollback without reporting success.
    - Filesystem and database deletion statuses are accurately reported.
    """
    # 1. First verify assessment exists in DB
    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    # 2. Validate safe storage file path before proceeding
    try:
        target_file = get_safe_assessment_file_path(assessment_id)
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )

    # 3. Perform atomic database deletion
    try:
        db.delete(assessment)
        db.commit()
    except Exception as db_exc:
        db.rollback()
        logger.error("Failed to delete assessment %s from database: %s", assessment_id, db_exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database failure during assessment deletion: {str(db_exc)}",
        )

    # 4. Only after DB commit succeeds, safely remove the stored binary file
    file_removed = False
    warning = None
    if target_file and target_file.is_file():
        try:
            target_file.unlink()
            file_removed = True
        except Exception as fs_exc:
            warning = f"Database record deleted, but could not remove binary file: {str(fs_exc)}"
            logger.warning(warning)

    return {
        "deleted": True,
        "assessment_id": assessment_id,
        "file_removed": file_removed,
        "warning": warning,
    }


@router.get("/{assessment_id}/report/html", status_code=status.HTTP_200_OK)
def get_assessment_html_report(assessment_id: str, db: Session = Depends(get_db)):
    """
    Generates a secure, standalone, downloadable HTML security report
    for the specified assessment record.
    """
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", assessment_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid assessment identifier format: '{assessment_id}'.",
        )

    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    report_data = build_report_data(assessment)
    html_content = generate_html_report(report_data)

    safe_filename = f"Sentinel-X_Assessment_{assessment_id}.html"

    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@router.get("/{assessment_id}/report/pdf", status_code=status.HTTP_200_OK)
def get_assessment_pdf_report(assessment_id: str, db: Session = Depends(get_db)):
    """
    Generates a secure, professional, downloadable PDF security report
    for the specified assessment record using ReportLab.
    """
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", assessment_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid assessment identifier format: '{assessment_id}'.",
        )

    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID '{assessment_id}' not found.",
        )

    report_data = build_report_data(assessment)
    pdf_bytes = generate_pdf_report(report_data)

    safe_filename = f"Sentinel-X_Assessment_{assessment_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )
