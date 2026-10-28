import logging
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.config import settings
from backend.app.modules.analysis import (
    analyze_firmware_bytes,
    persist_analysis_record,
    save_upload_safely,
    cleanup_file,
    ValidationError,
)
from backend.app.schemas.firmware import FirmwareUploadResponse
from backend.app.models.assessment import AssessmentRecord

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/firmware", tags=["Firmware Analysis"])


@router.post("/analyze", status_code=status.HTTP_200_OK)
async def analyze_firmware(
    file: UploadFile = File(..., description="ESP32 binary firmware file (.bin)"),
    db: Session = Depends(get_db),
):
    """
    Performs complete offline analysis on an uploaded ESP32 firmware binary.
    Validates file format, extracts binary metadata, pulls printable strings,
    detects potential secrets, calculates risk score, and returns sanitized results.
    """
    filename = file.filename or "firmware.bin"

    try:
        contents = await file.read()
    except Exception as e:
        logger.error(f"Error reading uploaded file payload: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file payload.",
        )

    try:
        result = analyze_firmware_bytes(contents, original_filename=filename)
        persist_analysis_record(db, result)
        return result
    except ValidationError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        logger.error(f"Analysis failure on {filename}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during firmware analysis. Please check file format.",
        )


@router.post("/upload", response_model=FirmwareUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_firmware(
    file: UploadFile = File(..., description="ESP32 binary firmware file (.bin)"),
    db: Session = Depends(get_db),
):
    """
    Ingests and stores a firmware binary, computing hashes and recording metadata
    prior to analysis.
    """
    filename = file.filename or "firmware.bin"

    try:
        contents = await file.read()
    except Exception as e:
        logger.error(f"Error reading upload file: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to read uploaded file payload.",
        )

    saved_path = None
    try:
        saved_path, assessment_id = save_upload_safely(contents, original_filename=filename)
        from backend.app.utils.crypto import compute_bytes_hashes
        from backend.app.modules.analysis.esp_parser import detect_image_type

        sha256, md5 = compute_bytes_hashes(contents)
        image_type = detect_image_type(contents)

        record = AssessmentRecord(
            id=assessment_id,
            filename=filename,
            file_size_bytes=len(contents),
            sha256=sha256,
            md5=md5,
            image_type=image_type,
            status="UPLOADED",
            risk_score=0,
            risk_rating="Clean",
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        return FirmwareUploadResponse(
            assessment_id=record.id,
            filename=record.filename,
            file_size_bytes=record.file_size_bytes,
            sha256=record.sha256,
            md5=record.md5,
            detected_image_type=record.image_type,
            created_at=record.created_at,
        )
    except ValidationError as ve:
        if saved_path:
            cleanup_file(saved_path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve),
        )
    except Exception as e:
        if saved_path:
            cleanup_file(saved_path)
        logger.error(f"Upload error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process firmware upload.",
        )


@router.get("/{assessment_id}", status_code=status.HTTP_200_OK)
def get_assessment(assessment_id: str, db: Session = Depends(get_db)):
    """Retrieves stored assessment record and associated sanitized findings."""
    assessment = db.query(AssessmentRecord).filter(AssessmentRecord.id == assessment_id).first()
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment with ID {assessment_id} not found.",
        )

    findings = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "detection_method": f.detection_method,
            "byte_offset": f.byte_offset,
            "additional_offsets": f.additional_offsets or [],
            "section": f.section,
            "evidence_masked": f.evidence_masked,
            "raw_occurrences": f.raw_occurrences,
            "rationale": f.rationale,
            "remediation": f.remediation,
            "is_potential": f.is_potential,
        }
        for f in assessment.findings
    ]

    return {
        "assessment_id": assessment.id,
        "filename": assessment.filename,
        "file_size_bytes": assessment.file_size_bytes,
        "sha256": assessment.sha256,
        "md5": assessment.md5,
        "image_type": assessment.image_type,
        "status": assessment.status,
        "risk_score": assessment.risk_score,
        "risk_rating": assessment.risk_rating,
        "image_metadata": assessment.image_metadata,
        "findings_count": len(findings),
        "findings": findings,
        "created_at": assessment.created_at.isoformat() if assessment.created_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
    }
