from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import html

from backend.app.models.assessment import AssessmentRecord
from backend.app.models.finding import FindingRecord
from backend.app.models.device import DeviceRecord


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


def format_bytes(size_bytes: int) -> str:
    """Formats raw byte counts into human-readable strings."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"


def build_report_data(assessment: AssessmentRecord) -> Dict[str, Any]:
    """
    Constructs the canonical report data structure from a persisted AssessmentRecord.
    Both HTML and PDF report generators consume this canonical structure.
    
    Guarantees:
    - Never fabricates device metadata if the assessment was offline.
    - Uses stored risk score and score breakdown (no secondary calculation).
    - Preserves masked evidence integrity (zero raw secrets).
    - Sorts findings deterministically by severity hierarchy.
    """
    now_utc = datetime.now(timezone.utc)
    
    # 1. Device Metadata (only when genuinely associated with an interrogated device)
    device_data: Optional[Dict[str, Any]] = None
    if assessment.device:
        dev: DeviceRecord = assessment.device
        chip_label = f"{dev.chip_family or 'ESP32'} (rev {dev.chip_revision})" if dev.chip_revision is not None else (dev.chip_family or "ESP32")
        device_data = {
            "id": dev.id,
            "port": dev.port,
            "chip_type": chip_label,
            "chip_family": dev.chip_family,
            "chip_revision": dev.chip_revision,
            "mac_address": dev.mac_address,
            "flash_size": dev.flash_size,
            "flash_vendor_id": dev.flash_vendor_id,
            "flash_mode": dev.flash_mode,
            "flash_speed": dev.flash_speed,
            "crystal_freq": dev.crystal_freq,
            "sdk_version": dev.sdk_version,
            "created_at": dev.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if dev.created_at else None,
        }

    # 2. Sort and Normalize Findings
    sorted_findings: List[FindingRecord] = sorted(
        assessment.findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule_id, f.byte_offset or "")
    )

    findings_list: List[Dict[str, Any]] = []
    summary_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for f in sorted_findings:
        sev = f.severity if f.severity in summary_counts else "Low"
        summary_counts[sev] += 1

        additional = f.additional_offsets if isinstance(f.additional_offsets, list) else []

        findings_list.append({
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "detection_method": f.detection_method,
            "byte_offset": f.byte_offset or "N/A",
            "additional_offsets": additional,
            "total_occurrences": f.raw_occurrences or (1 + len(additional)),
            "section": f.section or "Flash",
            "evidence_masked": f.evidence_masked,
            "fingerprint": f.fingerprint,
            "rationale": f.rationale,
            "false_positive_cases": f.false_positive_cases,
            "remediation": f.remediation,
            "verification_limitations": f.verification_limitations,
            "is_potential": f.is_potential,
        })

    # 3. Assessment Metadata & Hashes
    created_str = assessment.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if assessment.created_at else "Unknown"
    completed_str = assessment.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if assessment.completed_at else created_str

    # 4. Partition metadata if extracted
    partitions: List[Dict[str, Any]] = []
    if assessment.image_metadata and isinstance(assessment.image_metadata, dict):
        raw_parts = assessment.image_metadata.get("partitions")
        if isinstance(raw_parts, list):
            partitions = raw_parts

    # 5. Stored Risk Breakdown (canonical source of truth)
    score_breakdown = assessment.score_breakdown or {}
    raw_rule_breakdown = score_breakdown.get("finding_breakdown") or score_breakdown.get("rule_breakdown") or []

    return {
        "report_title": "Sentinel-X ESP32 Security Assessment Report",
        "generated_at": now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "assessment_id": assessment.id,
        "created_at": created_str,
        "completed_at": completed_str,
        "status": assessment.status,
        "filename": assessment.filename,
        "file_size_bytes": assessment.file_size_bytes,
        "file_size_formatted": format_bytes(assessment.file_size_bytes),
        "sha256": assessment.sha256,
        "md5": assessment.md5,
        "image_type": assessment.image_type,
        "device": device_data,
        "is_offline_analysis": device_data is None,
        "partitions": partitions,
        "risk_score": assessment.risk_score,
        "risk_rating": assessment.risk_rating,
        "summary_counts": summary_counts,
        "total_findings": len(findings_list),
        "findings": findings_list,
        "score_breakdown": {
            "raw_score": score_breakdown.get("raw_score", assessment.risk_score),
            "capped_score": score_breakdown.get("capped_score", assessment.risk_score),
            "rating": score_breakdown.get("rating", assessment.risk_rating),
            "items": raw_rule_breakdown,
            "disclaimer": score_breakdown.get(
                "disclaimer",
                "The Sentinel-X Risk Score is a deterministic heuristic reflecting static security indicators "
                "detected in the artifact. A score of 0 indicates that no configured indicator patterns were matched; "
                "it does not guarantee that the firmware or hardware is free of vulnerabilities."
            ),
        },
    }
