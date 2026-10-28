# Sentinel-X Assessment Package
from backend.app.modules.assessment.normalizer import (
    FindingSeverity,
    FindingConfidence,
    compute_finding_fingerprint,
    normalize_finding,
    deduplicate_findings,
    NormalizedFinding,
)

__all__ = [
    "FindingSeverity",
    "FindingConfidence",
    "compute_finding_fingerprint",
    "normalize_finding",
    "deduplicate_findings",
    "NormalizedFinding",
]
