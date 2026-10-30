from typing import List, Dict, Any, Tuple, Optional
from backend.app.config import settings, ScoringWeights


CONFIDENCE_FACTORS = {
    "High": 1.0,
    "Medium": 0.8,
    "Low": 0.5,
}

RATING_THRESHOLDS = [
    (0, "Clean"),
    (19, "Low"),
    (49, "Moderate"),
    (79, "High"),
    (100, "Critical"),
]


def determine_rating_band(score: int) -> str:
    """Maps a bounded score (0-100) to its standardized heuristic rating band."""
    if score == 0:
        return "Clean"
    for threshold, rating in RATING_THRESHOLDS:
        if score <= threshold:
            return rating
    return "Critical"


SEVERITY_FLOORS = {
    "Critical": (80, "Critical"),
    "High": (60, "High"),
    "Medium": (35, "Moderate"),
    "Low": (5, "Low"),
    "Informational": (0, "Clean"),
}


def calculate_risk_score(
    findings: List[Dict[str, Any]],
    weights: Optional[ScoringWeights] = None,
    enforce_severity_floor: bool = True,
) -> Tuple[int, str, Dict[str, Any]]:
    """
    Computes an explainable, deterministic risk score from security findings.
    
    Definition of N:
    - N represents the number of byte-offset occurrences of a specific canonical finding
      in the binary (N = raw_occurrences = 1 + len(additional_offsets)).
    
    Deduplication & Repetition Policy:
    - Deduplication merges genuinely identical findings (same rule and same secret identity/evidence),
      consolidating their locations into additional_offsets.
    - Repeated occurrences (N > 1) of the same finding across flash offsets receive diminishing returns
      via an occurrence dampening multiplier:
          multiplier = 1.0 + (dampening_factor * min(N - 1, max_dampening_instances))
      With default settings (factor 0.2, max 5 instances), the multiplier scales smoothly from 1.0x to 2.0x.
      This ensures identical repeated strings do not inflate risk uncontrollably.
    - Distinct findings (different rules or different underlying secrets) represent separate security
      exposures and contribute independently to the composite score.
    - The composite score is capped strictly at 100 with standardized rating bands:
      Clean (0), Low (1-19), Moderate (20-49), High (50-79), Critical (80-100).
    - Severity Floor Policy: If vulnerabilities are present, the baseline risk score is anchored
      to the severity of the most severe finding (>=80 for Critical, >=60 for High, >=35 for Medium,
      >=5 for Low), ensuring critical and high vulnerabilities are never downplayed as 'Low' or 'Moderate' risk.
      Additional findings and occurrences contribute incremental points on top of the baseline, capped at 100.
    - An empty assessment produces a score of 0 and the 'Clean' rating band.
    
    Returns:
        (risk_score, risk_rating, score_breakdown)
    """
    if weights is None:
        weights = settings.scoring

    severity_weight_map = {
        "Critical": weights.critical,
        "High": weights.high,
        "Medium": weights.medium,
        "Low": weights.low,
        "Informational": weights.informational,
    }

    raw_total_score = 0.0
    finding_breakdown: List[Dict[str, Any]] = []

    for f in findings:
        r_id = f.get("rule_id", "UNKNOWN_RULE")
        title = f.get("title", "")
        severity = f.get("severity", "Low")
        confidence = f.get("confidence", "Medium")

        base_weight = severity_weight_map.get(severity, weights.low)
        conf_factor = CONFIDENCE_FACTORS.get(confidence, 0.8)

        # N represents the number of byte-offset occurrences of this specific finding
        occurrences = int(f.get("raw_occurrences", 1))

        # Dampening multiplier for repeated hits of the same finding across offsets
        dampening_instances = min(occurrences - 1, weights.max_dampening_instances)
        occurrence_multiplier = 1.0 + (weights.dampening_factor * max(0, dampening_instances))

        points = base_weight * conf_factor * occurrence_multiplier
        raw_total_score += points

        finding_breakdown.append({
            "finding_id": f.get("id"),
            "rule_id": r_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "occurrences": occurrences,
            "base_weight": base_weight,
            "confidence_factor": conf_factor,
            "multiplier": round(occurrence_multiplier, 2),
            "calculated_points": round(points, 2),
        })

    # Calculate raw score
    raw_final = round(raw_total_score)
    final_score = min(max(0, raw_final), 100)

    # Determine highest severity level present in findings
    severities = [f.get("severity", "Low") for f in findings]
    max_severity = None
    for s_level in ["Critical", "High", "Medium", "Low", "Informational"]:
        if s_level in severities:
            max_severity = s_level
            break

    severity_floor_applied = False
    floor_score = 0
    min_rating = "Clean"
    if enforce_severity_floor and max_severity and max_severity in SEVERITY_FLOORS:
        floor_score, min_rating = SEVERITY_FLOORS[max_severity]
        
        # Primary finding of max_severity contributes the baseline floor
        max_sev_points = 0.0
        for item in finding_breakdown:
            if item.get("severity") == max_severity:
                max_sev_points = max(max_sev_points, float(item.get("calculated_points", 0.0)))
        
        # Additional risk accumulated from other findings/occurrences beyond the primary finding
        additional_points = max(0.0, raw_total_score - max_sev_points)
        calculated_with_floor = floor_score + round(additional_points)
        final_score = min(100, max(floor_score, calculated_with_floor))
        if final_score >= floor_score and floor_score > raw_final:
            severity_floor_applied = True
    elif len(findings) > 0 and raw_total_score > 0:
        final_score = max(1, final_score)

    rating = determine_rating_band(final_score)
    # Guarantee rating band is not lower than severity floor
    rating_ranks = {"Clean": 0, "Low": 1, "Moderate": 2, "High": 3, "Critical": 4}
    if enforce_severity_floor and rating_ranks.get(rating, 0) < rating_ranks.get(min_rating, 0):
        rating = min_rating
    elif len(findings) > 0 and rating == "Clean":
        rating = "Low"

    breakdown = {
        "raw_score": round(raw_total_score, 2),
        "capped_score": final_score,
        "rating": rating,
        "severity_floor": floor_score if severity_floor_applied else None,
        "severity_floor_applied": severity_floor_applied,
        "max_severity_detected": max_severity,
        "findings_evaluated_count": len(findings),
        "finding_breakdown": finding_breakdown,
        "rule_breakdown": finding_breakdown,  # Backwards compatibility alias
        "disclaimer": (
            "The Sentinel-X Risk Score is a deterministic heuristic reflecting static security indicators "
            "detected in the artifact. A score of 0 indicates that no configured indicator patterns were matched; "
            "it does not guarantee that the firmware or hardware is free of vulnerabilities."
        ),
    }

    return final_score, rating, breakdown
