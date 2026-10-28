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


def calculate_risk_score(
    findings: List[Dict[str, Any]],
    weights: Optional[ScoringWeights] = None,
) -> Tuple[int, str, Dict[str, Any]]:
    """
    Computes an explainable, deterministic risk score from security findings.
    
    Rules:
    - Each rule_id represents an underlying indicator class.
    - Repeated occurrences of the same rule are dampened via diminishing returns.
    - Lower confidence findings have reduced weight.
    - Score is capped at 100.
    
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

    # Group findings by rule_id
    grouped_by_rule: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        r_id = f.get("rule_id", "UNKNOWN_RULE")
        grouped_by_rule.setdefault(r_id, []).append(f)

    raw_total_score = 0.0
    rule_breakdown: List[Dict[str, Any]] = []

    for rule_id, rule_findings in grouped_by_rule.items():
        primary_finding = rule_findings[0]
        severity = primary_finding.get("severity", "Low")
        confidence = primary_finding.get("confidence", "Medium")

        base_weight = severity_weight_map.get(severity, weights.low)
        conf_factor = CONFIDENCE_FACTORS.get(confidence, 0.8)

        # Sum occurrences across all instances of this rule
        total_occurrences = sum(f.get("raw_occurrences", 1) for f in rule_findings)
        
        # Dampening multiplier for repeated hits of the same rule
        dampening_instances = min(total_occurrences - 1, weights.max_dampening_instances)
        occurrence_multiplier = 1.0 + (weights.dampening_factor * max(0, dampening_instances))

        rule_points = base_weight * conf_factor * occurrence_multiplier
        raw_total_score += rule_points

        rule_breakdown.append({
            "rule_id": rule_id,
            "title": primary_finding.get("title", ""),
            "severity": severity,
            "confidence": confidence,
            "occurrences": total_occurrences,
            "base_weight": base_weight,
            "confidence_factor": conf_factor,
            "multiplier": round(occurrence_multiplier, 2),
            "calculated_points": round(rule_points, 2),
        })

    final_score = min(round(raw_total_score), 100)
    rating = determine_rating_band(final_score)

    breakdown = {
        "raw_score": round(raw_total_score, 2),
        "capped_score": final_score,
        "rating": rating,
        "rules_evaluated_count": len(grouped_by_rule),
        "rule_breakdown": rule_breakdown,
        "disclaimer": (
            "The Sentinel-X Risk Score is a deterministic heuristic reflecting static security indicators "
            "detected in the artifact. A score of 0 indicates that no configured indicator patterns were matched; "
            "it does not guarantee that the firmware or hardware is free of vulnerabilities."
        ),
    }

    return final_score, rating, breakdown
