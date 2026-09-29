"""Weighted scoring + verdicts + confidence."""
from __future__ import annotations

from .features import FeatureResult

BENIGN_MAX = 20
SUSPICIOUS_MAX = 49


def score_features(feats: list[FeatureResult]) -> tuple[int, str, str, list[FeatureResult]]:
    score = min(100, sum(f.weight for f in feats if f.fired))
    verdict = verdict_for_score(score)
    fired = [f for f in feats if f.fired]
    # Confidence: TI-less offline model -> based on signal count + max weight
    if score >= 50 and len(fired) >= 3:
        conf = "HIGH"
    elif len(fired) >= 4 or score >= 35:
        conf = "MEDIUM"
    elif len(fired) >= 2:
        conf = "LOW"
    else:
        conf = "VERY_LOW"
    return score, verdict, conf, fired


def verdict_for_score(score: int) -> str:
    if score <= BENIGN_MAX:
        return "BENIGN"
    if score <= SUSPICIOUS_MAX:
        return "SUSPICIOUS"
    return "MALICIOUS"
