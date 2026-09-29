"""Check subpackage: offline phishing URL analysis."""
from .features import FeatureResult, analyze_url
from .report import defang, format_text, to_dict
from .scorer import score_features, verdict_for_score

__all__ = ["FeatureResult", "analyze_url", "defang", "format_text", "score_features", "to_dict", "verdict_for_score"]
