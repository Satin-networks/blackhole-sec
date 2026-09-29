"""Report helpers: defang, dict, text."""
from __future__ import annotations

from .features import FeatureResult
from .mitre import mitre_for


def defang(url: str) -> str:
    return url.replace("http", "hxxp").replace(".", "[.]").replace("@", "[@]").replace(":", "[:]")


def to_dict(info: dict, score: int, verdict: str, conf: str, fired: list[FeatureResult]) -> dict:
    return {
        "input": info["input"],
        "host": info["host"],
        "scheme": info["scheme"],
        "score": score,
        "verdict": verdict,
        "confidence": conf,
        "mitre": mitre_for([f.name for f in fired]),
        "defanged": defang(info["normalized"]),
        "signals": [
            {"name": f.name, "weight": f.weight, "evidence": f.evidence,
             "mitre": f.mitre, "explanation": f.explanation}
            for f in fired
        ],
    }


def format_text(info: dict, score: int, verdict: str, conf: str, fired: list[FeatureResult]) -> str:
    lines = [
        f"URL: {defang(info['normalized'])}",
        f"Host: {info['host'] or '(none)'}  Scheme: {info['scheme'] or '(none)'}",
        f"Verdict: {verdict}  Score: {score}/100  Confidence: {conf}",
    ]
    if not fired:
        lines.append("Signals: none - no phishing indicators found.")
    else:
        lines.append("Signals:")
        for f in fired:
            lines.append(f"  +{f.weight:2d} {f.name}: {f.evidence} - {f.explanation}")
    return "\n".join(lines)
