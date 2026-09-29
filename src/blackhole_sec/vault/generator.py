"""Password / passphrase generation with secrets (CSPRNG)."""
from __future__ import annotations

import secrets
import string

EFF_WORDS = ["amber", "banana", "cargo", "delta", "echo", "frost", "grape", "harbor", "ivory", "jungle", "karma", "lemon", "meadow", "north", "ocean", "piano", "quiet", "river", "solar", "tiger", "urban", "vivid", "whale", "xenon", "yearn", "zebra"]

AMBIGUOUS = set("l1I0O")


def generate_password(length: int = 20, symbols: bool = True, no_ambiguous: bool = True) -> str:
    if length < 8 or length > 128:
        raise ValueError("length must be 8..128")
    alpha = string.ascii_letters + string.digits + ("!@#$%^&*-_+=?" if symbols else "")
    if no_ambiguous:
        alpha = "".join(c for c in alpha if c not in AMBIGUOUS)
    return "".join(secrets.choice(alpha) for _ in range(length))


def generate_passphrase(words: int = 5) -> str:
    if words < 3 or words > 10:
        raise ValueError("words must be 3..10")
    return "-".join(secrets.choice(EFF_WORDS) for _ in range(words))
