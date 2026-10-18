"""Password / passphrase generation with secrets (CSPRNG).

Passphrases come from the EFF large wordlist (7776 words; five words is
~64 bits). The list loads lazily, so a broken install only breaks
passphrase generation, not the rest of the tool.
"""
from __future__ import annotations

import secrets
import string
from functools import lru_cache
from importlib.resources import files

AMBIGUOUS = set("l1I0O")

_WORDLIST_PACKAGE = "blackhole_sec"
_WORDLIST_NAME = "eff_large_wordlist.txt"


@lru_cache(maxsize=1)
def eff_words() -> tuple[str, ...]:
    """The EFF large wordlist, one lowercase word per entry."""
    raw = files(_WORDLIST_PACKAGE).joinpath("data", _WORDLIST_NAME).read_text(encoding="utf-8")
    words: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        word = line.split()[-1]
        if "-" in word:  # t-shirt, yo-yo: keep phrases parseable as N words
            continue
        words.append(word)
    if len(words) < 1024:
        raise RuntimeError("wordlist is missing or truncated; reinstall blackhole-sec")
    return tuple(words)


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
    pool = eff_words()
    return "-".join(secrets.choice(pool) for _ in range(words))
