"""Password strength rules shared by bundles and the vault.

Length floors, a short classic blocklist, run and pattern detection.
Deterministic, offline, nothing to load.
"""
from __future__ import annotations

import re

MIN_PASSWORD_LEN = 12

# exact matches only; the pattern rules below catch most of the rest
COMMON_PASSWORDS = frozenset({
    "123456", "123456789", "12345678", "1234567", "1234567890", "12345",
    "111111", "000000", "666666", "654321", "123123", "121212", "112233",
    "123321", "qwerty", "qwerty123", "qwertyuiop", "azerty", "asdfghjkl",
    "zxcvbnm", "password", "password1", "password123", "passw0rd", "p@ssw0rd",
    "letmein", "welcome", "welcome1", "iloveyou", "iloveu", "monkey",
    "monkey1", "dragon", "master", "shadow", "sunshine", "princess",
    "football", "baseball", "soccer", "hockey", "pokemon", "minecraft",
    "batman", "superman", "starwars", "trustno1", "whatever", "hello123",
    "admin", "admin123", "root", "toor", "guest", "secret", "changeme",
    "computer", "internet", "michael", "jennifer", "jordan23", "hunter2",
    "killer", "buster", "harley", "ranger", "tigger", "charlie", "daniel",
    "thomas", "robert", "andrew", "joshua", "pepper", "cookie", "maggie",
    "summer", "winter", "spring", "autumn", "october", "november", "december",
    "january", "february", "march1", "april", "august", "september",
    "kali", "kalilinux", "debian", "ubuntu", "linux123", "windows",
    "blackhole", "opsec", "opencode", "hacker", "h4cker", "gamer", "gamer1",
    "minecraft1", "fortnite", "roblox", "cod123", "sniper", "matrix",
    "terminal", "scriptkiddie", "freedom", "america", "canada", "london",
    "paris1", "berlin", "tokyo1", "naruto", "goku", "sasuke", "vegeta",
    "onepiece", "deathnote", "satan", "god", "jesus", "jesus1", "love123",
    "baby123", "angel", "angel1", "devil666", "soccer1", "basketball",
})

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "0123456789")


def _repetitive(low: str) -> bool:
    """True for passwords built from runs, counts, or keyboard walks."""
    if len(low) < 4:
        return False
    if re.fullmatch(r"(.+)\1+", low):  # "abcabc", "x1x1x1"
        return True
    if re.search(r"(.)\1{3,}", low):  # "aaaa", "!!!!"
        return True
    if re.search(r"(.{1,3})\1{2,}", low):  # "ababab", "123123123"
        return True
    runs = ["abcdefghijklmnopqrstuvwxyz", "0123456789", *_KEYBOARD_ROWS]
    for seq in runs:
        for i in range(len(seq) - 3):
            chunk = seq[i:i + 4]
            if chunk in low or chunk[::-1] in low:
                return True
    return False


def password_problems(password: str) -> list[str]:
    """Reasons PW is too weak for an archive or a vault master. Empty means ok."""
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LEN:
        problems.append(f"shorter than {MIN_PASSWORD_LEN} characters")
    classes = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ))
    if len(password) < 16 and classes < 3:
        problems.append(
            "under 16 characters and not mixing three of: lower, upper, digits, symbols"
        )
    low = password.lower()
    if low in COMMON_PASSWORDS:
        problems.append("it is one of the most guessed passwords")
    if _repetitive(low):
        problems.append("it repeats simple runs (like aaaa, abcd, qwerty)")
    return problems
