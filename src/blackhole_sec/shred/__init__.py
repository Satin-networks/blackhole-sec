"""Shred subpackage: metadata analyze/clean/verify + secure delete."""
from .cleaner import clean_file, shred_file, verify_clean
from .metadata import analyze_file

__all__ = ["analyze_file", "clean_file", "shred_file", "verify_clean"]
