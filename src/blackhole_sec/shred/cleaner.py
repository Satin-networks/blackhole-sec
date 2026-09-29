"""Clean, verify and shred files."""
from __future__ import annotations

import os
from pathlib import Path

from PIL import Image

from .metadata import analyze_file

SHRED_RENAMES = 3


def clean_file(src: str | Path, out: str | Path | None = None) -> Path:
    """Write a cleaned copy next to the original. The original is left alone."""
    s = Path(src)
    o = Path(out) if out else s.with_name(s.stem + ".cleaned" + s.suffix)
    if s.suffix.lower() in (".jpg", ".jpeg", ".tiff", ".tif", ".webp", ".png"):
        with Image.open(s) as im:
            # Re-save without EXIF: Pillow drops exif unless explicitly passed.
            if im.mode in ("RGBA", "LA") and o.suffix.lower() in (".jpg", ".jpeg"):
                im = im.convert("RGB")
            im.save(o)
    elif s.suffix.lower() == ".pdf":
        data = s.read_bytes()
        # Minimal sanitization: remove common info keys is non-trivial without
        # a PDF lib; safest honest behavior is copy + report remaining risk.
        o.write_bytes(data)
    else:
        o.write_bytes(s.read_bytes())
    return o


def verify_clean(path: str | Path) -> tuple[bool, dict]:
    info = analyze_file(path)
    clean = len(info.get("sensitive", [])) == 0
    return clean, info


def shred_file(path: str | Path, passes: int = 3) -> None:
    """Overwrite + rename + unlink. Default 3 (DoD-like); 1=fast, 7=paranoid."""
    if passes not in (1, 3, 7):
        raise ValueError("passes must be 1, 3 or 7")
    p = Path(path)
    size = p.stat().st_size
    patterns = [b"\x00", b"\xFF", None]  # None = random
    with open(p, "r+b") as f:
        for i in range(passes):
            pat = patterns[i % 3]
            chunk = (pat * 65536) if pat else os.urandom(65536)
            f.seek(0)
            remaining = size
            while remaining > 0:
                n = min(65536, remaining)
                f.write(chunk[:n] if pat else os.urandom(n))
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
    # Rename to hide name, then delete
    for _ in range(SHRED_RENAMES):
        tmp = p.with_name(os.urandom(8).hex())
        try:
            p.rename(tmp)
            p = tmp
        except Exception:
            break
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass
