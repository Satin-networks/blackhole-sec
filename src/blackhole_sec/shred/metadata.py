"""Look at file metadata without touching the file."""
from __future__ import annotations

import zipfile
from pathlib import Path

from PIL import Image
from PIL.ExifTags import TAGS

SENSITIVE_TAGS = {"GPSInfo", "Make", "Model", "Software", "Artist", "Copyright",
                  "DateTime", "DateTimeOriginal", "ExifOffset", "MakerNote"}


def analyze_file(path: str | Path) -> dict:
    p = Path(path)
    info: dict = {"file": str(p), "size": p.stat().st_size, "type": p.suffix.lower(),
                  "tags": {}, "sensitive": [], "score": 100}
    if info["type"] in (".jpg", ".jpeg", ".tiff", ".tif", ".webp", ".png"):
        try:
            with Image.open(p) as im:
                exif = im.getexif() if hasattr(im, "getexif") else {}
                for k, v in (exif.items() if exif else []):
                    name = TAGS.get(k, str(k))
                    info["tags"][name] = str(v)[:120]
                info["sensitive"] = [t for t in info["tags"] if t in SENSITIVE_TAGS]
        except Exception as e:
            info["error"] = str(e)
    elif info["type"] == ".docx":
        try:
            with zipfile.ZipFile(p) as z:
                for n in ("docProps/core.xml", "docProps/app.xml"):
                    if n in z.namelist():
                        info["tags"][n] = z.read(n)[:400].decode(errors="replace")
                        info["sensitive"].append(n)
        except Exception as e:
            info["error"] = str(e)
    elif info["type"] == ".pdf":
        try:
            data = p.read_bytes()
            for key in (b"/Author", b"/Creator", b"/Producer", b"/CreationDate", b"/ModDate"):
                if key in data:
                    info["tags"][key.decode()] = "present"
                    info["sensitive"].append(key.decode())
        except Exception as e:
            info["error"] = str(e)
    else:
        info["note"] = "generic file: no embedded EXIF parser; size/mtime only"
    info["score"] = max(0, 100 - 20 * len(info["sensitive"]))
    return info
