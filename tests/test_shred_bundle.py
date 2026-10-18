from pathlib import Path

import pytest
from PIL import Image

from blackhole_sec.bundle import (
    DEFAULT_KDF_PRESET,
    KDF_PRESETS,
    NeedsPassword,
    WrongPassword,
    bundle_info,
    create_bundle,
    extract_bundle,
    password_problems,
    read_bundle,
)
from blackhole_sec.shred.cleaner import clean_file, shred_file, verify_clean
from blackhole_sec.shred.metadata import analyze_file


def _img_with_exif(p: Path):
    im = Image.new("RGB", (16, 16), "red")
    exif = Image.Exif()
    exif[271] = "EvilCam"  # Make
    exif[306] = "2024:01:01 00:00:00"  # DateTime
    im.save(p, exif=exif)


def test_analyze_and_clean(tmp_path: Path):
    src = tmp_path / "a.jpg"
    _img_with_exif(src)
    info = analyze_file(src)
    assert info["sensitive"], info
    out = clean_file(src)
    ok, _ = verify_clean(out)
    assert ok
    # src untouched (non-destructive)
    assert src.exists() and out.exists()


def test_shred_removes(tmp_path: Path):
    f = tmp_path / "secret.txt"
    f.write_text("top secret")
    shred_file(f, passes=1)
    assert not f.exists()


def test_bundle_password_roundtrip(tmp_path: Path):
    src = tmp_path / "data"
    (src / "sub").mkdir(parents=True)
    (src / "hello.txt").write_text("hi")
    (src / "sub" / "b.txt").write_text("bye")
    bhb = tmp_path / "a.bhb"
    create_bundle(src, bhb, password="bundle-pass-123!", preset="light")
    dest = tmp_path / "out"
    names = extract_bundle(bhb, dest, password="bundle-pass-123!")
    assert (dest / "hello.txt").read_text() == "hi"
    assert len(names) == 2


def test_bundle_plain_roundtrip(tmp_path: Path):
    src = tmp_path / "d2"
    src.mkdir()
    (src / "x.txt").write_text("x")
    bhb = tmp_path / "b.bhb"
    meta = create_bundle(src, bhb, password=None)
    assert meta["keyfile"] is None
    assert not Path(str(bhb) + ".key").exists()
    dest = tmp_path / "o2"
    extracted = extract_bundle(bhb, dest)
    assert (dest / "x.txt").read_text() == "x"
    assert extracted == ["x.txt"]


def test_bundle_legacy_keyfile_still_opens(tmp_path: Path):
    """Bundles from 0.2.x keyfile mode keep opening (kdf 0 reader)."""
    import os
    import struct

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from blackhole_sec.bundle import (
        HEADER_FMT,
        MAGIC,
        NONCE_LEN,
        VERSION_KDF_NONE,
        _build_tar,
    )
    from blackhole_sec.vault.crypto import b64e

    src = tmp_path / "old"
    src.mkdir()
    (src / "o.txt").write_text("legacy")
    tar_bytes = _build_tar(src)
    key = os.urandom(32)
    salt = os.urandom(8)
    nonce = os.urandom(NONCE_LEN)
    header = struct.pack(HEADER_FMT, MAGIC, VERSION_KDF_NONE, 3, 65536, 4, len(salt)) + salt + nonce
    ct = AESGCM(key).encrypt(nonce, tar_bytes, header)
    bhb = tmp_path / "old.bhb"
    bhb.write_bytes(header + struct.pack(">Q", len(ct)) + ct)
    kf = tmp_path / "old.bhb.key"
    kf.write_text(b64e(key))
    out = tmp_path / "ro"
    assert extract_bundle(bhb, out, keyfile=kf) == ["o.txt"]
    assert (out / "o.txt").read_text() == "legacy"


def test_bundle_zipslip_rejected(tmp_path: Path):
    import io
    import tarfile

    from blackhole_sec.bundle import _safe_extract
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("../../evil.txt")
        payload = b"evil"
        ti.size = len(payload)
        tf.addfile(ti, io.BytesIO(payload))
    dest = tmp_path / "safe"
    names = _safe_extract(buf.getvalue(), dest)
    assert names == [] and not (tmp_path / "evil.txt").exists()


def test_bundle_wrong_password_fails(tmp_path: Path):
    src = tmp_path / "d3"
    src.mkdir()
    (src / "s.txt").write_text("s")
    bhb = tmp_path / "c.bhb"
    create_bundle(src, bhb, password="right-password-1", preset="light")
    with pytest.raises(WrongPassword):
        extract_bundle(bhb, tmp_path / "bad", password="wrong-password-1")


def test_bundle_weak_passwords_rejected(tmp_path: Path):
    src = tmp_path / "d4"
    src.mkdir()
    (src / "s.txt").write_text("s")
    bhb = tmp_path / "weak.bhb"
    assert password_problems("Password1")  # 10 chars and on the classic list
    with pytest.raises(ValueError) as ei:
        create_bundle(src, bhb, password="Password1", preset="light")
    assert "shorter than 12" in str(ei.value)
    assert not bhb.exists()


def test_bundle_strong_passphrase_accepted(tmp_path: Path):
    src = tmp_path / "d5"
    src.mkdir()
    (src / "s.txt").write_text("s")
    bhb = tmp_path / "ok.bhb"
    pw = "abacus-abdomen-abdominal"
    create_bundle(src, bhb, password=pw, preset="light")
    assert extract_bundle(bhb, tmp_path / "o5", password=pw) == ["s.txt"]


def test_bundle_default_kdf_is_heavy(tmp_path: Path):
    assert DEFAULT_KDF_PRESET == "hard"
    assert KDF_PRESETS["light"] == {"t": 3, "m": 64 * 1024, "p": 4}
    hard = KDF_PRESETS["hard"]
    # the default must beat the old 64 MiB x 3 by at least 32x
    assert hard["m"] * hard["t"] >= 32 * (64 * 1024 * 3)
    src = tmp_path / "d6"
    src.mkdir()
    (src / "s.txt").write_text("s")
    bhb = tmp_path / "default.bhb"
    create_bundle(src, bhb, password="bundle-pass-123!")
    info = bundle_info(bhb)
    assert (info["t"], info["m"], info["p"]) == (hard["t"], hard["m"], hard["p"])


def test_bundle_needs_password_error(tmp_path: Path):
    src = tmp_path / "d7"
    src.mkdir()
    (src / "s.txt").write_text("s")
    bhb = tmp_path / "np.bhb"
    create_bundle(src, bhb, password="bundle-pass-123!", preset="light")
    with pytest.raises(NeedsPassword):
        read_bundle(bhb)


def test_bundle_rejects_absurd_header_params(tmp_path: Path):
    import os
    import struct

    from blackhole_sec.bundle import HEADER_FMT, MAGIC

    salt = os.urandom(16)
    header = struct.pack(HEADER_FMT, MAGIC, 1, 3, 10 ** 9, 4, len(salt)) + salt + b"\x00" * 12
    bad = tmp_path / "absurd.bhb"
    bad.write_bytes(header + struct.pack(">Q", 8) + b"\x00" * 8)
    with pytest.raises(ValueError) as ei:
        read_bundle(bad, password="whatever-password-1")
    assert "unsupported KDF parameters" in str(ei.value)
