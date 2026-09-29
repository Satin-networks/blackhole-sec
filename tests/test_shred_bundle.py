from pathlib import Path

from PIL import Image

from blackhole_sec.bundle import create_bundle, extract_bundle
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
    create_bundle(src, bhb, password="bundle-pass-123!")
    dest = tmp_path / "out"
    names = extract_bundle(bhb, dest, password="bundle-pass-123!")
    assert (dest / "hello.txt").read_text() == "hi"
    assert len(names) == 2


def test_bundle_keyfile_roundtrip(tmp_path: Path):
    src = tmp_path / "d2"
    src.mkdir()
    (src / "x.txt").write_text("x")
    bhb = tmp_path / "b.bhb"
    meta = create_bundle(src, bhb, password=None)
    assert meta["keyfile"] and Path(meta["keyfile"]).exists()
    dest = tmp_path / "o2"
    extracted = extract_bundle(bhb, dest)
    assert (dest / "x.txt").read_text() == "x"
    assert extracted == ["x.txt"]


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
    create_bundle(src, bhb, password="right-123!")
    try:
        extract_bundle(bhb, tmp_path / "bad", password="wrong-123!")
        assert False, "should have failed"
    except ValueError:
        pass
