from pathlib import Path

import pytest

from blackhole_sec.vault.generator import generate_passphrase, generate_password
from blackhole_sec.vault.store import Vault, VaultLocked


def test_create_set_get_audit(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "correct-horse-battery-staple-1!", preset="light")
    v.set("github", "alice", "supersecretpassword123", "notes")
    e = v.get("github")
    assert e and e.password == "supersecretpassword123"
    a = v.audit()
    assert a["total"] == 1
    assert p.stat().st_mode & 0o777 == 0o600
    v.lock()
    assert v.is_locked


def test_wrong_master_rejected(tmp_path: Path):
    p = tmp_path / "v.db"
    Vault.create(p, "right-password-12345", preset="light")
    v = Vault(p)
    with pytest.raises(VaultLocked):
        v.unlock("wrong-password-12345")


def test_reuse_detected(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "another-good-master-1!", preset="light")
    v.set("a", "u", "samepassword12345")
    v.set("b", "u", "samepassword12345")
    a = v.audit()
    assert a["reused"]


def test_vault_defaults_are_heavier(tmp_path: Path):
    import json

    from blackhole_sec.vault.crypto import DEFAULT_PRESET, KDF_PRESETS

    assert DEFAULT_PRESET == "hard"
    hard = KDF_PRESETS["hard"]
    # at least 16x the old 64 MiB x 3 per guess
    assert hard["m"] * hard["t"] >= 16 * (64 * 1024 * 3)
    p = tmp_path / "v.db"
    Vault.create(p, "defaults-check-master-1!")
    params = json.loads(p.read_text())["kdf_params"]
    assert params == hard


def test_change_master_upgrades_kdf(tmp_path: Path):
    import json

    p = tmp_path / "v.db"
    v = Vault.create(p, "old-master-password-1", preset="light")
    v.change_master("new-master-password-1")
    params = json.loads(p.read_text())["kdf_params"]
    from blackhole_sec.vault.crypto import KDF_PRESETS

    assert params == KDF_PRESETS["hard"]
    v2 = Vault(p)
    with pytest.raises(VaultLocked):
        v2.unlock("old-master-password-1")
    v2.unlock("new-master-password-1")
    assert v2.get("github") is None  # empty vault, but it opens


def test_vault_stores_and_exports_files(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "file-master-1234!", preset="light")
    src = tmp_path / "doc.txt"
    body = b"stored file body " * 500
    src.write_bytes(body)
    e = v.add_file(src, label="doc")
    assert e.kind == "file" and e.size == len(body) and e.filename == "doc.txt"
    assert e.sha256 and e.password == ""
    assert (tmp_path / "v.db.files").is_dir()

    v2 = Vault(p)
    v2.unlock("file-master-1234!")
    outdir = tmp_path / "out"
    outdir.mkdir()
    out = v2.export_file("doc", outdir)
    assert out.read_bytes() == body
    with pytest.raises(FileExistsError):
        v2.export_file("doc", outdir)
    v2.export_file("doc", outdir, force=True)
    nested = v2.export_file("doc", str(tmp_path / "deep") + "/")
    assert nested.read_bytes() == body


def test_vault_export_rejects_secrets_and_ghosts(tmp_path: Path):
    v = Vault.create(tmp_path / "v.db", "file-master-1234!", preset="light")
    v.set("github", "alice", "entry-password-12345")
    with pytest.raises(KeyError):
        v.export_file("github", tmp_path)
    with pytest.raises(KeyError):
        v.export_file("ghost", tmp_path)


def test_vault_file_cap_and_tamper_detection(tmp_path: Path):
    v = Vault.create(tmp_path / "v.db", "file-master-1234!", preset="light")
    src = tmp_path / "big.bin"
    src.write_bytes(b"x" * 40)
    with pytest.raises(ValueError):
        v.add_file(src, max_bytes=8)
    e = v.add_file(src)
    blob = v.files_dir / f"{e.file_id}.bin"
    raw = bytearray(blob.read_bytes())
    raw[-1] ^= 1
    blob.write_bytes(bytes(raw))
    with pytest.raises(ValueError):
        v.export_file("big.bin", tmp_path)


def test_vault_file_replace_remove_and_change_master(tmp_path: Path):
    p = tmp_path / "v.db"
    v = Vault.create(p, "file-master-1234!", preset="light")
    one = tmp_path / "one.txt"
    one.write_bytes(b"first")
    e1 = v.add_file(one, label="keep")
    old_id = e1.file_id
    old_blob = v.files_dir / f"{old_id}.bin"
    assert old_blob.exists()

    two = tmp_path / "two.txt"
    two.write_bytes(b"second")
    e2 = v.add_file(two, label="keep")
    assert e2.file_id != old_id
    assert not old_blob.exists()

    v.change_master("new-file-master-1234!", preset="light")
    outdir = tmp_path / "out"
    outdir.mkdir()
    assert v.export_file("keep", outdir).read_bytes() == b"second"

    v2 = Vault(p)
    with pytest.raises(VaultLocked):
        v2.unlock("file-master-1234!")
    v2.unlock("new-file-master-1234!")
    assert v2.export_file("keep", outdir, force=True).read_bytes() == b"second"

    blob = v.files_dir / f"{e2.file_id}.bin"
    assert v.remove("keep")
    assert not blob.exists()
    with pytest.raises(KeyError):
        v.export_file("keep", tmp_path)


def test_vault_audit_ignores_stored_files(tmp_path: Path):
    v = Vault.create(tmp_path / "v.db", "file-master-1234!", preset="light")
    src = tmp_path / "a.txt"
    src.write_bytes(b"data")
    v.add_file(src)
    a = v.audit()
    assert a["total"] == 1 and not a["weak"] and not a["reused"]


def test_generators():
    assert len(generate_password(20)) == 20
    assert len(generate_passphrase(5).split("-")) == 5
    with pytest.raises(ValueError):
        generate_password(4)


def test_passphrase_wordlist_is_the_full_eff_list():
    from blackhole_sec.vault.generator import eff_words

    words = eff_words()
    # the full 7776 minus the few hyphenated entries the loader drops
    assert 7700 < len(words) <= 7776
    assert len(set(words)) == len(words)
    assert all(w.isascii() and w.islower() for w in words)
