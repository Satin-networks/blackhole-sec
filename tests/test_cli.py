"""CLI help and non-interactive behavior. Every command must explain itself."""
import json

from click.testing import CliRunner
from PIL import Image

from blackhole_sec.cli import main

runner = CliRunner()


def test_top_level_help_lists_commands():
    r = runner.invoke(main, ["--help"])
    assert r.exit_code == 0, r.output
    for cmd in ("check", "vault", "shred", "bundle", "intake"):
        assert cmd in r.output


def test_every_command_has_help():
    groups = [
        ["check", "--help"],
        ["vault", "--help"],
        ["vault", "init", "--help"],
        ["vault", "set", "--help"],
        ["vault", "get", "--help"],
        ["vault", "list", "--help"],
        ["vault", "audit", "--help"],
        ["vault", "gen", "--help"],
        ["shred", "--help"],
        ["shred", "analyze", "--help"],
        ["shred", "clean", "--help"],
        ["shred", "verify", "--help"],
        ["shred", "shred", "--help"],
        ["bundle", "--help"],
        ["bundle", "create", "--help"],
        ["bundle", "extract", "--help"],
        ["intake", "--help"],
        ["upgrade", "--help"],
    ]
    for args in groups:
        r = runner.invoke(main, args)
        assert r.exit_code == 0, args
        assert "Example" in r.output, args


def test_short_help_flag_works():
    r = runner.invoke(main, ["check", "-h"])
    assert r.exit_code == 0
    assert "URLS" in r.output or "URL" in r.output


def test_check_benign_and_malicious_exit_codes():
    r = runner.invoke(main, ["check", "https://www.google.com"])
    assert r.exit_code == 0
    assert "BENIGN" in r.output
    r = runner.invoke(main, ["check", "http://secure.paypal.com.evil-tk.tk/login?redirect=http://evil.com"])
    assert r.exit_code == 2
    assert "MALICIOUS" in r.output


def test_check_explain_adds_reasons():
    url = "http://secure-paypal-login.tk/free-nitro"
    plain = runner.invoke(main, ["check", url])
    explained = runner.invoke(main, ["check", "--explain", url])
    assert explained.output.count("T1566") >= plain.output.count("T1566")
    assert len(explained.output) > len(plain.output)


def test_check_json_is_parseable():
    r = runner.invoke(main, ["check", "--json", "https://www.google.com"])
    assert r.exit_code == 0
    assert json.loads(r.output)[0]["verdict"] == "BENIGN"


def test_check_needs_input():
    r = runner.invoke(main, ["check"])
    assert r.exit_code != 0
    assert "--file" in r.output


def test_bundle_create_rejects_both_flags(tmp_path):
    src = tmp_path / "d"
    src.mkdir()
    r = runner.invoke(main, ["bundle", "create", str(src), str(tmp_path / "o.bhb"),
                             "--password", "--no-password"])
    assert r.exit_code != 0
    assert "not both" in r.output


def test_shred_verify_and_intake(tmp_path):
    img = tmp_path / "p.png"
    Image.new("RGB", (8, 8), "blue").save(img)
    r = runner.invoke(main, ["shred", "verify", str(img)])
    assert r.exit_code == 0
    assert "PASS" in r.output
    r = runner.invoke(main, ["intake", "https://www.google.com", str(img)])
    assert r.exit_code == 0
    assert "BENIGN" in r.output and "CLEAN" in r.output


def test_vault_gen_validates():
    r = runner.invoke(main, ["vault", "gen", "--length", "24"])
    assert r.exit_code == 0
    assert len(r.output.strip()) == 24
    r = runner.invoke(main, ["vault", "gen", "--words", "5"])
    assert r.exit_code == 0
    assert len(r.output.strip().split("-")) == 5


def test_upgrade_check_reports_versions(monkeypatch):
    from blackhole_sec import cli

    monkeypatch.setattr(cli, "_installed_version", lambda: "0.1.0")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda timeout=10: "0.1.1")
    r = runner.invoke(main, ["upgrade", "--check"])
    assert r.exit_code == 0
    assert "0.1.0" in r.output and "0.1.1" in r.output


def test_upgrade_check_already_latest(monkeypatch):
    from blackhole_sec import cli

    monkeypatch.setattr(cli, "_installed_version", lambda: "0.1.1")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda timeout=10: "0.1.1")
    r = runner.invoke(main, ["upgrade", "--check"])
    assert r.exit_code == 0
    assert "already on the latest" in r.output


def test_upgrade_runs_pip(monkeypatch):
    import subprocess

    from blackhole_sec import cli

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(cli, "_installed_version", lambda: "0.1.0")
    monkeypatch.setattr(cli, "_latest_pypi_version", lambda timeout=10: "0.1.1")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    r = runner.invoke(main, ["upgrade"])
    assert r.exit_code == 0, r.output
    assert calls and calls[0][-2:] == ["--upgrade", "blackhole-sec"]


def test_upgrade_no_network(monkeypatch):
    from blackhole_sec import cli

    def boom(timeout=10):
        raise OSError("offline")

    monkeypatch.setattr(cli, "_latest_pypi_version", boom)
    r = runner.invoke(main, ["upgrade", "--check"])
    assert r.exit_code != 0
    assert "PyPI" in r.output


def test_bundle_create_unwritable_dir(tmp_path):
    import os

    if os.geteuid() == 0:
        import pytest

        pytest.skip("permission bits don't apply to root")
    src = tmp_path / "d"
    src.mkdir()
    (src / "f.txt").write_text("x")
    denied = tmp_path / "noperm"
    denied.mkdir()
    denied.chmod(0o555)
    try:
        r = runner.invoke(main, ["bundle", "create", "--no-password", str(src), str(denied / "o.bhb")])
    finally:
        denied.chmod(0o755)
    assert r.exit_code != 0
    assert "permission denied" in r.output
    assert "Traceback" not in r.output


def test_bundle_extract_wrong_password_is_clean(tmp_path):
    from blackhole_sec.bundle import create_bundle

    src = tmp_path / "d"
    src.mkdir()
    (src / "s.txt").write_text("s")
    bhb = tmp_path / "c.bhb"
    create_bundle(src, bhb, password="right-password-1")
    r = runner.invoke(main, ["bundle", "extract", str(bhb), str(tmp_path / "out")])
    assert r.exit_code != 0
    assert "password" in r.output.lower()
    assert "Traceback" not in r.output


def test_vault_missing_hints_init(tmp_path):
    r = runner.invoke(main, ["vault", "get", "ghost", "--vault", str(tmp_path / "nope.db")])
    assert r.exit_code != 0
    assert "vault init" in r.output
    assert "Traceback" not in r.output


def test_misplaced_flag_suggests_subcommand():
    r = runner.invoke(main, ["bundle", "--no-password", "a", "b"])
    assert r.exit_code != 0
    assert "bundle create" in r.output
    assert "--no-password" in r.output


def test_misplaced_flag_on_top_level():
    r = runner.invoke(main, ["--json", "http://x.tk/"])
    assert r.exit_code != 0
    assert "check" in r.output


def test_typo_suggests_command():
    r = runner.invoke(main, ["bundle", "cretae"])
    assert r.exit_code != 0
    assert "create" in r.output
