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
