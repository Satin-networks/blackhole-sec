"""blackhole command line. check / vault / shred / bundle / intake."""
from __future__ import annotations

import csv
import getpass
import json
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .bundle import create_bundle, extract_bundle
from .check.features import analyze_url
from .check.mitre import mitre_for
from .check.report import defang, format_text, to_dict
from .check.scorer import score_features
from .shred.cleaner import clean_file, shred_file, verify_clean
from .shred.metadata import analyze_file
from .vault.generator import generate_passphrase, generate_password
from .vault.store import Vault, VaultLocked

console = Console()
DEFAULT_VAULT = "~/.blackhole/vault.db"
HELP_NAMES = {"help_option_names": ["-h", "--help"]}

MAIN_EPILOG = """\b
Examples:
  blackhole check "http://secure-paypal-login.tk/free-nitro"
  blackhole vault init
  blackhole shred analyze photo.jpg
  blackhole bundle create ./mydir ./backup.bhb

Run 'blackhole COMMAND -h' for that command's options.
Full guide: https://satin-networks.github.io/blackhole-sec/
"""


def _master(prompt: str = "Master password: ") -> str:
    return getpass.getpass(prompt)


def _open_vault(path: str) -> Vault:
    v = Vault(Path(path).expanduser())
    try:
        v.unlock(_master())
    except VaultLocked as e:
        raise click.ClickException(str(e)) from e
    return v


def _installed_version() -> str:
    try:
        from importlib.metadata import version

        return version("blackhole-sec")
    except Exception:
        return __version__


def _latest_pypi_version(timeout: int = 10) -> str:
    import urllib.request

    req = urllib.request.Request(
        "https://pypi.org/pypi/blackhole-sec/json",
        headers={"User-Agent": "blackhole-sec"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)["info"]["version"]


@click.group(context_settings=HELP_NAMES, epilog=MAIN_EPILOG)
@click.version_option(_installed_version(), prog_name="blackhole-sec")
def main() -> None:
    """Offline opsec toolkit. Nothing leaves your machine."""


# check
@main.command(
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole check "http://secure-paypal-login.tk/free-nitro"
  blackhole check -f urls.txt --json > report.json
  echo "http://paypal-secure.tk/login" | blackhole check --file -
  blackhole check suspect.tk/even --threshold 30; echo $?

Exit codes: 0 means nothing scored at/above --threshold,
2 means something did (handy in scripts and CI).
""",
)
@click.argument("urls", nargs=-1, metavar="[URL]...")
@click.option(
    "--file",
    "-f",
    "file_",
    metavar="PATH",
    type=click.Path(exists=True, allow_dash=True),
    help="Read URLs from PATH, one per line. Use - for stdin.",
)
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON and skip the rich table.")
@click.option("--csv", "as_csv", is_flag=True, help="Print one CSV row per URL (input,host,score,verdict,...).")
@click.option(
    "--explain",
    is_flag=True,
    help="Add a plain-language reason and MITRE tag under every fired signal.",
)
@click.option(
    "--threshold",
    type=int,
    default=50,
    show_default=True,
    help="Score at/above which the exit code becomes 2. 0-20 is BENIGN, 21-49 SUSPICIOUS, 50+ MALICIOUS.",
)
def check_cmd(urls, file_, as_json, as_csv, explain, threshold):
    """Score one or more URLs without fetching them.

    URLS are checked as pure text over stdin-safe heuristics. The URL is
    never opened, so pasting a live phish is safe. Output is defanged
    (hxxp[://]) so it can't be clicked by accident.
    """
    targets: list[str] = list(urls)
    if file_:
        src = sys.stdin.read().splitlines() if file_ == "-" else Path(file_).read_text().splitlines()
        targets += [line.strip() for line in src if line.strip()]
    if not targets:
        raise click.UsageError("give at least one URL or --file PATH")
    results = []
    for raw in targets:
        info, feats = analyze_url(raw)
        score, verdict, conf, fired = score_features(feats)
        results.append((info, score, verdict, conf, fired))
    if as_json:
        click.echo(json.dumps([to_dict(i, s, v, c, f) for i, s, v, c, f in results], indent=2))
    elif as_csv:
        w = csv.writer(sys.stdout)
        w.writerow(["input", "host", "score", "verdict", "confidence", "mitre", "defanged"])
        for i, s, v, c, f in results:
            d = to_dict(i, s, v, c, f)
            w.writerow([d["input"], d["host"], s, v, c, ";".join(d["mitre"]), d["defanged"]])
    else:
        for i, s, v, c, f in results:
            color = "green" if v == "BENIGN" else ("yellow" if v == "SUSPICIOUS" else "red")
            console.print(f"[bold {color}]{v} {s}/100 ({c})[/] {defang(i['normalized'])}")
            for feat in f:
                console.print(f"  +{feat.weight:2d} {feat.name}: {feat.evidence}")
                if explain:
                    console.print(f"       [dim]{feat.explanation} [{feat.mitre or 'no MITRE tag'}][/]")
            console.print(f"  [dim]MITRE: {', '.join(mitre_for([x.name for x in f])) or 'none'}[/]")
    worst = max(s for _, s, _, _, _ in results)
    sys.exit(2 if worst >= threshold else 0)


# vault
@main.group(
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole vault init
  blackhole vault set github --username alice --generate 24
  blackhole vault get github --show
""",
)
def vault_grp():
    """Password vault on your own disk.

    First run 'blackhole vault init', then 'set'/'get' entries by SERVICE
    name (e.g. github, wifi, bank). The vault locks after every command.
    """


@vault_grp.command(
    "init",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole vault init --vault ~/.blackhole/vault.db
""",
)
@click.option(
    "--vault",
    default=DEFAULT_VAULT,
    show_default=True,
    metavar="PATH",
    help="Where to create the vault file (created chmod 0600).",
)
def vault_init(vault):
    """Create a new empty vault. Asks for the master password twice."""
    p = Path(vault).expanduser()
    if p.exists():
        raise click.ClickException(f"vault already exists at {p} (delete it or pick --vault PATH)")
    m1 = _master("New master password: ")
    m2 = _master("Confirm: ")
    if m1 != m2:
        raise click.ClickException("passwords differ, try again")
    if not m1:
        raise click.ClickException("empty master password, try again")
    Vault.create(p, m1)
    console.print(f"[green]vault created[/] {p} (0600, argon2id + aes-gcm)")


@vault_grp.command(
    "set",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole vault set github --username alice
  blackhole vault set github --username alice --generate 24
  blackhole vault set wifi --passphrase 5
""",
)
@click.argument("service", metavar="SERVICE")
@click.option("--vault", default=DEFAULT_VAULT, show_default=True, metavar="PATH", help="Vault file to open.")
@click.option("--username", default="", metavar="NAME", help="Username or email to store alongside the secret.")
@click.option(
    "--generate",
    type=click.IntRange(8, 128),
    default=0,
    metavar="LEN",
    help="Generate a random password of LEN chars (8-128) instead of prompting.",
)
@click.option(
    "--passphrase",
    type=click.IntRange(3, 10),
    default=0,
    metavar="WORDS",
    help="Generate a passphrase of WORDS words (3-10) instead of prompting.",
)
def vault_set(service, vault, username, generate, passphrase):
    """Save (or overwrite) the entry for SERVICE.

    Without --generate/--passphrase you are prompted once for the entry
    password (hidden input).
    """
    v = _open_vault(vault)
    if generate:
        pw = generate_password(generate)
    elif passphrase:
        pw = generate_passphrase(passphrase)
    else:
        pw = _master("Entry password: ")
        if not pw:
            v.lock()
            raise click.ClickException("empty password, rerun with --generate LEN to make one")
    if not username:
        username = click.prompt("Username", default="")
    notes = click.prompt("Notes (optional)", default="")
    v.set(service, username, pw, notes)
    if generate or passphrase:
        console.print(f"[green]saved[/] {service}  generated secret: {pw}")
    else:
        console.print(f"[green]saved[/] {service}")
    v.lock()


@vault_grp.command(
    "get",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole vault get github --show
  blackhole vault get github
""",
)
@click.argument("service", metavar="SERVICE")
@click.option("--vault", default=DEFAULT_VAULT, show_default=True, metavar="PATH", help="Vault file to open.")
@click.option(
    "--show",
    is_flag=True,
    help="Print the secret to the terminal. Without it, blackhole tries the clipboard instead.",
)
def vault_get(service, vault, show):
    """Show or copy the entry for SERVICE.

    Default copies the password to the clipboard (cleared after ~30s);
    with --show it is printed, which is better for piping into scripts.
    """
    v = _open_vault(vault)
    e = v.get(service)
    if not e:
        v.lock()
        raise click.ClickException(f"no entry for '{service}' (see 'blackhole vault list')")
    if show:
        console.print(f"{e.service}  user={e.username}  pass={e.password}")
    else:
        try:
            import tkinter

            r = tkinter.Tk()
            r.withdraw()
            r.clipboard_clear()
            r.clipboard_append(e.password)
            r.update()
            console.print("[green]copied to clipboard[/] - clear it when you're done")
            r.after(30000, lambda: (r.clipboard_clear(), r.update(), r.destroy()))
        except Exception:
            console.print("[yellow]clipboard unavailable here; rerun with --show[/]")
    v.lock()


@vault_grp.command(
    "list",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole vault list --vault ~/backup.db
""",
)
@click.option("--vault", default=DEFAULT_VAULT, show_default=True, metavar="PATH", help="Vault file to open.")
def vault_list(vault):
    """List service names in the vault (usernames shown, passwords never)."""
    v = _open_vault(vault)
    rows = [(e.service, e.username, str(e.updated)) for s in v.list_services() for e in [v.get(s)] if e]
    t = Table("service", "username", "updated")
    for row in rows:
        t.add_row(*row)
    console.print(t)
    v.lock()


@vault_grp.command(
    "audit",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole vault audit
""",
)
@click.option("--vault", default=DEFAULT_VAULT, show_default=True, metavar="PATH", help="Vault file to open.")
def vault_audit(vault):
    """Score password health: reused, short (<12 chars), and stale (>1yr)."""
    v = _open_vault(vault)
    a = v.audit()
    console.print(f"Score: {a['score']}/100  entries={a['total']}")
    if a["reused"]:
        console.print(f"[red]reused passwords:[/] {a['reused']}")
    if a["weak"]:
        console.print(f"[yellow]weak (<12 chars):[/] {a['weak']}")
    if a["stale"]:
        console.print(f"[yellow]stale (>1y):[/] {a['stale']}")
    if a["score"] == 100:
        console.print("[green]all clear[/]")
    v.lock()


@vault_grp.command(
    "gen",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole vault gen --length 24
  blackhole vault gen --words 5
""",
)
@click.option("--length", default=20, show_default=True, help="Password length (8-128).")
@click.option("--words", default=0, metavar="N", help="Print a passphrase of N words (3-10) instead.")
def vault_gen(length, words):
    """Print a fresh secret without storing anything. Uses os-provided randomness."""
    try:
        console.print(generate_passphrase(words) if words else generate_password(length))
    except ValueError as e:
        raise click.ClickException(str(e)) from e


# shred
@main.group(
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole shred analyze photo.jpg
  blackhole shred clean photo.jpg
  blackhole shred verify photo.cleaned.jpg
""",
)
def shred_grp():
    """Strip metadata and delete files for good.

    Typical flow: analyze to see what's there, clean to write a
    *.cleaned copy, verify it passes, post the copy.
    """


@shred_grp.command(
    "analyze",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole shred analyze photo.jpg scan.png
""",
)
@click.argument("files", nargs=-1, required=True, metavar="FILE...", type=click.Path(exists=True))
def shred_analyze(files):
    """Show metadata score (0-100) and sensitive tags per FILE. Read-only."""
    for f in files:
        info = analyze_file(f)
        color = "green" if info["score"] >= 80 else ("yellow" if info["score"] >= 50 else "red")
        console.print(f"[bold {color}]{info['score']}/100[/] {f} tags={info.get('sensitive', [])}")


@shred_grp.command(
    "clean",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole shred clean photo.jpg
  blackhole shred clean *.jpg --out-dir ./clean --yes
""",
)
@click.argument("files", nargs=-1, required=True, metavar="FILE...", type=click.Path(exists=True))
@click.option("--out-dir", default=None, metavar="DIR", help="Write cleaned copies into DIR instead of next to originals.")
@click.option("--yes", is_flag=True, help="Skip the per-file confirmation prompt.")
def shred_clean(files, out_dir, yes):
    """Write cleaned copies (originals untouched) and verify each one."""
    for f in files:
        out = Path(out_dir) / (Path(f).stem + ".cleaned" + Path(f).suffix) if out_dir else None
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
        if not yes and not click.confirm(f"Clean {f} -> {out or 'auto'}?"):
            continue
        p = clean_file(f, out)
        ok, _ = verify_clean(p)
        console.print(f"[green]cleaned[/] {p} verify={'PASS' if ok else 'REMAINING-RISK'}")


@shred_grp.command(
    "verify",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole shred verify photo.cleaned.jpg; echo $?
""",
)
@click.argument("files", nargs=-1, required=True, metavar="FILE...", type=click.Path(exists=True))
def shred_verify(files):
    """Exit 0 if every FILE is clean, 1 otherwise. Built for scripts."""
    bad = 0
    for f in files:
        ok, info = verify_clean(f)
        console.print(f"{'PASS' if ok else 'FAIL'} {f} sensitive={info.get('sensitive', [])}")
        bad += not ok
    sys.exit(1 if bad else 0)


@shred_grp.command(
    "shred",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole shred shred secret.txt --passes 7 --yes
""",
)
@click.argument("files", nargs=-1, required=True, metavar="FILE...", type=click.Path(exists=True))
@click.option(
    "--passes",
    type=click.Choice(["1", "3", "7"]),
    default="3",
    show_default=True,
    help="Overwrite passes: 1 is fast, 3 is the default, 7 is paranoid.",
)
@click.option("--yes", is_flag=True, help="Skip the irreversible-action confirmation.")
def shred_shred(files, passes, yes):
    """Overwrite, rename, and delete each FILE. This cannot be undone."""
    for f in files:
        if not yes and not click.confirm(f"Securely delete {f} ({passes} passes)? This is irreversible"):
            continue
        shred_file(f, int(passes))
        console.print(f"[red]shredded[/] {f}")


# bundle
@main.group(
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole bundle create ./photos ./photos.bhb
  blackhole bundle extract ./photos.bhb ./restored --password
""",
)
def bundle_grp():
    """Pack directories into encrypted .bhb files.

    Password mode derives the key from your password (Argon2id).
    Keyfile mode (--no-password) writes OUT.key, and you need both
    files to extract. See 'blackhole bundle create -h'.
    """


@bundle_grp.command(
    "create",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole bundle create ./photos ./photos.bhb
  blackhole bundle create ./photos ./photos.bhb --password
  blackhole bundle create ./photos ./photos.bhb --no-password
""",
)
@click.argument("src", metavar="SRC_DIR", type=click.Path(exists=True, file_okay=False))
@click.argument("out", metavar="OUT_FILE")
@click.option("--password", is_flag=True, help="Prompt for a bundle password (same as the default).")
@click.option(
    "--no-password",
    is_flag=True,
    help="Keyfile mode: random key, writes OUT_FILE.key (0600). Keep it safe, it is required to extract.",
)
def bundle_create(src, out, password, no_password):
    """Archive SRC_DIR into encrypted OUT_FILE (.bhb).

    With no flags you are prompted for a password. Filenames and
    contents are all inside the encrypted blob.
    """
    if password and no_password:
        raise click.UsageError("use either --password or --no-password, not both")
    pw = None
    if not no_password:
        p1 = _master("Bundle password: ")
        p2 = _master("Confirm: ")
        if p1 != p2:
            raise click.ClickException("passwords differ, try again")
        if not p1:
            raise click.ClickException("empty password, rerun with --no-password for keyfile mode")
        pw = p1
    meta = create_bundle(src, out, pw)
    console.print(f"[green]bundle created[/] {meta['bundle']} ({meta['bytes_out']}B from {meta['bytes_in']}B tar, {meta['kdf']})")
    if meta.get("keyfile"):
        console.print(f"[yellow]KEEP SAFE:[/] keyfile {meta['keyfile']} (0600) - needed to extract")


@bundle_grp.command(
    "extract",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole bundle extract ./photos.bhb ./restored --password
  blackhole bundle extract ./photos.bhb ./restored --keyfile ./photos.bhb.key
""",
)
@click.argument("bundle", metavar="BUNDLE_FILE")
@click.argument("dest", metavar="DEST_DIR")
@click.option("--password", is_flag=True, help="Prompt for the bundle password (password-mode bundles).")
@click.option("--keyfile", default=None, metavar="PATH", help="Key file for keyfile-mode bundles (defaults to BUNDLE_FILE.key).")
def bundle_extract(bundle, dest, password, keyfile):
    """Decrypt BUNDLE_FILE into DEST_DIR. Wrong password/key just refuses to open."""
    pw = _master("Bundle password: ") if password else None
    try:
        names = extract_bundle(bundle, dest, pw, keyfile)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    console.print(f"[green]extracted {len(names)} files[/] -> {dest}")


# intake
@main.command(
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole intake "http://evil.tk/login" ./photo.jpg
""",
)
@click.argument("url", metavar="URL")
@click.argument("file", metavar="FILE", type=click.Path(exists=True))
def intake_cmd(url, file):
    """Score a link and check a file in one go. For triaging a DM with an attachment."""
    info, feats = analyze_url(url)
    score, verdict, conf, fired = score_features(feats)
    ok, minfo = verify_clean(file)
    console.print(format_text(info, score, verdict, conf, fired))
    console.print(f"File {file}: {'CLEAN' if ok else 'HAS-METADATA'} score={minfo['score']} sensitive={minfo.get('sensitive', [])}")


# upgrade
@main.command(
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole upgrade
  blackhole upgrade --check
""",
)
@click.option(
    "--check",
    is_flag=True,
    help="Only compare installed vs latest version, don't install anything.",
)
def upgrade_cmd(check):
    """Upgrade to the latest release from PyPI (uses pip under the hood).

    Needs network for this one command; everything else stays offline.
    If this python has no pip, reinstall with the curl installer in the README.
    """
    current = _installed_version()
    try:
        latest = _latest_pypi_version()
    except Exception:
        raise click.ClickException("could not reach PyPI, check your connection and try again") from None
    if current == latest:
        console.print(f"[green]already on the latest ({current})[/]")
        return
    if check:
        console.print(f"installed: {current}  latest: {latest}  (run without --check to upgrade)")
        return
    console.print(f"upgrading {current} -> {latest} ...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "blackhole-sec"], check=True)
    except FileNotFoundError:
        raise click.ClickException("no pip in this python; reinstall with the curl installer (see README)") from None
    except subprocess.CalledProcessError as e:
        raise click.ClickException(f"pip failed with exit {e.returncode}") from e
    console.print(f"[green]upgraded to {latest}[/] (open a new shell if the old version still shows)")
