"""blackhole command line. check / vault / shred / bundle / intake."""
from __future__ import annotations

import csv
import errno
import getpass
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from .bundle import create_bundle, extract_bundle, list_bundle, read_bundle
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


class SuggestGroup(click.Group):
    """A group that points at the right subcommand on typos and misplaced flags."""

    def parse_args(self, ctx, args):
        try:
            return super().parse_args(ctx, args)
        except click.NoSuchOption as e:
            owner = self._find_flag_owner(e.option_name)
            if owner:
                base = e.message.rstrip(".")
                e.message = f"{base}. Did you mean '{ctx.command_path} {owner} {e.option_name} ...'?"
            raise

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError as e:
            if args:
                import difflib

                guess = difflib.get_close_matches(args[0], list(self.commands), n=1)
                if guess:
                    raise click.UsageError(
                        f"No such command '{args[0]}'. Did you mean '{guess[0]}'?"
                    ) from e
            raise

    def _find_flag_owner(self, option_name: str) -> str | None:
        for sub, cmd in sorted(self.commands.items()):
            for p in getattr(cmd, "params", []):
                if isinstance(p, click.Option) and option_name in p.opts:
                    return sub
        return None


def _master(prompt: str = "Master password: ") -> str:
    return getpass.getpass(prompt)


def _open_vault(path: str) -> Vault:
    p = Path(path).expanduser()
    if not p.exists():
        raise click.ClickException(
            f"no vault at {p}. Run 'blackhole vault init' first (or fix --vault PATH)."
        )
    v = Vault(p)
    try:
        with _fs(f"could not open vault {p}"):
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


def _score_bar(score: int, width: int = 20) -> str:
    filled = max(0, min(width, round(score / 100 * width)))
    return "#" * filled + "-" * (width - filled)


def _sev_color(weight: int) -> str:
    if weight >= 15:
        return "red"
    if weight >= 8:
        return "yellow"
    return "dim"


def _score_color(score: int) -> str:
    if score >= 80:
        return "red"
    if score >= 50:
        return "yellow"
    return "green"


def _disable_color(ctx, param, value):
    if value:
        console.no_color = True
    return value


@contextmanager
def _fs(action: str):
    """Turn filesystem failures into one-line errors instead of tracebacks."""
    try:
        yield
    except OSError as e:
        raise _friendly(action, e) from e


def _friendly(action: str, e: OSError) -> click.ClickException:
    reason = {
        errno.EACCES: "permission denied",
        errno.EPERM: "operation not permitted",
        errno.ENOENT: "no such file or directory",
        errno.ENOSPC: "disk full",
        errno.EROFS: "read-only filesystem",
        errno.ENAMETOOLONG: "path too long",
    }.get(e.errno or 0, (e.strerror or "filesystem error").lower())
    where = f" for {e.filename}" if e.filename else ""
    fix = "Check ownership and free space, or pick another path."
    if (e.errno or 0) == errno.ENOENT and "vault" in action:
        fix = "Run 'blackhole vault init' first, or point --vault at the right file."
    if (e.errno or 0) in (errno.EACCES, errno.EPERM) and _owned_by_root(e.filename):
        fix = "That file belongs to root. Retry the same command with sudo."
    return click.ClickException(f"{action} failed{where}: {reason}. {fix}")


def _owned_by_root(filename: str | None) -> bool:
    if not filename:
        return False
    try:
        return os.stat(filename).st_uid == 0 and os.geteuid() != 0
    except OSError:
        return False


def _need_writable_dir(path: str | Path, what: str) -> None:
    """Fail fast with a clear message before doing expensive work."""
    parent = Path(path).expanduser().parent
    if str(parent) in ("", "."):
        parent = Path(".")
    if not parent.exists():
        raise click.ClickException(f"cannot write {what} to {path}: directory {parent} does not exist.")
    if not os.access(parent, os.W_OK | os.X_OK):
        raise click.ClickException(
            f"cannot write {what} to {path}: permission denied for {parent}. "
            "Pick a directory you own, e.g. ~/backups."
        )


@click.group(cls=SuggestGroup, context_settings=HELP_NAMES, epilog=MAIN_EPILOG)
@click.version_option(_installed_version(), prog_name="blackhole-sec")
@click.option(
    "--no-color",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=_disable_color,
    help="Plain output, no ANSI colors. Also honored: NO_COLOR env, pipes.",
)
def main() -> None:
    """Offline opsec toolkit. Nothing leaves your machine."""


# check
@main.command(
    "check",
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
        if file_ == "-":
            src = sys.stdin.read().splitlines()
        else:
            with _fs("could not read URL list"):
                src = Path(file_).read_text().splitlines()
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
            bar = _score_bar(s)
            console.print(f"[bold {color}]{v} {s}/100 ({c})[/] [{color}]{bar}[/] {escape(defang(i['normalized']))}", highlight=False)
            for feat in f:
                fc = _sev_color(feat.weight)
                console.print(f"  [{fc}]+{feat.weight:2d} {feat.name}[/]: {escape(feat.evidence)}", highlight=False)
                if explain:
                    console.print(f"       [dim]{escape(feat.explanation)} [{feat.mitre or 'no MITRE tag'}][/]", highlight=False)
            console.print(f"  [dim]MITRE: {', '.join(mitre_for([x.name for x in f])) or 'none'}[/]", highlight=False)
    worst = max(s for _, s, _, _, _ in results)
    sys.exit(2 if worst >= threshold else 0)


# vault
@main.group(
    "vault",
    cls=SuggestGroup,
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
    with _fs(f"could not create vault {p}"):
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
    if generate and passphrase:
        raise click.UsageError("use either --generate or --passphrase, not both")
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
    with _fs(f"could not save entry in {v.path}"):
        v.set(service, username, pw, notes)
    if generate or passphrase:
        console.print(f"[green]saved[/] {service}  generated secret: {pw}", markup=False, highlight=False)
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

    Default copies the password to the clipboard (it stays until you
    overwrite it, so clear it when done); with --show it is printed,
    which is better for piping into scripts.
    """
    v = _open_vault(vault)
    e = v.get(service)
    if not e:
        v.lock()
        raise click.ClickException(f"no entry for '{service}' (see 'blackhole vault list')")
    if show:
        console.print(f"{e.service}  user={e.username}  pass={e.password}", markup=False, highlight=False)
    else:
        if _to_clipboard(e.password):
            console.print("[green]copied to clipboard[/] - overwrite or clear it when done")
        else:
            console.print("[yellow]clipboard unavailable here; rerun with --show[/]")
    v.lock()


def _to_clipboard(text: str) -> bool:
    """Copy text so it survives this process exiting. Best effort."""
    import shutil

    tools = (
        ("wl-copy", ["wl-copy"]),
        ("xclip", ["xclip", "-selection", "clipboard"]),
        ("xsel", ["xsel", "--clipboard", "--input"]),
    )
    for name, args in tools:
        if shutil.which(name):
            try:
                subprocess.run(args, input=text.encode(), check=True, timeout=10)
                return True
            except (OSError, subprocess.SubprocessError):
                continue
    try:
        import tkinter

        r = tkinter.Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(text)
        r.update()
        r.destroy()
        return True
    except Exception:
        return False


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
    t = Table("service", "username", "updated", title=f"vault: {v.path}", show_lines=False)
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
    color = "green" if a["score"] >= 90 else ("yellow" if a["score"] >= 60 else "red")
    console.print(f"[{color}]Score: {a['score']}/100  entries={a['total']}[/] [{color}]{_score_bar(a['score'])}[/]")
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
        secret = generate_passphrase(words) if words else generate_password(length)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    console.print(secret, markup=False, highlight=False)


@vault_grp.command(
    "rm",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole vault rm old-forum --yes
""",
)
@click.argument("service", metavar="SERVICE")
@click.option("--vault", default=DEFAULT_VAULT, show_default=True, metavar="PATH", help="Vault file to open.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def vault_rm(service, vault, yes):
    """Delete the entry for SERVICE. This cannot be undone."""
    v = _open_vault(vault)
    if v.get(service) is None:
        v.lock()
        raise click.ClickException(f"no entry for '{service}' (see 'blackhole vault list')")
    if not yes and not click.confirm(f"Delete '{service}'?"):
        v.lock()
        return
    with _fs(f"could not update vault {v.path}"):
        v.remove(service)
    console.print(f"[red]deleted[/] {service}")
    v.lock()


@vault_grp.command(
    "passwd",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole vault passwd
""",
)
@click.option("--vault", default=DEFAULT_VAULT, show_default=True, metavar="PATH", help="Vault file to open.")
def vault_passwd(vault):
    """Change the master password. Every entry is re-encrypted under the new one."""
    v = _open_vault(vault)
    m1 = _master("New master password: ")
    m2 = _master("Confirm: ")
    if m1 != m2:
        v.lock()
        raise click.ClickException("passwords differ, try again")
    if not m1:
        v.lock()
        raise click.ClickException("empty master password, try again")
    with _fs(f"could not update vault {v.path}"):
        v.change_master(m1)
    console.print("[green]master password changed[/]")
    v.lock()


# shred
@main.group(
    "shred",
    cls=SuggestGroup,
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
        with _fs(f"could not read {f}"):
            info = analyze_file(f)
        color = _score_color(info["score"])
        bar = _score_bar(info["score"])
        console.print(f"[bold {color}]{info['score']}/100[/] [{color}]{bar}[/] {f} tags={info.get('sensitive', [])}", highlight=False)


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
            with _fs(f"could not prepare output directory for {f}"):
                out.parent.mkdir(parents=True, exist_ok=True)
        if not yes and not click.confirm(f"Clean {f} -> {out or 'auto'}?"):
            continue
        with _fs(f"could not clean {f}"):
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
        with _fs(f"could not read {f}"):
            ok, info = verify_clean(f)
        mark = "[green]PASS[/]" if ok else "[red]FAIL[/]"
        console.print(f"{mark} {f} sensitive={info.get('sensitive', [])}")
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
        with _fs(f"could not shred {f}"):
            shred_file(f, int(passes))
        console.print(f"[red]shredded[/] {f}")


# bundle
@main.group(
    "bundle",
    cls=SuggestGroup,
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
    _need_writable_dir(out, "bundle")
    pw = None
    if not no_password:
        p1 = _master("Bundle password: ")
        p2 = _master("Confirm: ")
        if p1 != p2:
            raise click.ClickException("passwords differ, try again")
        if not p1:
            raise click.ClickException("empty password, rerun with --no-password for keyfile mode")
        pw = p1
    with _fs(f"could not create bundle {out}"):
        meta = create_bundle(src, out, pw)
    console.print(f"[green]bundle created[/] {meta['bundle']} ({meta['bytes_out']}B from {meta['bytes_in']}B tar, {meta['kdf']})")
    console.print(f"[dim]source left untouched: {src}[/]")
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
        with _fs(f"could not extract {bundle}"):
            names = extract_bundle(bundle, dest, pw, keyfile)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    console.print(f"[green]extracted {len(names)} files[/] -> {dest}")


def _bundle_secret(password: bool, keyfile: str | None) -> tuple[str | None, str | None]:
    if password and keyfile:
        raise click.UsageError("use either --password or --keyfile, not both")
    return (_master("Bundle password: ") if password else None), keyfile


@bundle_grp.command(
    "list",
    context_settings=HELP_NAMES,
    epilog="""\b
Examples:
  blackhole bundle list ./photos.bhb --password
  blackhole bundle list ./photos.bhb
""",
)
@click.argument("bundle", metavar="BUNDLE_FILE")
@click.option("--password", is_flag=True, help="Prompt for the bundle password (password-mode bundles).")
@click.option("--keyfile", default=None, metavar="PATH", help="Key file for keyfile-mode bundles (defaults to BUNDLE_FILE.key).")
def bundle_list(bundle, password, keyfile):
    """Show what's inside BUNDLE_FILE without extracting anything."""
    pw, kf = _bundle_secret(password, keyfile)
    try:
        with _fs(f"could not read {bundle}"):
            entries = list_bundle(bundle, pw, kf)
    except ValueError as e:
        raise click.ClickException(str(e)) from e
    t = Table("path", "bytes", title=f"bundle: {bundle}")
    total = 0
    for name, size in entries:
        t.add_row(name, str(size))
        total += size
    console.print(t)
    console.print(f"[dim]{len(entries)} files, {total} bytes uncompressed[/]")


@bundle_grp.command(
    "verify",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole bundle verify ./photos.bhb --password; echo $?
""",
)
@click.argument("bundle", metavar="BUNDLE_FILE")
@click.option("--password", is_flag=True, help="Prompt for the bundle password (password-mode bundles).")
@click.option("--keyfile", default=None, metavar="PATH", help="Key file for keyfile-mode bundles (defaults to BUNDLE_FILE.key).")
def bundle_verify(bundle, password, keyfile):
    """Check a bundle opens with this password/key. Exit 0 yes, 1 no."""
    pw, kf = _bundle_secret(password, keyfile)
    try:
        with _fs(f"could not read {bundle}"):
            data = read_bundle(bundle, pw, kf)
    except ValueError as e:
        console.print(f"[red]FAIL[/] {bundle}: {e}")
        sys.exit(1)
    console.print(f"[green]OK[/] {bundle} ({len(data)} bytes of tar.gz, auth passed)")


# intake
@main.command(
    "intake",
    context_settings=HELP_NAMES,
    epilog="""\b
Example:
  blackhole intake "http://evil.tk/login" ./photo.jpg
  blackhole intake "http://evil.tk/login" ./photo.jpg --json
""",
)
@click.argument("url", metavar="URL")
@click.argument("file", metavar="FILE", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Print the link verdict and file verdict as one JSON object.")
def intake_cmd(url, file, as_json):
    """Score a link and check a file in one go. For triaging a DM with an attachment."""
    info, feats = analyze_url(url)
    score, verdict, conf, fired = score_features(feats)
    with _fs(f"could not read {file}"):
        ok, minfo = verify_clean(file)
    if as_json:
        click.echo(json.dumps({
            "url": to_dict(info, score, verdict, conf, fired),
            "file": {"file": str(file), "clean": ok, "score": minfo["score"],
                     "sensitive": minfo.get("sensitive", [])},
        }, indent=2))
        return
    console.print(format_text(info, score, verdict, conf, fired))
    mark = "[green]CLEAN[/]" if ok else "[yellow]HAS-METADATA[/]"
    console.print(f"File {file}: {mark} score={minfo['score']} sensitive={minfo.get('sensitive', [])}")


# upgrade
@main.command(
    "upgrade",
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
