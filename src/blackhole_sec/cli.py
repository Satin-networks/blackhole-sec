"""blackhole command line. check / vault / shred / bundle / intake."""
from __future__ import annotations

import csv
import getpass
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

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


def _master(prompt: str = "Master password: ") -> str:
    return getpass.getpass(prompt)


@click.group()
@click.version_option("0.1.0", prog_name="blackhole-sec")
def main() -> None:
    """Offline opsec toolkit. Nothing leaves your machine."""


# check
@main.command("check")
@click.argument("urls", nargs=-1)
@click.option("--file", "-f", "file_", type=click.Path(exists=True), help="File with one URL per line (or - for stdin).")
@click.option("--json", "as_json", is_flag=True, help="JSON output.")
@click.option("--csv", "as_csv", is_flag=True, help="CSV summary output.")
@click.option("--explain", is_flag=True, help="Show per-signal explanations (default in text mode).")
@click.option("--threshold", type=int, default=50, help="Exit-code threshold for MALICIOUS.")
def check_cmd(urls, file_, as_json, as_csv, explain, threshold):
    """Score URLs without fetching them."""
    targets: list[str] = list(urls)
    if file_:
        src = sys.stdin.read().splitlines() if file_ == "-" else Path(file_).read_text().splitlines()
        targets += [l.strip() for l in src if l.strip()]
    if not targets:
        raise click.UsageError("give at least one URL or --file")
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
                    console.print(f"       [dim]{feat.explanation} [{feat.mitre}][/]")
            console.print(f"  [dim]MITRE: {', '.join(mitre_for([x.name for x in f])) or 'none'}[/]")
    worst = max(s for _, s, _, _, _ in results)
    sys.exit(2 if worst >= threshold else 0)


# vault
@main.group("vault")
def vault_grp():
    """Password vault on your own disk."""


@vault_grp.command("init")
@click.option("--vault", default=DEFAULT_VAULT, help="Vault file path.")
def vault_init(vault):
    p = Path(vault).expanduser()
    if p.exists():
        raise click.ClickException("vault already exists")
    m1 = _master("New master password: ")
    m2 = _master("Confirm: ")
    if m1 != m2:
        raise click.ClickException("passwords differ")
    Vault.create(p, m1)
    console.print(f"[green]vault created[/] {p} (0600, argon2id+aes-gcm)")


@vault_grp.command("set")
@click.argument("service")
@click.option("--vault", default=DEFAULT_VAULT)
@click.option("--username", default="", help="Username/email.")
@click.option("--generate", type=int, default=0, help="Generate password of this length.")
@click.option("--passphrase", type=int, default=0, help="Generate passphrase with N words.")
def vault_set(service, vault, username, generate, passphrase):
    v = Vault(Path(vault).expanduser())
    try:
        v.unlock(_master())
    except VaultLocked as e:
        raise click.ClickException(str(e))
    pw = ""
    if generate:
        pw = generate_password(generate)
    elif passphrase:
        pw = generate_passphrase(passphrase)
    else:
        pw = _master("Entry password (empty=keep prompt hidden, will ask): ") or getpass.getpass("Entry password: ")
    notes = click.prompt("Notes (optional)", default="")
    v.set(service, username or click.prompt("Username", default=""), pw, notes)
    console.print(f"[green]saved[/] {service}")
    v.lock()


@vault_grp.command("get")
@click.argument("service")
@click.option("--vault", default=DEFAULT_VAULT)
@click.option("--show", is_flag=True, help="Print secret (otherwise copies if possible).")
def vault_get(service, vault, show):
    v = Vault(Path(vault).expanduser())
    try:
        v.unlock(_master())
    except VaultLocked as e:
        raise click.ClickException(str(e))
    e = v.get(service)
    if not e:
        raise click.ClickException("not found")
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
            console.print("[yellow]clipboard unavailable; use --show[/]")
    v.lock()


@vault_grp.command("list")
@click.option("--vault", default=DEFAULT_VAULT)
def vault_list(vault):
    v = Vault(Path(vault).expanduser())
    try:
        v.unlock(_master())
    except VaultLocked as e:
        raise click.ClickException(str(e))
    t = Table("service", "username", "updated")
    for s in v.list_services():
        e = v.get(s)
        assert e
        t.add_row(e.service, e.username, str(e.updated))
    console.print(t)
    v.lock()


@vault_grp.command("audit")
@click.option("--vault", default=DEFAULT_VAULT)
def vault_audit(vault):
    v = Vault(Path(vault).expanduser())
    try:
        v.unlock(_master())
    except VaultLocked as e:
        raise click.ClickException(str(e))
    a = v.audit()
    console.print(f"Score: {a['score']}/100  entries={a['total']}")
    if a["reused"]:
        console.print(f"[red]reused passwords:[/] {a['reused']}")
    if a["weak"]:
        console.print(f"[yellow]weak (<12 chars):[/] {a['weak']}")
    if a["stale"]:
        console.print(f"[yellow]stale (>1y):[/] {a['stale']}")
    v.lock()


@vault_grp.command("gen")
@click.option("--length", default=20, help="Password length.")
@click.option("--words", default=0, help="Passphrase words instead (e.g. --words 5).")
def vault_gen(length, words):
    console.print(generate_passphrase(words) if words else generate_password(length))


# shred
@main.group("shred")
def shred_grp():
    """Strip metadata and delete files for good."""


@shred_grp.command("analyze")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
def shred_analyze(files):
    for f in files:
        info = analyze_file(f)
        color = "green" if info["score"] >= 80 else ("yellow" if info["score"] >= 50 else "red")
        console.print(f"[bold {color}]{info['score']}/100[/] {f} tags={info.get('sensitive', [])}")


@shred_grp.command("clean")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--out-dir", default=None, help="Output directory.")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
def shred_clean(files, out_dir, yes):
    for f in files:
        out = Path(out_dir) / (Path(f).stem + ".cleaned" + Path(f).suffix) if out_dir else None
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
        if not yes and not click.confirm(f"Clean {f} -> {out or 'auto'} (non-destructive)?"):
            continue
        p = clean_file(f, out)
        ok, _ = verify_clean(p)
        console.print(f"[green]cleaned[/] {p} verify={'PASS' if ok else 'REMAINING-RISK'}")


@shred_grp.command("verify")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
def shred_verify(files):
    bad = 0
    for f in files:
        ok, info = verify_clean(f)
        console.print(f"{'PASS' if ok else 'FAIL'} {f} sensitive={info.get('sensitive', [])}")
        bad += (not ok)
    sys.exit(1 if bad else 0)


@shred_grp.command("shred")
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--passes", type=click.Choice(["1", "3", "7"]), default="3")
@click.option("--yes", is_flag=True, help="Skip confirmation.")
def shred_shred(files, passes, yes):
    for f in files:
        if not yes and not click.confirm(f"Securely delete {f} ({passes} passes)? This is irreversible"):
            continue
        shred_file(f, int(passes))
        console.print(f"[red]shredded[/] {f}")


# bundle
@main.group("bundle")
def bundle_grp():
    """Pack directories into encrypted .bhb files."""


@bundle_grp.command("create")
@click.argument("src", type=click.Path(exists=True, file_okay=False))
@click.argument("out")
@click.option("--password", is_flag=True, help="Prompt for password (else keyfile mode).")
@click.option("--no-password", is_flag=True, help="Keyfile mode: writes OUT.key (0600).")
def bundle_create(src, out, password, no_password):
    pw = None
    if password:
        p1 = _master("Bundle password: ")
        p2 = _master("Confirm: ")
        if p1 != p2:
            raise click.ClickException("passwords differ")
        pw = p1
    elif not no_password:
        pw = _master("Bundle password: ")
    meta = create_bundle(src, out, pw)
    console.print(f"[green]bundle created[/] {meta['bundle']} ({meta['bytes_out']}B from {meta['bytes_in']}B tar, {meta['kdf']})")
    if meta.get("keyfile"):
        console.print(f"[yellow]KEEP SAFE:[/] keyfile {meta['keyfile']} (0600) - needed to extract")


@bundle_grp.command("extract")
@click.argument("bundle")
@click.argument("dest")
@click.option("--password", is_flag=True, help="Prompt for password.")
@click.option("--keyfile", default=None, help="Path to .key file (keyfile mode).")
def bundle_extract(bundle, dest, password, keyfile):
    pw = _master("Bundle password: ") if password else None
    names = extract_bundle(bundle, dest, pw, keyfile)
    console.print(f"[green]extracted {len(names)} files[/] -> {dest}")


# intake
@main.command("intake")
@click.argument("url")
@click.argument("file", type=click.Path(exists=True))
def intake_cmd(url, file):
    """Score a link and check a file in one go."""
    info, feats = analyze_url(url)
    score, verdict, conf, fired = score_features(feats)
    ok, minfo = verify_clean(file)
    console.print(format_text(info, score, verdict, conf, fired))
    console.print(f"File {file}: {'CLEAN' if ok else 'HAS-METADATA'} score={minfo['score']} sensitive={minfo.get('sensitive', [])}")
