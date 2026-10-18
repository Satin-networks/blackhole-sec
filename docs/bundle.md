# Bundles (.bhb)

Two flavors. With a password, `.bhb` packs a directory to tar.gz and
encrypts the whole thing, names and all - only blackhole opens it.
With `--no-password` it packs plain: no encryption, opens with no
flags, same as a zip with no password. Pick per bundle.

Password mode is deliberately expensive to open - that is the point.
Every guess an attacker makes costs the full Argon2id work below, per
try. Unlocking in a terminal takes a few seconds; that is the trade.

| `--kdf` preset | memory | passes | work vs the old default |
|---|---|---|---|
| `light` | 64 MiB | 3 | 1x (what 0.2.x used) |
| `hard` (default) | 1 GiB | 8 | ~42x |
| `paranoid` | 2 GiB | 12 | ~128x |

## Creating one

```bash
# password mode (prompts twice)
blackhole bundle create ./photos ./photos.bhb

# let blackhole make a strong password and print it once
blackhole bundle create ./photos ./photos.bhb --generate

# the heaviest settings (wants a few GiB of RAM free)
blackhole bundle create ./photos ./photos.bhb --kdf paranoid

# plain mode: no password, no extra files, anyone can open it
blackhole bundle create ./photos ./photos.bhb --no-password
```

Weak passwords are rejected before anything is written: shorter than
12 characters, fewer than three character classes under 16, the usual
top-list classics, repeated runs and keyboard walks. `--generate`
sidesteps all of that with a 24-character random password. Store it
before you close the terminal.

## Opening one

```bash
blackhole bundle extract ./photos.bhb ./restored
```

Password-mode bundles prompt for the password themselves; plain
bundles need nothing. A wrong password re-prompts, up to three tries,
then gives up cleanly. A tampered file refuses to open. There is no
partial extract. Bundles made back when `--no-password` wrote a `.key`
file still open with `--keyfile`, nothing else changed for them.

## Peeking without unpacking

```bash
blackhole bundle list ./photos.bhb
blackhole bundle verify ./photos.bhb; echo $?
```

`list` prints every file with its size. `verify` only checks the
password/key and authenticity: exit 0 opens, 1 does not.

## Root-owned files

`create` never deletes or moves your source; it only reads it. If a
bundle (or its directory) belongs to root, run the same command with
sudo - blackhole says so in the error. Files created that way are
root-owned too, including anything you extract.

## How it compares to zip

| Problem with zip | What .bhb password mode does |
|---|---|
| ZipCrypto breaks in minutes | Argon2id (heavy, per-bundle params) into AES-256-GCM |
| Weak passwords get guessed in minutes | Creation rejects them; `--generate` makes real ones |
| Filenames visible without the password | Names are inside the encrypted blob |
| ZipSlip (`../../evil`) on extract | Absolute paths, `..`, symlinks and devices are skipped |
| Every website unzips it | Only blackhole reads `.bhb` |

## Format v1

Big-endian, one header, one payload:

```
BHB1 | kdf_id | t,m,p | salt | [nonce (12)] | ct_len (u64) | ct
```

`kdf_id` 1 (password) and 0 (old keyfile) carry a nonce and `ct` is
AES-GCM with the header as AAD. `kdf_id` 2 (plain) has no nonce and
`ct` is the tar.gz as-is.

The `t,m,p` numbers are per bundle: the reader derives with whatever
the header says, so files written by older versions keep opening with
their original, lighter numbers. Absurd values are rejected before a
single byte is hashed, so a crafted file cannot ask your machine for
more RAM than it has.

Implementation lives in `src/blackhole_sec/bundle/__init__.py`. It is
short enough to read in one sitting, which is intentional.

## Tips

- Bundle the cleaned copies (`*.cleaned.jpg`), not the originals, when
  you share photos with other people.
- `.bhb` files are chmod 0600 on creation. Copy them normally, perms do
  not survive every filesystem, so check after moving.
- Write the password down somewhere real, or keep it in the vault. There
  is no recovery, and with these numbers there will never be one.
