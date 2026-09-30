# Bundles (.bhb)

Two flavors. With a password, `.bhb` packs a directory to tar.gz and
encrypts the whole thing, names and all - only blackhole opens it.
With `--no-password` it packs plain: no encryption, opens with no
flags, same as a zip with no password. Pick per bundle.

## Creating one

```bash
# password mode (prompts twice)
blackhole bundle create ./photos ./photos.bhb

# same, explicit flag
blackhole bundle create ./photos ./photos.bhb --password

# plain mode: no password, no extra files, anyone can open it
blackhole bundle create ./photos ./photos.bhb --no-password
```

## Opening one

```bash
blackhole bundle extract ./photos.bhb ./restored --password
blackhole bundle extract ./photos.bhb ./restored   # plain bundles need nothing
```

A wrong password or a tampered file just refuses to open. There is no
partial extract. Bundles made back when `--no-password` wrote a `.key`
file still open with `--keyfile`, nothing else changed for them.

## Peeking without unpacking

```bash
blackhole bundle list ./photos.bhb --password
blackhole bundle verify ./photos.bhb --password; echo $?
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
| ZipCrypto breaks in minutes | Argon2id into AES-256-GCM, no legacy modes |
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

Implementation lives in `src/blackhole_sec/bundle/__init__.py`. It is
short enough to read in one sitting, which is intentional.

## Tips

- Bundle the cleaned copies (`*.cleaned.jpg`), not the originals, when
  you share photos with other people.
- `.bhb` files are chmod 0600 on creation. Copy them normally, perms do
  not survive every filesystem, so check after moving.
