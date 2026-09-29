# Bundles (.bhb)

Zip passwords crack fast, and even AES zip leaves filenames sitting in the
clear for anyone to read. `.bhb` packs a directory to tar.gz and encrypts
the whole thing, names and all. Only blackhole can open it, which is the
whole point.

## Creating one

```bash
# password mode (prompts twice)
blackhole bundle create ./photos ./photos.bhb

# same, explicit flag
blackhole bundle create ./photos ./photos.bhb --password

# keyfile mode: no password, writes photos.bhb.key (0600) next to it.
# You need both files to extract.
blackhole bundle create ./photos ./photos.bhb --no-password
```

## Opening one

```bash
blackhole bundle extract ./photos.bhb ./restored --password
blackhole bundle extract ./photos.bhb ./restored --keyfile ./photos.bhb.key
```

A wrong password, a wrong keyfile, or a tampered file just refuses to
open. There is no partial extract.

## How it compares to zip

| Problem with zip | What .bhb does |
|---|---|
| ZipCrypto breaks in minutes | Argon2id into AES-256-GCM, no legacy modes |
| Filenames visible without the password | Names are inside the encrypted blob |
| ZipSlip (`../../evil`) on extract | Absolute paths, `..`, symlinks and devices are skipped |
| Every website unzips it | Only blackhole reads `.bhb` |

## Format v1

Big-endian, one header, one ciphertext:

```
BHB1 | kdf_id | t,m,p | salt | nonce (12) | ct_len (u64) | ct
```

`ct` holds the tar.gz bytes. The header is passed as AAD so any edit to
it fails decryption. `kdf_id` 1 means Argon2id with the stored params,
0 means keyfile mode with a random 32-byte key.

Implementation lives in `src/blackhole_sec/bundle/__init__.py`. It is
short enough to read in one sitting, which is intentional.

## Tips

- Keep the `.key` file like a password: USB stick, vault, paper. Losing
  both the bundle password and the keyfile means losing the data.
- Bundle the cleaned copies (`*.cleaned.jpg`), not the originals, when
  you share photos with other people.
- `.bhb` files are chmod 0600 on creation. Copy them normally, perms do
  not survive every filesystem, so check after moving.
