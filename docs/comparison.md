# Compared to age and 7-Zip

Both are good, both are older, and each beats this one somewhere. The
honest table first.

| | blackhole-sec (.bhb) | age | 7-Zip (.7z) |
|---|---|---|---|
| Cost of one password guess | Argon2id, 1 GiB x 8 by default, carried per bundle | scrypt, ~256 MiB by default (`-W` raises it) | iterated SHA-256, memory-light, count fixed by the app |
| Encryption | AES-256-GCM, header authenticated | ChaCha20-Poly1305 | AES-256-CBC + HMAC-SHA256 |
| Second factor | optional keyfile: password + file both | no | no |
| Directories | built in (a tar.gz inside the blob) | no, pipe a tar through it | yes |
| Filenames | inside the ciphertext, always | only if you tar before encrypting | visible unless `-mhe=on` |
| Weak passwords | refused at creation | accepted | accepted |
| Opens elsewhere | blackhole only | any age implementation | just about anywhere |
| Compression | gzip | none | LZMA2, much better |

## Where they win

age has a written spec and independent implementations that agree on
the bytes, plus security review work this project has not had. If
interop matters, or you want a design with a name behind it, use age.

7-Zip is everywhere, has a GUI, and compresses far better. Its AES
layer is fine; the difference is that testing guesses against a .7z
is cheap in memory, so GPUs and dedicated rigs chew through them
faster than they chew through a memory-hard KDF at similar wall-clock
settings. That is the whole reason for Argon2id here.

## Where .bhb lands ahead

- Guessing is memory-hard and heavy by default, and the cost lives in
  each bundle's header, so new bundles can get steeper without
  breaking old ones.
- The password can be only half the key. With `--keyfile`, a copy of
  the bundle alone cannot be tested offline at all.
- Sloppy passwords are refused when the bundle is made, not after a
  loss.
- Tags, sizes, and structure are inside the ciphertext, no flags
  needed.
- Extraction refuses absolute paths, `..`, symlinks, and devices by
  default.

## The fine print

Opening a `hard` bundle costs a few seconds and up to a gigabyte of
RAM; `paranoid` about two. That is the point, but it is also a real
cost on old machines, so `--kdf light` exists.
`.bhb` has not been independently reviewed. The format is a page of
code (`src/blackhole_sec/bundle/__init__.py`); read it before you
bet anything you cannot lose on it. If you need third-party assurance
today, age is the safer pick.
