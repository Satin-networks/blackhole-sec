# blackhole-sec

Four small tools I reach for every day, in one install.
Everything runs offline. Nothing phones home.

<div class="grid cards" markdown>

-   :material-link-off: **check**

    Paste a sketchy link, get a score and a reason.
    Never fetches the URL.

-   :material-lock: **vault**

    Passwords in one encrypted file on your disk.
    Argon2id + AES-256-GCM.

-   :material-image-off: **shred**

    See photo metadata, strip it, or delete for real.

-   :material-package-variant-closed: **bundle**

    Encrypted `.bhb` archives instead of zip.
    Names and contents hidden.

</div>

```bash
pip install blackhole-sec
# or without touching pip yourself:
curl -fsSL https://raw.githubusercontent.com/Satin-networks/blackhole-sec/main/scripts/install.sh | bash

blackhole check "http://secure-paypal-login.tk/free-nitro"
blackhole vault init
blackhole shred analyze photo.jpg
blackhole bundle create ./mydir ./backup.bhb
```

Start with [Checking links](check.md) if you live in Discord DMs,
or [Everyday recipes](recipes.md) for copy-paste flows.

> Companion to [wisp](https://github.com/satin-networks/wisp),
> our local WireGuard manager. Wisp moves the packets,
> blackhole keeps the rest of your life tidy.
