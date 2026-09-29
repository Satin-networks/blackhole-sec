"""Offline phishing checks. String analysis only, nothing is fetched."""
from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from urllib.parse import urlparse

MAX_URL_LEN = 2048

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "work", "fit",
    "sbs", "cyou", "rest", "bar", "loan", "win", "bid", "click", "link",
    "country", "stream", "download", "review", "party", "trade",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bitly.com", "cutt.ly", "rb.gy", "shorte.st", "tiny.cc",
}

FREE_HOST_ABUSE = {
    "ngrok.io", "glitch.me", "repl.co", "replit.dev", "pages.dev",
    "netlify.app", "vercel.app", "herokuapp.com", "appspot.com",
    "github.io", "gitlab.io", "surge.sh", "render.com",
}

BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "discord": ["discord.com", "discord.gg"],
    "steam": ["steampowered.com", "steampc.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "instagram": ["instagram.com"],
    "facebook": ["facebook.com", "fb.com"],
    "twitter": ["twitter.com", "x.com"],
    "tiktok": ["tiktok.com"],
    "roblox": ["roblox.com"],
    "minecraft": ["minecraft.net", "mojang.com"],
    "freezehost": ["freezehost.pro"],
    "satin": ["satin.networks"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "confirm", "account",
    "free", "nitro", "airdrop", "coins", "gift", "winner", "prize",
    "wallet", "seed", "recovery", "password", "billing", "invoice",
]

MALWARE_EXTS = (".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".jar", ".apk", ".msi", ".com", ".pif")

REDIRECT_PARAMS = ("url=", "redirect=", "next=", "continue=", "dest=", "destination=", "r=")


@dataclass
class FeatureResult:
    name: str
    weight: int
    fired: bool
    evidence: str = ""
    mitre: str = ""
    explanation: str = ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    n = len(s)
    for v in freq.values():
        p = v / n
        ent -= p * math.log2(p)
    return ent


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_ip(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def _is_private_ip(host: str) -> bool:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h).is_private
    except ValueError:
        return False


def normalize_url(raw: str) -> str:
    raw = raw.strip().strip("'\"")
    if len(raw) > MAX_URL_LEN:
        raw = raw[:MAX_URL_LEN]
    if "://" not in raw:
        raw = "http://" + raw
    return raw


def analyze_url(raw_url: str) -> tuple[dict, list[FeatureResult]]:
    """Return (parsed_info, features). Never raises on bad input, never networks."""
    url = normalize_url(raw_url)
    try:
        p = urlparse(url)
    except ValueError:
        p = urlparse("http://invalid/")
    try:
        host = (p.hostname or "").lower()
    except ValueError:
        host = ""
    path = p.path or ""
    query = p.query or ""
    full = url

    feats: list[FeatureResult] = []

    def add(name, weight, fired, evidence="", mitre="", explanation=""):
        feats.append(FeatureResult(name, weight if fired else 0, fired, evidence, mitre, explanation))

    # 1 IP host
    is_ip = _is_ip(host)
    add("ip_host", 15, is_ip, host, "T1583.005",
        "URL uses an IP address instead of a domain name, a common evasion tactic.")
    # 2 private IP
    add("private_ip", 20, _is_private_ip(host), host, "T1583.005",
        "Private/local IP as host suggests LAN attack or tunneling.")
    # 3 punycode
    add("punycode", 16, "xn--" in host, host, "T1027",
        "Punycode (xn--) can hide lookalike internationalized domains.")
    # 4 non-ascii / homoglyph
    non_ascii = any(ord(c) > 127 for c in host)
    add("homoglyph", 18, non_ascii, host, "T1566.002",
        "Non-ASCII characters enable homograph attacks (e.g. Cyrillic 'а' for 'a').")
    # 5 shortener
    add("shortener", 10, host in SHORTENERS, host, "T1659",
        "URL shortener hides the true destination.")
    # 6 suspicious TLD
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    add("suspicious_tld", 10, tld in SUSPICIOUS_TLDS, f".{tld}", "",
        "TLD is disproportionately abused for phishing.")
    # 7 length
    add("long_url", 4, len(full) > 75, f"len={len(full)}", "",
        "Unusually long URL, often used to hide the malicious part.")
    add("very_long_url", 4, len(full) > 200, f"len={len(full)}", "T1027",
        "Extremely long URL, strong obfuscation signal.")
    # 8 deep path
    depth = len([s for s in path.split("/") if s])
    add("deep_path", 3, depth > 4, f"depth={depth}", "",
        "Deeply nested path obscures the endpoint.")
    # 9 subdomains
    labels = host.split(".") if host else []
    sub_count = max(0, len(labels) - 2)
    add("many_subdomains", 3, sub_count > 2, f"subdomains={sub_count}", "",
        "Excessive subdomains often squat on a trusted name (a.b.c.evil.com).")
    add("extreme_subdomains", 4, sub_count > 4, f"subdomains={sub_count}", "T1027",
        "Extreme subdomain depth is rare on legitimate sites.")
    # 10 hyphens
    add("many_hyphens", 3, host.count("-") > 3, host, "",
        "Many hyphens typify combo-squat domains (paypal-secure-login-verify).")
    # 11 double slash in path
    add("double_slash", 5, "//" in path, path[:80], "",
        "Double slash inside the path can confuse parsers.")
    # 12 @ trick
    add("at_symbol", 8, "@" in full, full[:120], "",
        "'@' in a URL means everything before it is credentials, not the destination.")
    # 13 no https
    add("no_https", 7, p.scheme != "https", p.scheme, "",
        "No HTTPS on a login/payment page exposes credentials.")
    # 14 non-standard port
    try:
        port = p.port
    except ValueError:
        port = -1  # invalid port like :99999
        add("nonstd_port", 3, True, "invalid port", "", "Invalid port value.")
        port = None
    if port is None:
        std = True
    else:
        std = (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)
        add("nonstd_port", 3, not std, f"port={port}", "",
            "Non-standard port is uncommon for public login pages.")
    # 15 hex/percent encoding abuse
    pct = full.count("%")
    add("hex_encoding", 6, pct >= 3 or "%25" in full.lower(), f"percent signs={pct}", "T1027",
        "Excessive percent-encoding hides keywords from users and filters.")
    # 16 entropy
    ent = _shannon_entropy(host.replace(".", ""))
    add("high_domain_entropy", 5, ent > 4.2 and len(host) >= 12, f"entropy={ent:.2f}", "T1027",
        "High entropy suggests an algorithmically generated domain (DGA).")
    pent = _shannon_entropy(path)
    add("high_path_entropy", 6, pent > 4.5 and len(path) >= 20, f"entropy={pent:.2f}", "T1027",
        "High path entropy suggests random tokens or obfuscation.")
    # 17 suspicious keywords
    low = full.lower()
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in low]
    add("suspicious_keywords", 8, bool(hits), ",".join(hits[:5]), "T1566.002",
        "Phishing lure words in the URL (verify/free/nitro/wallet...).")
    # 18 malware ext - path only (not TLD like .com)
    _path_only = (path.split("?")[0].lower() or "/")
    add("malware_ext", 15, _path_only.endswith(MALWARE_EXTS), path[-30:], "T1105",
        "Direct executable payload in the URL path.")
    # 19 redirect param
    add("redirect_param", 6, any(r in low for r in REDIRECT_PARAMS), query[:80], "T1659",
        "Open-redirect parameter can launder a trusted domain into an evil one.")
    # 20 brand in wrong domain
    brand_hit = ""
    brand_ok = False
    for brand, legit in BRANDS.items():
        if brand in host:
            brand_hit = brand
            brand_ok = any(host == d or host.endswith("." + d) for d in legit)
            break
    add("brand_impersonation", 18, bool(brand_hit) and not brand_ok,
        f"brand={brand_hit} host={host}", "T1566.002",
        "Trusted brand name appears in a domain that is not the brand's own.")
    # 21 brand in subdomain (a.paypal.com.evil.com pattern)
    brand_in_sub = False
    if brand_hit and not brand_ok and host.count(".") >= 2:
        brand_in_sub = True
    add("brand_in_subdomain", 15, brand_in_sub, host, "T1566.002",
        "Brand placed in subdomain while actual domain is attacker-controlled.")
    # 22 typosquat edit distance
    typo = ""
    if host and not brand_ok:
        base = host.split(".")[0]
        for brand in BRANDS:
            if 1 <= _levenshtein(base, brand) <= 2 and base != brand:
                typo = f"{base}~{brand}"
                break
    add("typosquat", 18, bool(typo), typo, "T1566.002",
        "Domain is one or two edits from a major brand (paypa1, micros0ft).")
    # 23 free-host abuse
    add("hosting_abuse", 12, any(host == d or host.endswith("." + d) for d in FREE_HOST_ABUSE),
        host, "T1583.006", "Free hosting / tunnel domain frequently abused for phishing pages.")
    # 24 digits ratio
    digits = sum(c.isdigit() for c in host)
    add("digit_heavy", 4, len(host) > 0 and digits / max(1, len(host)) > 0.3, host, "",
        "Digit-heavy domain is atypical for legitimate brands.")
    # 25 userinfo present
    try:
        has_user = bool(p.username)
    except ValueError:
        has_user = False
    add("userinfo", 8, has_user, "user@", "", "Credentials embedded in URL.")

    info = {
        "input": raw_url[:MAX_URL_LEN],
        "normalized": url,
        "scheme": p.scheme,
        "host": host,
        "path": path,
        "query": query[:200],
    }
    return info, feats
