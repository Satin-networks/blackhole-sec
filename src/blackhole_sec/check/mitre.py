"""MITRE ATT&CK mapping for signals."""
MAP = {
    "ip_host": ["T1583.005"],
    "private_ip": ["T1583.005"],
    "punycode": ["T1027"],
    "homoglyph": ["T1566.002"],
    "shortener": ["T1659"],
    "hex_encoding": ["T1027"],
    "high_domain_entropy": ["T1027"],
    "high_path_entropy": ["T1027"],
    "suspicious_keywords": ["T1566.002"],
    "malware_ext": ["T1105"],
    "redirect_param": ["T1659"],
    "brand_impersonation": ["T1566.002"],
    "brand_in_subdomain": ["T1566.002"],
    "typosquat": ["T1566.002"],
    "hosting_abuse": ["T1583.006"],
    "very_long_url": ["T1027"],
    "extreme_subdomains": ["T1027"],
    "digit_heavy": [],
    "userinfo": [],
}


def mitre_for(fired_names: list[str]) -> list[str]:
    out: list[str] = []
    for n in fired_names:
        for t in MAP.get(n, []):
            if t not in out:
                out.append(t)
    return sorted(out)
