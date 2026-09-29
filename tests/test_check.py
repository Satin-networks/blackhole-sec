import json

from blackhole_sec.check.features import analyze_url
from blackhole_sec.check.report import defang, to_dict
from blackhole_sec.check.scorer import score_features


def verdict(url: str) -> tuple[str, int]:
    _info, feats = analyze_url(url)
    s, v, _, _ = score_features(feats)
    return v, s


def test_benign_google():
    v, s = verdict("https://www.google.com/search?q=hello")
    assert v == "BENIGN", (v, s)


def test_phishing_brand_subdomain():
    v, s = verdict("http://secure.paypal.com.evil-tk.tk/login?redirect=http://evil.com")
    assert v == "MALICIOUS", (v, s)


def test_ip_host_flagged():
    _v, s = verdict("http://192.168.1.10/login")
    assert s >= 15


def test_punycode_and_homoglyph():
    _v, s = verdict("http://xn--pypal-4ve.com/login")
    assert s >= 16


def test_defang_never_returns_live_link():
    assert "http" not in defang("http://evil.com/a")


def test_json_shape():
    info, feats = analyze_url("https://discord.com/login")
    s, v, c, fired = score_features(feats)
    d = to_dict(info, s, v, c, fired)
    assert {"input", "host", "score", "verdict", "confidence", "mitre", "defanged", "signals"} <= set(d)
    assert isinstance(json.dumps(d), str)


def test_offline_never_networks(monkeypatch):
    import socket
    def boom(*a, **k):
        raise AssertionError("network used!")
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    verdict("http://paypal-secure-login-verify.tk/free-nitro?url=http://evil.com/x.exe")
