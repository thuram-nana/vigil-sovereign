"""F1 — url_guard: the app-layer SSRF/metadata pre-filter (delegating IP checks to the P6 egress
denylist). Requires vigil_gateway on the path."""

from __future__ import annotations

import pytest

from vigil_integration.safety.url_guard import UnsafeURLError, assert_safe_url, is_safe_url


def _r(*ips):
    return lambda host, port: list(ips)


def test_non_http_schemes_are_refused():
    for u in ("file:///etc/passwd", "gopher://x/", "ftp://h/", "data:text/plain,hi", "  "):
        assert is_safe_url(u)[0] is False


def test_metadata_hostnames_are_blocked():
    for u in ("http://metadata.google.internal/computeMetadata/v1/",
              "https://metadata/", "http://instance-data.ec2.internal/"):
        assert is_safe_url(u, resolve=_r("93.184.216.34"))[0] is False


def test_metadata_ip_is_blocked_via_denylist():
    # 169.254.169.254 (IMDS) is hard-denied by the shared egress denylist
    ok, reason = is_safe_url("https://imds.example/", resolve=_r("169.254.169.254"))
    assert ok is False and "denied" in reason
    # IPv4-mapped IPv6 form must not slip past (denylist unwraps it)
    assert is_safe_url("https://x/", resolve=_r("::ffff:169.254.169.254"))[0] is False


def test_public_https_target_is_allowed():
    assert is_safe_url("https://example.com/path", resolve=_r("93.184.216.34"))[0] is True


def test_private_is_denied_unless_charter_allowlisted():
    assert is_safe_url("https://internal/", resolve=_r("10.0.0.5"))[0] is False
    assert is_safe_url("https://internal/", resolve=_r("10.0.0.5"), allowed_ips=["10.0.0.5"])[0] is True
    # CGNAT (100.64/10) and ULA are also private-tier
    assert is_safe_url("https://x/", resolve=_r("100.100.100.200"))[0] is False


def test_plaintext_http_to_public_host_is_refused():
    assert is_safe_url("http://example.com/", resolve=_r("93.184.216.34"))[0] is False
    # http to an explicitly-allowlisted internal IP is permitted
    assert is_safe_url("http://internal/", resolve=_r("10.0.0.9"), allowed_ips=["10.0.0.9"])[0] is True


def test_unresolvable_host_fails_closed():
    assert is_safe_url("https://nope.invalid/", resolve=lambda h, p: [])[0] is False


def test_denied_if_any_resolved_ip_is_denied():
    # DNS returning both a public and an internal IP → refused (defends against rebinding at check time)
    assert is_safe_url("https://x/", resolve=_r("93.184.216.34", "169.254.169.254"))[0] is False


def test_backslash_authority_confusion_matches_the_real_client():
    # F1 re-check: `http://<metadata>\@allowed/` connects to the metadata IP (requests folds \->/).
    # url_guard must fold \->/ too, see the metadata IP literal, and deny — not be fooled by 'allowed'.
    # (No resolve injection: the folded host is an IP literal, so _resolve_ips returns it directly.)
    ok, reason = is_safe_url("http://169.254.169.254\\@allowed.com/")
    assert ok is False and "denied" in reason
    # a bare metadata IP with a trailing backslash-path is likewise denied
    assert is_safe_url("https://169.254.169.254\\x/")[0] is False


def test_assert_raises_and_passes():
    with pytest.raises(UnsafeURLError):
        assert_safe_url("https://x/", resolve=_r("169.254.169.254"))
    assert_safe_url("https://example.com/", resolve=_r("93.184.216.34"))  # no raise
