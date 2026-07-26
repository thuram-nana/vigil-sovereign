"""A1 — live API-key health probes + the API-keys status plane.

Proves the property the operator asked for: a bad/expired key ALWAYS shows as failing (never a false green),
the probe is fail-closed + secret-free + SSRF-guarded, and settings_status/check_secret surface the verdict.
"""
from __future__ import annotations

import io
import urllib.error

import pytest


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SIGIL_HOME", str(tmp_path))
    # keep probe companion-config deterministic
    for k in ("AZURE_OPENAI_ENDPOINT", "CRUCIBLE_BEDROCK_REGION", "AWS_REGION"):
        monkeypatch.delenv(k, raising=False)


def _probes():
    from sigil.platform import secret_probes as P
    return P


def _store():
    from sigil.platform.secrets import SecretStore
    return SecretStore()


# --- fail-closed + secret-free core ----------------------------------------------------------------

def test_unset_secret_is_unknown_not_ok():
    P = _probes()
    v = P.check_secret_health("MISTRAL_API_KEY")
    assert v["status"] == "unknown" and v["reason"] == "not set"


def test_secret_without_probe_is_unknown():
    P = _probes()
    _store().set("CRUCIBLE_API_KEY", "internal-shared-secret")
    v = P.check_secret_health("CRUCIBLE_API_KEY")
    assert v["status"] == "unknown" and "no live check" in v["reason"]


def test_probe_that_raises_fails_closed(monkeypatch):
    P = _probes()
    _store().set("ANTHROPIC_API_KEY", "sk-whatever")
    monkeypatch.setitem(P._PROBES, "ANTHROPIC_API_KEY",
                        lambda v, s, c: (_ for _ in ()).throw(RuntimeError("boom")))
    v = P.check_secret_health("ANTHROPIC_API_KEY")
    assert v["status"] == "fail" and "RuntimeError" in v["reason"]


def test_verdict_and_cache_never_contain_the_secret_value(monkeypatch):
    P = _probes()
    secret = "sk-ant-SUPER-SECRET-abc123"
    _store().set("ANTHROPIC_API_KEY", secret)
    monkeypatch.setitem(P._PROBES, "ANTHROPIC_API_KEY", lambda v, s, c: (P.OK, "reachable (HTTP 200)"))
    v = P.check_secret_health("ANTHROPIC_API_KEY")
    assert v["status"] == "ok"
    blob = P._HEALTH_CACHE.read_text(encoding="utf-8") + repr(v)
    assert secret not in blob                      # neither the cache nor the verdict leaks the value


# --- HTTP status mapping (401/403 → fail; 2xx → ok; network → fail) --------------------------------

def _fake_urlopen_status(code):
    class _Resp:
        def getcode(self):
            return code
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
    return lambda req, timeout=None: _Resp()


def test_http_probe_ok_and_reject(monkeypatch):
    P = _probes()
    monkeypatch.setattr(P.urllib.request, "urlopen", _fake_urlopen_status(200))
    assert P._http_probe("https://api.example.com/x", {})[0] == P.OK

    def _401(req, timeout=None):
        raise urllib.error.HTTPError("u", 401, "unauth", {}, io.BytesIO(b""))
    monkeypatch.setattr(P.urllib.request, "urlopen", _401)
    st, reason = P._http_probe("https://api.example.com/x", {})
    assert st == P.FAIL and "401" in reason

    def _neterr(req, timeout=None):
        raise urllib.error.URLError("no route")
    monkeypatch.setattr(P.urllib.request, "urlopen", _neterr)
    assert P._http_probe("https://api.example.com/x", {})[0] == P.FAIL


def test_anthropic_probe_sends_key_header_and_maps_ok(monkeypatch):
    P = _probes()
    captured = {}

    def _cap(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        class _R:
            def getcode(self): return 200
            def __enter__(self): return self
            def __exit__(self, *a): return False
        return _R()
    monkeypatch.setattr(P.urllib.request, "urlopen", _cap)
    st, _ = P._probe_anthropic("sk-ant-xyz", _store(), {})
    assert st == P.OK
    assert captured["url"] == "https://api.anthropic.com/v1/models"     # host-pinned
    assert captured["headers"].get("x-api-key") == "sk-ant-xyz"


# --- SSRF guard on the one operator-supplied URL (Azure endpoint) ----------------------------------

def test_azure_probe_rejects_non_azure_endpoint():
    P = _probes()
    st, reason = P._probe_azure_openai("key", _store(), {"AZURE_OPENAI_ENDPOINT": "http://evil.example.com"})
    assert st == P.FAIL and "openai.azure.com" in reason
    st2, reason2 = P._probe_azure_openai("key", _store(), {"AZURE_OPENAI_ENDPOINT": ""})
    assert st2 == P.UNKNOWN                        # no endpoint → can't check (not a false ok)


def test_aws_probe_needs_companion_and_boto3():
    P = _probes()
    # no companion secret → unknown (not fail, not ok)
    st, reason = P._probe_aws("AKIA...", _store(), {})
    assert st == P.UNKNOWN and "AWS_SECRET_ACCESS_KEY" in reason


# --- the settings plane surfaces health + category + the failing count -----------------------------

def test_settings_status_surfaces_health_category_and_failing_count():
    from sigil.ui import settings as S
    _store().set("ANTHROPIC_API_KEY", "sk-ant-x")
    _probes()._write_cache("ANTHROPIC_API_KEY", {"status": "fail", "reason": "rejected", "checked_at": 1})
    st = S.settings_status()
    assert st["keys_failing"] == 1
    assert [c["id"] for c in st["secret_categories"]] == ["llm", "cloud", "integration", "destruction"]
    row = next(r for r in st["secrets"] if r["name"] == "ANTHROPIC_API_KEY")
    assert row["category"] == "llm" and row["probeable"] is True
    assert row["health"]["status"] == "fail"
    # a set-but-never-checked key reads as 'unchecked', not a false ok
    _store().set("GITHUB_TOKEN", "ghp_x")
    st2 = S.settings_status()
    gh = next(r for r in st2["secrets"] if r["name"] == "GITHUB_TOKEN")
    assert gh["health"]["status"] == "unchecked"


def test_check_secret_action_refuses_unknown_name():
    from sigil.ui import settings as S
    from sigil.governor.identity import ensure_owner_keypair
    from sigil.spine.store import SpineStore
    with pytest.raises(ValueError):
        S.check_secret("NOT_A_SECRET", store=SpineStore(), owner_key=ensure_owner_keypair())


def test_secret_names_is_the_full_inventory():
    from sigil.ui import settings as S
    assert set(S.SECRET_NAMES) >= {"ANTHROPIC_API_KEY", "GITHUB_TOKEN", "VIGIL_DESTRUCTION_OWNER_KEY",
                                   "MISTRAL_API_KEY", "OPENAI_API_KEY", "AWS_ACCESS_KEY_ID",
                                   "AZURE_OPENAI_API_KEY"}
