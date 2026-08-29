"""The offense doctor's LLM-backend probe must not leak an endpoint's inline credentials.

`vigil doctor` (offense plane) is surfaced to operator+ over /api/doctor (Wave 2b parity). A credentialed
self-hosted endpoint (LLM_API_BASE=https://user:key@proxy) must never leak its userinfo into the report's
`endpoint` field or `detail` — the raw endpoint is still used for probing (host/port carry no userinfo),
the REDACTED copy is what surfaces. Shares the scrubber with the sovereign plane (vigil_core.doctor).
"""
from vigil_integration import doctor as dmod


def test_probe_llm_backend_redacts_a_credentialed_nonloopback_endpoint(monkeypatch):
    # a self-hosted family backend pointed at a credentialed NON-loopback proxy — the engine refuses it,
    # but the doctor still reports it; the creds must be stripped before they reach the report.
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "self-hosted")
    monkeypatch.setenv("CRUCIBLE_SELFHOSTED_ENDPOINT", "https://apiuser:s3cr3t@PASS@proxy.example:8443/v1")
    out = dmod._probe_llm_backend()
    # the endpoint field is the redacted copy — userinfo gone, host/path preserved
    assert out.get("endpoint") == "https://***@proxy.example:8443/v1", out.get("endpoint")
    # NO credential fragment (incl. the tail after the unescaped @) anywhere in the probe result
    import json
    blob = json.dumps(out, default=str)
    for needle in ("apiuser", "s3cr3t", "PASS", "apiuser:s3cr3t"):
        assert needle not in blob, f"llm-backend probe leaked {needle!r}: {out.get('detail')}"


def test_probe_llm_backend_loopback_endpoint_without_creds_is_unchanged(monkeypatch):
    # the common case: a plain loopback endpoint has no userinfo and must render verbatim
    monkeypatch.setenv("CRUCIBLE_LLM_BACKEND", "ollama")
    monkeypatch.setenv("CRUCIBLE_OLLAMA_HOST", "http://127.0.0.1:11434")
    out = dmod._probe_llm_backend()
    assert out.get("endpoint") == "http://127.0.0.1:11434"
