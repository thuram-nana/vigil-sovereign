"""E5 (discovery half) — the WARDEN-gated exposed-secret DISCOVERY runner (secret_discovery).

Discovery HUNTS a retained text surface for strings whose SHAPE matches a known secret format and emits a
secret-safe CANDIDATE for each. The load-bearing invariant: a candidate is a LEAD, never a FACT — a regex
match on tool bytes is a hint, not proof. Promotion to a FACT stays OATH-gated: only the WARDEN-gated
``secret_runner`` confirming call, adjudicated by the deterministic E5 oracle, can do it.

The pure-discovery tests are framework-free and run in the sovereign leg; the ONE oracle-gating test uses a
function-level ``importorskip('framework')`` and runs in the offense leg (this file is on the offense-leg list
in ci.yml, so that test executes; the guard test_ci_framework_tests_run_in_offense_leg enforces that).
"""
from __future__ import annotations

import pytest

from vigil_integration.live.secret_discovery import (
    DISCOVERY_PATTERNS, SecretCandidate, candidate_finding, discovery_types, fact_capable_types, scan,
)

# A retained text surface with ONE valid token of each recognised shape. Every secret-shaped fixture is
# ASSEMBLED AT RUNTIME (the recognizable prefix is never contiguous with its body in a single source literal),
# so GitHub push-protection secret scanning cannot match a fake token — the assembled dummy is identical.
# (The AWS value is AWS's own documented example key; the rest are constructed dummies. None is a live secret;
# discovery fingerprints + redacts them.)
def _tok(*parts: str) -> str:
    return "".join(parts)

_AWS = _tok("AKI", "AIOSFODNN7EXAMPLE")                          # AWS documented example key, de-literalized
_GH = _tok("gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyzABCD")   # ghp_ + 40
_GL = _tok("glp", "at-", "abcdEFGH1234ijklMNOP")                     # glpat- + 20
_SL = _tok("xo", "xb-", "1111111111-2222222222-abcdefghijklmnop")   # xoxb- + body
_GK = _tok("AI", "za", "b" * 35)                                    # AIza + 35
_WH = _tok("https://hooks.", "slack.com", "/services/", "T00000000", "/B00000000", "/",
           "abcdefABCDEF012345678901")
_BLOB = f"""
# leaked config dump (test fixture)
aws_key      = {_AWS}
github_token = {_GH}
gitlab_token = {_GL}
slack_token  = {_SL}
google_key   = {_GK}
slack_hook   = {_WH}
"""

_ALL_TYPES = {"aws_access_key", "github_pat", "gitlab_pat", "slack_token",
              "google_api_key", "slack_webhook_url"}


# -- behaviour: every recognised shape is found, and every result is a LEAD -----------------------------
def test_scan_finds_a_candidate_of_every_recognised_shape() -> None:
    cands = scan(_BLOB, source="config:dump.env")
    found = {c.secret_type for c in cands}
    assert found == _ALL_TYPES, f"missing: {_ALL_TYPES - found}; extra: {found - _ALL_TYPES}"
    # EVERY discovery result is a LEAD — discovery never produces a FACT.
    assert all(c.verdict == "LEAD" for c in cands)
    assert all(c.source == "config:dump.env" for c in cands)


def test_fact_capable_labelling_is_honest() -> None:
    """The four types the E5 oracle can adjudicate are fact_capable; the two with no sound identity endpoint
    (a Google API key, a Slack webhook URL) are recognised LEADs but NOT promotable — honestly labelled."""
    by_type = {c.secret_type: c for c in scan(_BLOB)}
    for t in ("aws_access_key", "github_pat", "gitlab_pat", "slack_token"):
        assert by_type[t].fact_capable is True, t
    for t in ("google_api_key", "slack_webhook_url"):
        assert by_type[t].fact_capable is False, t


def test_fact_capable_set_is_the_runner_supported_set_no_drift() -> None:
    """fact_capable labelling is driven by the runner's supported set (imported, not re-listed), and every
    FACT-capable type is actually discoverable."""
    from vigil_integration.live.secret_runner import SUPPORTED_SECRET_TYPES
    assert fact_capable_types() == frozenset(SUPPORTED_SECRET_TYPES)
    assert fact_capable_types() <= discovery_types()          # every promotable type is recognised
    assert fact_capable_types() < discovery_types()           # discovery recognises strictly MORE than it promotes


# -- secret-safety: the raw value is never retained -----------------------------------------------------
def test_no_raw_secret_value_is_retained_on_a_candidate() -> None:
    cands = {c.secret_type: c for c in scan(_BLOB, source="js:app.js")}
    # token-type secrets: the raw token IS the secret and must NOT appear anywhere on the candidate — only a
    # short structural prefix (or a host label) survives, plus a redacted preview and a fingerprint.
    for t, raw in (("github_pat", _GH), ("gitlab_pat", _GL), ("slack_token", _SL),
                   ("google_api_key", _GK), ("slack_webhook_url", _WH)):
        c = cands[t]
        assert raw not in repr(c), f"{t}: raw value leaked into the candidate"
        assert raw not in c.redacted and raw not in c.identifier, t
    # an AWS AccessKeyId is a PUBLIC identifier (the secret is the SecretAccessKey, which is not in the text at
    # all) — it is deliberately retained as the identifier, exactly as the E5 oracle retains it.
    aws = cands["aws_access_key"]
    assert aws.identifier == _AWS
    assert aws.redacted.startswith("AKIA") and "REDACTED" in aws.redacted
    assert aws.fingerprint.startswith("sha256:")


def test_fingerprint_matches_the_validation_runners_fingerprint_for_correlation() -> None:
    """The candidate's fingerprint is the SAME domain-separated fingerprint secret_runner stamps on a
    validated capture — so a later FACT can be tied back to this candidate without the raw value."""
    from vigil_integration.live.secret_runner import secret_fingerprint
    aws = next(c for c in scan(_BLOB) if c.secret_type == "aws_access_key")
    assert aws.fingerprint == secret_fingerprint(_AWS)


# -- NEGATIVE CONTROL: benign text and near-misses produce nothing (the recognizer is not a no-op) -------
def test_benign_text_and_near_misses_yield_no_candidates() -> None:
    # near-miss shapes are assembled at runtime too (prefix split from body), so no source literal matches.
    benign = (
        "This paragraph mentions AKIA airlines, a github ghp handle, glpat as a word, "
        "and xoxb without a token. None is a secret.\n"
        + _tok("AK", "IASHORT01") + "\n"            # AKIA + <16 chars -> not an access key
        + _tok("glp", "at-tooshort") + "\n"         # glpat- + <20 chars -> not a token
        + _tok("AI", "zaShort") + "\n"              # AIza + <35 chars -> not a google key
        + _tok("xo", "xb-short") + "\n"             # xox?- + <10 chars -> not a slack token
        + _tok("https://hooks.", "slack.com/services/onlyonepart") + "\n"   # not a 3-segment webhook path
    )
    assert scan(benign) == [], scan(benign)
    # ...and the discriminating positive: dropping one real token INTO the same benign text is found.
    assert {c.secret_type for c in scan(benign + "\nreal=" + _AWS)} == {"aws_access_key"}


def test_scan_never_raises_on_odd_input() -> None:
    for bad in (None, b"bytes", 123, [], {}, ""):
        assert scan(bad) == []       # type: ignore[arg-type]


# -- the discovery runner has NO mint/FACT path (adjudication is elsewhere) ------------------------------
def test_candidate_finding_is_a_lead_and_the_module_exposes_no_mint_path() -> None:
    import vigil_integration.live.secret_discovery as disc
    cand = next(c for c in scan(_BLOB) if c.secret_type == "aws_access_key")
    finding = candidate_finding(cand)
    assert finding["verdict"] == "LEAD" and finding["bug_class"] == "secret_exposure"
    # the module offers no admission / certification / FACT primitive — adjudication lives in the oracle path.
    for forbidden in ("admit", "certify", "certify_admitted", "build_certificate", "mint"):
        assert not hasattr(disc, forbidden), f"discovery must expose no FACT-minting primitive: {forbidden}"


# -- ORACLE-GATED: a discovered candidate's bytes alone never fire the oracle (LEAD, not FACT) -----------
def test_a_discovered_candidate_stays_a_lead_until_the_oracle_confirms_a_real_call() -> None:
    """The core soundness property: adjudication stays oracle-gated. A discovered candidate routed through the
    E5 oracle WITHOUT a confirming call does NOT fire (it is a LEAD); only a fingerprint-bound confirming call
    over an allow-listed transport makes the SAME oracle fire — proving no FACT is minted from tool bytes."""
    pytest.importorskip("framework.v2.verify", reason="the E5 oracle needs CRUCIBLE (offense leg)")
    from framework.v2.verify.oracles import exposed_secret_validity_oracle

    cand = next(c for c in scan(_BLOB, source="js:app.js") if c.secret_type == "aws_access_key")
    # bytes-alone capture (a discovery LEAD, no confirming call) -> the oracle does NOT fire
    lead_capture = {
        "secret_type": cand.secret_type,
        "credential": {"identifier": cand.identifier, "secret": "[REDACTED]",
                       "credential_fingerprint": cand.fingerprint, "source": cand.source},
    }
    lead_sig = exposed_secret_validity_oracle(lead_capture)
    assert lead_sig.fired is False and lead_sig.observed["reason"] == "no_confirming_call"

    # POSITIVE CONTROL: the SAME candidate WITH a fingerprint-bound, allow-listed confirming call -> fires.
    fact_capture = {
        **lead_capture,
        "confirming_call": {"action": "sts:GetCallerIdentity", "status": 200,
                            "credential_fingerprint": cand.fingerprint,
                            "endpoint": "https://sts.us-east-1.amazonaws.com/",
                            "tls_verified": True, "no_proxy": True, "no_redirect": True,
                            "resolved_peer": "1.2.3.4", "response_digest": "sha256:aaa",
                            "response": {"Arn": "arn:aws:iam::123456789012:user/leaked",
                                         "Account": "123456789012", "UserId": "AIDAEXAMPLE"}},
    }
    assert exposed_secret_validity_oracle(fact_capture).fired is True


def test_every_discovery_pattern_compiles_and_matches_its_own_row() -> None:
    """A cheap structural guard: each pattern is a compiled regex, and scanning a string that is ONLY that
    row's token yields exactly that one type."""
    samples = {"aws_access_key": _AWS, "github_pat": _GH, "gitlab_pat": _GL,
               "slack_token": _SL, "google_api_key": _GK, "slack_webhook_url": _WH}
    assert set(samples) == set(DISCOVERY_PATTERNS)
    for t, tok in samples.items():
        assert {c.secret_type for c in scan(tok)} == {t}, (t, tok)
    # every candidate from a single-token scan is a LEAD with the expected type
    assert all(isinstance(c, SecretCandidate) and c.verdict == "LEAD"
               for c in scan(" ".join(samples.values())))
