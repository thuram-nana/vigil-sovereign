"""Adjudicate a REAL GitHub credential validation through the production confirmation path.

Driven by ``secret_github_livefire.sh``, which obtains a token from ``gh auth token`` and pipes it here on
stdin. This module does the part that matters: it drives the real WARDEN-gated runner over the real
``live_transport`` against the real ``api.github.com``, then feeds the resulting capture to the same code
that runs in a real assessment — the deterministic oracle, the admission step, the certificate mint — and
checks the certificate by re-verifying it OFFLINE.

Every expectation below is asserted, so this exits non-zero if reality stops matching the claim. That is
deliberate: a live-fire script that only prints and never fails is a demo, not a proof.

THE CONTROLS ARE THE PRODUCT. A validity oracle that says "valid" for everything proves nothing, so three
things that MUST NOT be confirmed are run against the same production path:

  1. A bogus token of the correct SHAPE, sent live to the real api.github.com. GitHub answers 401 and the
     oracle leaves it a LEAD. This is a real network round-trip, not a fixture.
  2. The confirmed capture with its confirming ENDPOINT swapped to an attacker-controlled host. This is the
     anti-laundering gate that makes the whole design sound: if any endpoint could confirm a secret, an
     attacker who controls one could mint arbitrary facts. Done as a MUTATION of the real capture rather
     than a live call, because sending the operator's genuine token to a third-party host to prove a point
     would be the exact harm the gate exists to prevent — and the runner's own exfil floor refuses it too,
     which is asserted separately.
  3. The confirmed capture with the credential and the call carrying DIFFERENT fingerprints — the "some
     other secret authenticated" case.

THE TOKEN. It is read from stdin, used, and dropped. It is never written to disk, an argv, or an
environment variable, and the run asserts it does not appear in the capture, the oracle context, or the
signed certificate.
"""
from __future__ import annotations

import copy
import json
import sys


class _AllowGate:
    """The D5 charter scope gate, standing in for a signed charter. The operator's own GitHub account is
    the authorized target here; the gate is exercised for real (including its refusal) below."""

    def authorize(self, *_scope):
        return True, "operator's own GitHub identity, authorized owner-test"


class _DenyGate:
    def authorize(self, *_scope):
        return False, "resource not in signed charter scope"


class _Runner:
    """Bookkeeping for the checks, so one deviation anywhere fails the whole run."""

    def __init__(self) -> None:
        self.failures: list[str] = []

    def expect(self, label: str, condition: bool, detail: str = "") -> bool:
        print(f"   {'OK ' if condition else '!! '}{label}")
        if not condition:
            self.failures.append(f"{label}{': ' + detail if detail else ''}")
        return condition

    def check_fact(self, label: str, result, want_fact: bool, trust_root) -> None:
        """Assert a verdict, and — when it is a FACT — that its signed certificate re-verifies OFFLINE."""
        from framework.v2.evidence.certify import verify_certificate

        got = bool(result.is_fact)
        verdict = result.verdict + (" + signed certificate" if got else "")
        self.expect(f"{label:<58} {verdict}", got == want_fact,
                    f"expected {'a confirmed fact' if want_fact else 'NO fact'}, got {result.verdict}")
        if got:
            verified = verify_certificate(result.certificate.signed,
                                          oracle_context=result.oracle_context, trust_root=trust_root)
            print(f"       offline re-verification of the certificate: {'PASS' if verified.ok else 'FAIL'}")
            self.expect("       the signed certificate re-verifies offline", bool(verified.ok))


def _read_token() -> str:
    """The token, from stdin only. Never an argv, never an env var, never a file."""
    if sys.stdin.isatty():
        print("   !! no token on stdin. This harness is driven by secret_github_livefire.sh, which")
        print("      pipes `gh auth token` in. Do not pass a token as an argument.")
        return ""
    return sys.stdin.readline().strip()


def main() -> int:
    from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
    from vigil_integration.live.live_transport import bearer_transport_factory
    from vigil_integration.live.secret_runner import run_secret_validation, secret_fingerprint
    from vigil_integration.live.secret_verify import secret_verify

    token = _read_token()
    if not token:
        return 1

    keypair = generate_keypair()
    signers = [("gov0", keypair.private_key_b64)]
    trust_root = TrustRoot(threshold=1, authorizers=[
        AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=keypair.public_key_b64)])
    runner = _Runner()
    scope = ("github", "self", "", "user")

    def validate(secret: str, **kwargs):
        """One gated run of the production runner against the real provider. The runner closes the
        credential-bearing transport itself once the confirming call returns."""
        return run_secret_validation(
            "github_pat", secret=secret, source="livefire:gh auth token (operator's own credential)",
            authorize=lambda: (True, "authorized owner-test, WARDEN A2 approved"),
            scope_gate=_AllowGate(), scope=scope,
            credential_transport=bearer_transport_factory(), **kwargs)

    # =============================================================================================
    print("\n   -- The FACT: a real credential, the real provider, the production path --")
    # =============================================================================================
    outcome = validate(token)
    if not runner.expect(f"the gated runner reached api.github.com and captured a confirming call "
                         f"({outcome.status})", outcome.status == "captured", outcome.reason):
        print(f"   LIVE-FIRE FAILED: {outcome.reason}")
        return 1

    capture = outcome.capture
    call = capture["confirming_call"]
    print(f"      peer {call['resolved_peer']}  status {call['status']}  "
          f"tls_verified={call['tls_verified']}  no_proxy={call['no_proxy']}  "
          f"no_redirect={call['no_redirect']}")
    print(f"      identity echo: {call['response']}")
    print(f"      identifier retained: {capture['credential']['identifier']!r}   "
          f"secret retained: {capture['credential']['secret']!r}")

    runner.expect("the confirming call really was HTTP 200 from GitHub", call["status"] == 200,
                  f"status was {call['status']}")
    runner.expect("a peer address was recorded from the live socket", bool(call["resolved_peer"]))
    runner.expect("TLS was genuinely verified on that connection", call["tls_verified"] is True)
    runner.expect("no proxy interposed and no redirect was followed",
                  call["no_proxy"] is True and call["no_redirect"] is True)
    runner.expect("the endpoint is GitHub's own /user",
                  call["endpoint"] == "https://api.github.com/user")
    runner.expect("the credential and the confirming call carry the SAME fingerprint",
                  capture["credential"]["credential_fingerprint"] == call["credential_fingerprint"]
                  == secret_fingerprint(token))
    runner.expect("the plaintext token is NOT in the capture", token not in json.dumps(capture))

    result = secret_verify(capture, engagement_slug="livefire", signers=signers)
    runner.check_fact("real GitHub token -> api.github.com  [VALID]", result, True, trust_root)
    runner.expect("the plaintext token is NOT in the retained oracle context",
                  token not in json.dumps(result.oracle_context, default=str))
    if result.is_fact:
        runner.expect("the plaintext token is NOT in the signed certificate",
                      token not in json.dumps(result.certificate.signed, default=str))

    # =============================================================================================
    print("\n   -- Negative control 1: a bogus token, LIVE, to the same real endpoint --")
    # =============================================================================================
    # Correct shape, certainly-invalid body. It was never anyone's credential, so this cannot collide
    # with a real account, and it goes to the genuine provider — a real 401 over the real network.
    bogus = "ghp_" + "0" * 36
    bogus_outcome = validate(bogus)
    if runner.expect(f"the gated runner reached api.github.com with the bogus token "
                     f"({bogus_outcome.status})", bogus_outcome.status == "captured",
                     bogus_outcome.reason):
        bogus_call = bogus_outcome.capture["confirming_call"]
        print(f"      peer {bogus_call['resolved_peer']}  status {bogus_call['status']}  "
              f"identity echo: {bogus_call['response']}")
        runner.expect("GitHub really rejected it (401)", bogus_call["status"] == 401,
                      f"status was {bogus_call['status']}")
        runner.check_fact("bogus token, real 401 from GitHub  [INVALID]",
                          secret_verify(bogus_outcome.capture, engagement_slug="livefire",
                                        signers=signers), False, trust_root)

    # =============================================================================================
    print("\n   -- Negative control 2: the SAME capture, confirming endpoint swapped (laundering) --")
    # =============================================================================================
    laundered = copy.deepcopy(capture)
    laundered["confirming_call"]["endpoint"] = "https://api.attacker.example/user"
    runner.check_fact("real capture, attacker-controlled confirming endpoint",
                      secret_verify(laundered, engagement_slug="livefire", signers=signers),
                      False, trust_root)

    lookalike = copy.deepcopy(capture)
    lookalike["confirming_call"]["endpoint"] = "https://api.github.com.attacker.example/user"
    runner.check_fact("real capture, suffix-confusion lookalike endpoint",
                      secret_verify(lookalike, engagement_slug="livefire", signers=signers),
                      False, trust_root)

    # The runner refuses the same thing one layer earlier, so a live credential never even travels there.
    refused = validate(token, endpoint="https://api.attacker.example/user")
    runner.expect("the runner's exfil floor refuses to send the live token off the allow-list "
                  f"({refused.status})", refused.status == "refused" and refused.capture is None,
                  refused.reason)

    # =============================================================================================
    print("\n   -- Negative control 3: the SAME capture, fingerprints no longer bound --")
    # =============================================================================================
    unbound = copy.deepcopy(capture)
    unbound["confirming_call"]["credential_fingerprint"] = secret_fingerprint("a different secret")
    runner.check_fact("real capture, credential and call fingerprints differ",
                      secret_verify(unbound, engagement_slug="livefire", signers=signers),
                      False, trust_root)

    # =============================================================================================
    print("\n   -- The gates, on the same live path --")
    # =============================================================================================
    warden_refused = run_secret_validation(
        "github_pat", secret=token, source="livefire", authorize=lambda: (False, "kill-switch tripped"),
        scope_gate=_AllowGate(), scope=scope, credential_transport=bearer_transport_factory())
    runner.expect("WARDEN refusal stops the run before any network call",
                  warden_refused.status == "refused" and warden_refused.capture is None,
                  warden_refused.reason)

    scope_refused = run_secret_validation(
        "github_pat", secret=token, source="livefire", authorize=lambda: (True, "ok"),
        scope_gate=_DenyGate(), scope=scope, credential_transport=bearer_transport_factory())
    runner.expect("charter-scope refusal stops the run before any network call",
                  scope_refused.status == "refused" and scope_refused.capture is None,
                  scope_refused.reason)

    print()
    if runner.failures:
        print("   LIVE-FIRE FAILED:")
        for failure in runner.failures:
            print(f"     - {failure}")
        return 1
    print("   All checks held against a real GitHub credential and the real api.github.com.")
    print("   The valid credential was confirmed and its certificate re-verified offline.")
    print("   A bogus token was rejected by GitHub itself and correctly left unconfirmed, and the")
    print("   confirmed capture stopped being a fact the moment its confirming endpoint or its")
    print("   fingerprint binding was tampered with.")
    print("   This proves the github_pat row ONLY. The aws_access_key row is built but unexercised —")
    print("   it needs a real AWS key, and nothing here says anything about it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
