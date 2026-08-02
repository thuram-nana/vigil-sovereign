"""remediation.live_adapter — a REAL live-HTTP re-drive adapter behind :class:`LiveTargetAdapter` (VF-1a.2).

:mod:`prove_driver` is a pure four-state protocol orchestrator over an INJECTED :class:`LiveTargetAdapter`;
:mod:`test_prove_driver` exercises the whole state machine offline against a fake. This module is the FIRST
real adapter: it re-drives the ORIGINAL exploit against a live, authorized target through CRUCIBLE's gated
:class:`HttpExecutor` (charter/scope/kill-switch/budget/rate-limit), captures the fresh response bytes, and
turns them into the exact ``oracle_context`` the ORIGINAL oracle re-fires over — so the driver's REMEDIATED /
STILL_VULNERABLE / INCONCLUSIVE / REFUSED verdict is earned over FRESH evidence, not the retained finding.

Scope of this slice: the response-side ``error_signature`` channel (``error_based_sqli``). A general
multi-channel adapter (differential, boolean, evaluation, …) is a documented follow-up.

The freshness split this adapter implements, stated plainly and HONESTLY (it is the load-bearing soundness
argument, and its LIMIT is disclosed — never overclaimed). VF-1a.3 adds a LIVE positive control and genuine F2
for the firing case, but the F2 story is asymmetric between the two verdicts and the asymmetry is FUNDAMENTAL:

  * the POSITIVE CONTROL is now a LIVE gated fetch this run (VF-1a.3): it sends a benign, challenge-bearing
    marker through the SAME injectable ``param`` and confirms the target answered THIS run — so the control
    genuinely exercises the live channel now, instead of asserting a live channel from RETAINED bytes (the old
    control's honesty gap). It still returns the RETAINED original firing ``oracle_context`` for the driver's
    harness-capability check (the SAME oracle still FIRES on the known-vulnerable bytes, so a live silence is not
    a harness artefact). If the marker is reflected it records ``injectable_param_live`` as an INFORMATIONAL
    signal — but reflection could come from the app OR an interposing edge that echoes the request, so it does
    NOT distinguish them and does NOT close the param-stripping-edge case (that discriminator is deferred).
  * **Genuine F2 for the STILL_VULNERABLE (firing) case.** When constructed with a ``payload_template`` (a slot
    ``{challenge}`` in the exploit payload), each trial carries the fresh ``challenge`` THROUGH the exploit
    payload. If the original oracle FIRES and the fresh challenge is reflected IN the matched datastore-error
    LINE (e.g. ``... near '~<challenge>' ...``), the driver credits **F2**: the nonce came back through the SAME
    error channel the firing signal did — as attributable as the error_signature oracle's own firing. This is
    NOT byte-unforgeable: a target that FABRICATES a matching error embedding the nonce is indistinguishable on
    the response channel (the deferred OOB/zkTLS frontier; the OOB Tier-2 is the unforgeable channel). A target
    that emits a STATIC error banner and reflects the input on a DIFFERENT line does NOT earn F2 (capped to F1).
  * **F2 is FUNDAMENTALLY unattainable for the REMEDIATED (silent) case, and this adapter never fakes it.** A
    fixed sink produces no signature, so a silent response can contain the challenge only by REFLECTION — which
    an echoing app or an interposing edge can produce without the sink. The driver therefore caps a SILENT
    trial at **F1 (the target answered, and echoed the challenge, THIS run)** regardless of reflection, and a
    genuine remediation is reported at F1. A verifier that sets ``policy.minimum_freshness_level >= F2`` for a
    remediation gets INCONCLUSIVE — honest, because sink-traversal is unprovable once the sink is removed.
  * **HONEST LIMITS (the residuals for the silent case, disclosed not hidden):** the F1 remediation does not
    distinguish (a) a payload-discriminating WAF (blocks the exploit's metacharacters while passing a benign
    request), nor (b) a param-stripping edge in front of a reflecting/echoing gateway, from a real fix. Ruling
    those out needs a matched-decoy differential (a metachar-identical-but-semantically-null control) or the OOB
    Tier-2, both deferred. This adapter makes the control genuinely LIVE and delivers genuine F2 where it is
    sound (firing), and refuses to over-claim F2 or interposition-closure where it is not (silent).

Invariants honoured here (mirroring prove_driver / remediation_cert):
  * FATAL-2 — every ``framework.v2`` import is function-local; module scope is stdlib + vigil_core (via the
    import-clean :mod:`prove_driver` types) only.
  * Determinism — no wallclock / rng in this adapter. The driver supplies ``now`` / ``run_id`` / the nonces;
    the ``challenge`` is passed in per call. The only I/O is the gated HTTP send.
  * Fail-closed — every error path yields ``reachable=False`` / a raised identity sample; a firing or silent
    context is NEVER fabricated (the bytes come from the wire or not at all).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

from vigil_core import digest_payload   # stdlib+crypto only — FATAL-2 safe at module scope

# prove_driver's module scope is stdlib + vigil_core (+ remediation_cert, also framework-free), so importing
# these observation/enum/type shapes here is FATAL-2 safe — no framework is pulled at import time.
from .prove_driver import (
    ControlObservation,
    EffectiveAuthorization,
    Freshness,
    LiveTargetAdapter,
    TrialObservation,
)

# The channel/oracle family this slice drives. A response-side, deterministic-per-observation error signature.
_ERROR_SIGNATURE_CHANNEL = "error_signature"


@dataclass(frozen=True)
class _HttpRequest:
    """The minimal duck-typed shape :meth:`HttpExecutor.gated_fetch` reads (``.method`` / ``.url`` /
    ``.headers`` / ``.body``). Kept local so the adapter never imports the scanner's request model."""

    url: str
    method: str = "GET"
    headers: tuple = ()
    body: Optional[str] = None


@dataclass
class LiveHttpAdapter:
    """A live-HTTP :class:`LiveTargetAdapter` for the ``error_signature`` / ``error_based_sqli`` channel.

    Re-drives the original exploit (``endpoint_path`` with ``param`` = ``payload``) through the gated
    ``executor`` and adjudicates the FRESH response with the original oracle, while carrying the driver's
    per-run ``challenge`` in ``nonce_param`` (echoed by the target) to establish freshness.

    Required construction inputs:
      * ``executor`` — a constructed CRUCIBLE ``HttpExecutor`` (holds the charter/scope/kill-switch/budget
        gate chain). The adapter never bypasses it: every send is a ``gated_fetch``.
      * ``base_url`` — the target's scheme+host(:port); the target identity is derived from it.
      * ``endpoint_path`` / ``param`` / ``payload`` — the original exploit request.
      * ``nonce_param`` — the query param the target echoes (freshness).
      * ``original_firing_context`` — the RETAINED original firing ``oracle_context`` (the positive control).

    Oracle/finding metadata (``bug_class`` / ``oracle_*`` / digests / ``destructive``) rides on the cert.
    """

    executor: Any
    base_url: str
    endpoint_path: str
    param: str
    payload: str
    nonce_param: str
    original_firing_context: dict
    # VF-1a.3 — optional exploit-payload template carrying the run challenge THROUGH the injectable param, so a
    # FIRING trial's oracle-judged bytes embed the challenge (genuine F2, sink-traversed). MUST contain the
    # literal ``{challenge}`` slot; when unset the adapter falls back to the F1 behaviour (payload verbatim, the
    # challenge only on the separate ``nonce_param``). The template NEVER changes the exploit's semantics — it
    # only threads the nonce into a data position the vulnerable sink reflects (e.g. an extractvalue marker).
    payload_template: str = ""
    bug_class: str = "error_based_sqli"
    oracle_family: str = _ERROR_SIGNATURE_CHANNEL
    oracle_id: str = "oracle:error_signature"
    oracle_version: str = "1.0"
    original_probe_recipe_digest: str = ""
    execution_profile_digest: str = ""
    destructive: bool = False
    # The engagement/charter slug the gated TLS handshake runs under (VF-2c). Optional: when unset it falls
    # back to the executor's own ``engagement_slug`` (the adapter already holds the executor), so a normally
    # constructed adapter needs no extra wiring — the handshake authorizes against the SAME charter as the
    # HTTP re-drive.
    engagement: str = ""

    _host: str = field(init=False, default="")
    _slug: str = field(init=False, default="")

    def __post_init__(self) -> None:
        # The identity of the target for the policy match + the F0 target-identity digest. Host is derived from
        # the authorized base_url (a config fact); for HTTPS, identity_sample STRENGTHENS this with the OBSERVED
        # leaf-key SPKI (a real probe of the key the target presents) — see identity_sample's docstring.
        self._host = urlsplit(self.base_url).hostname or ""
        # Slug for the gated TLS handshake: an explicit ``engagement`` wins; otherwise reuse the executor's.
        self._slug = str(self.engagement or getattr(self.executor, "engagement_slug", "") or "")
        # A payload_template MUST carry the {challenge} slot, else it silently degrades to an F1 payload while
        # claiming F2 — fail-closed at construction rather than mint a falsely-strong freshness claim later.
        if self.payload_template and "{challenge}" not in self.payload_template:
            raise ValueError("payload_template must contain the literal '{challenge}' slot (F2 requires the "
                             "run nonce to ride the exploit payload); leave it empty for F1 behaviour")
        # Bind the ACTUALLY re-driven probe into the cert (N4): if the caller did not supply a probe digest,
        # derive one over the concrete re-drive spec (endpoint/param/payload/nonce_param/bug_class) so the
        # signed "fixed" verdict attests WHICH exploit request was re-driven. Honest-producer tier: this binds
        # the probe THIS adapter sends; cryptographically tying it back to the ORIGINAL finding's probe (vs a
        # malicious producer swapping in a benign payload) stays the deferred frontier, stated in the docstring.
        if not self.original_probe_recipe_digest:
            self.original_probe_recipe_digest = digest_payload({
                "endpoint_path": self.endpoint_path, "param": self.param, "payload": self.payload,
                "nonce_param": self.nonce_param, "payload_template": self.payload_template,
                "bug_class": self.bug_class, "method": "GET"})

    # ---- identity ----------------------------------------------------------------------------------
    def identity_sample(self) -> dict:
        """Return the target's OBSERVED identity. Best-effort issues one gated base request so an
        authorization/scope failure is surfaced early: a GATE REFUSAL (not authorized to even probe this host)
        RAISES — the driver maps that to a REFUSED / TARGET_UNAVAILABLE disposition. A pure transport failure
        (the app is simply DOWN) does NOT raise: identity ("who this host is") is a policy fact, while liveness
        ("did it answer THIS run") is established by the exploit trials — so a down target surfaces as an
        INCONCLUSIVE unreachable trial, not a refusal to test. Never fabricates.

        Identity strength (VF-2c). For an HTTPS target this binds to the target's OBSERVED TLS
        SubjectPublicKeyInfo — the sha256 of the ACTUAL public key the endpoint presented on the wire —
        returned ALONGSIDE ``host`` as ``tls_spki_sha256``. That is a PARTIAL anti-transplant property, stated
        honestly with its limit:

          * WHAT IT BUYS — the owner's ``IdentityAttestation`` policy pins the acceptable SPKI(s), so a
            *different* target (one presenting a different leaf key) fails ``identity_matches`` and is REFUSED.
            A REMEDIATED verdict earned against key K therefore cannot be transplanted onto a target presenting
            key K' — the cert binds to the observed key, not a producer-asserted host string.
          * WHAT IT IS NOT — it is not full byte-authenticity of the exchange. It proves which KEY answered the
            handshake, NOT that the response bytes the oracle judged were produced/signed by the holder of that
            key (a channel-binding / signed-transcript step is the deferred stronger frontier).

        For an HTTP target, or when the gated handshake refuses/fails at the TRANSPORT layer, the sample is
        host-only (``{"host": ...}``) — an honest weaker binding; an SPKI is NEVER fabricated. A GATE refusal
        on the handshake (no slug, out of charter scope, ACTIVE_RECON not entitled, kill-switch) still RAISES.
        """
        try:
            resp = self.executor.gated_fetch(_HttpRequest(url=self.base_url, method="GET"))
        except Exception as exc:  # noqa: BLE001 — an executor crash is a genuine "cannot sample" (fail-closed)
            raise RuntimeError(f"identity sample failed: {exc}") from exc
        note = str((resp or {}).get("refused") or "")
        # A GATE refusal (charter/scope/kill-switch/authority) is stamped "REFUSED:" by the executor; a
        # transport error is stamped with the exception type ("httpx.…"). Only the former is a "cannot test".
        if "REFUSED:" in note:
            raise RuntimeError(f"identity sample refused by gate: {note}")
        sample = {"host": self._host}
        # STRONGER binding for HTTPS: the sha256 of the OBSERVED leaf-key SPKI, from a gated TLS handshake.
        split = urlsplit(self.base_url)
        if (split.scheme or "").lower() == "https" and self._host:
            spki = self._observed_tls_spki(split)   # may RAISE on a GATE refusal (unauthorized active probe)
            if spki:
                sample["tls_spki_sha256"] = spki
        return sample

    def _observed_tls_spki(self, split) -> str:
        """Perform the SAME audited, bounded TLS handshake ``verify.reachability`` uses (kill-switch ->
        single-host -> ACTIVE_RECON -> charter scope, engagement slug required) and return the sha256 of the
        presented leaf-key SPKI, or "" on a pure transport failure (target DOWN / handshake reset → honest
        host-only binding). A GATE refusal RAISES so an unauthorized target is REFUSED, not silently
        downgraded to a host-only pin. Framework import is function-local (FATAL-2)."""
        from framework.v2.verify.tls import capture_tls_handshake   # lazy — FATAL-2
        port = split.port or 443
        tls = capture_tls_handshake(self._host, int(port), slug=self._slug)
        if tls.get("connected"):
            return str(tls.get("spki_sha256") or "")
        err = str(tls.get("error") or "")
        if not self._looks_like_transport_failure(err):
            raise RuntimeError(f"identity sample TLS handshake refused by gate: {err}")
        return ""   # a genuine transport failure → the weaker host-only binding (honest, never fabricated)

    @staticmethod
    def _looks_like_transport_failure(err: str) -> bool:
        """Classify a ``capture_tls_handshake`` refusal string WITHOUT importing the gate internals. A CONNECT
        failure is formatted there as ``"<ExceptionType>: <msg>"`` — a single whitespace-free token before the
        first ': '. Every GATE refusal from ``reachability._authorize`` is an English phrase (spaces before any
        colon, or no colon at all). Fail-closed: anything not clearly transport-shaped is treated as a gate
        refusal (so the caller RAISES rather than silently pinning host-only)."""
        head = err.split(":", 1)[0].strip()
        return bool(head) and " " not in head

    # ---- positive control (VF-1a.3: a LIVE probe, not just retained bytes) ------------------------
    def run_positive_control(self, *, challenge: str, auth: EffectiveAuthorization) -> ControlObservation:
        """The positive-control twin (VF-1a.3). Two jobs, kept separate and honest:

          1. HARNESS CAPABILITY (unchanged): return the RETAINED original firing ``oracle_context`` so the
             driver confirms the SAME oracle STILL FIRES on the known-vulnerable bytes — a live silence is then
             not a harness artefact. The driver independently re-fires the oracle over this context.
          2. LIVE CHANNEL (new): issue a REAL gated fetch this run, sending a BENIGN, challenge-bearing marker
             through the SAME injectable ``param``. If the target answers, the observation channel is exercised
             live NOW (``channel_alive``) rather than assumed from retained bytes. If the marker is reflected,
             record ``injectable_param_live`` — an INFORMATIONAL signal only (reflection could be the app OR an
             echoing edge; it does not distinguish them, see the honest limit below).

        Host-level authorization is already enforced by ``identity_sample`` (which runs first and maps a gate
        REFUSAL → REFUSED). A gate refusal on THIS narrower control probe RAISES and is caught by the driver as
        INCONCLUSIVE/COLLECTOR_FAILED (testing began, this probe was refused); a pure transport failure (target
        DOWN) → ``reachable=False`` → the driver's INCONCLUSIVE/TARGET_UNAVAILABLE. Never a fabricated live
        channel. The marker is deliberately benign (no exploit metacharacters) so it is NOT the vuln.

        HONEST LIMITS (documented at their true boundary): a live control does NOT rule out (a) a
        payload-discriminating WAF that passes this benign marker while blocking the exploit's metacharacters
        (the exploit is then silent because blocked, not fixed), nor (b) a param-stripping edge fronting a
        request-echoing gateway (``injectable_param_live`` would be True from the edge's echo, not the app).
        Both residuals (silent case) need a matched-decoy differential or the OOB Tier-2, both deferred. This
        control's sound contribution is that it is genuinely LIVE — it does not claim to close interposition.
        """
        # The benign live marker: the run challenge with a fixed, metacharacter-free prefix so it is trivially
        # distinguishable in the body AND cannot itself be an injection. It rides the SAME injectable param.
        marker = f"vfctl{challenge}"
        req = _HttpRequest(url=self._control_url(marker), method="GET")
        try:
            resp = self.executor.gated_fetch(req)
        except Exception as exc:  # noqa: BLE001 — an executor crash is a genuine "cannot run the control"
            raise RuntimeError(f"positive control live probe failed: {exc}") from exc
        note = str((resp or {}).get("refused") or "")
        if "REFUSED:" in note:
            raise RuntimeError(f"positive control refused by gate: {note}")
        status = (resp or {}).get("status")
        if status in (0, None):
            # The target did not answer the live control this run: the channel is NOT proven live. Fail-closed —
            # the driver maps an unreachable control to INCONCLUSIVE/TARGET_UNAVAILABLE, never a fixed claim.
            return ControlObservation(
                reachable=False, channel_alive=False,
                oracle_context=dict(self.original_firing_context),
                definition_digest=self.original_probe_recipe_digest,
                detail=f"live control not answered: {note or status}")
        body = str((resp or {}).get("body") or "")
        param_live = marker in body            # the app reflected the benign marker → injectable param reached it
        return ControlObservation(
            reachable=True,
            channel_alive=True,                # the target answered the live control THIS run
            oracle_context=dict(self.original_firing_context),   # harness-capability check runs over this
            freshness_level=Freshness.F0_NONCE_GENERATED,        # a control never sources run freshness (F2 is trials-only)
            definition_digest=self.original_probe_recipe_digest,
            injectable_param_live=param_live,
            detail=("live positive control: channel alive this run; injectable-param marker "
                    f"{'reflected (app OR edge — informational)' if param_live else 'not reflected'}"
                    " — harness capability from retained firing bytes"),
        )

    # ---- exploit trial (the live re-drive) --------------------------------------------------------
    def run_exploit_trial(self, *, challenge: str, trial_index: int,
                          auth: EffectiveAuthorization) -> TrialObservation:
        """Re-drive the ORIGINAL exploit over the live target and return the FRESH observation. Builds the
        mutated request (``param`` = ``payload`` AND ``nonce_param`` = ``challenge``), gated-fetches it,
        turns the response body into an ``error_signature`` ``oracle_context`` (the exact context the
        original oracle re-fires over), and reports freshness from whether the target echoed the challenge
        into the JUDGED bytes. Any refusal/exception ⇒ ``reachable=False`` (the driver → INCONCLUSIVE);
        never fabricates a firing/silent context.
        """
        req = _HttpRequest(url=self._exploit_url(challenge), method="GET")
        try:
            resp = self.executor.gated_fetch(req)
        except Exception as exc:  # noqa: BLE001 — a transport/executor crash is an unreachable trial
            return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                    detail=f"trial send crashed: {exc}")
        status = (resp or {}).get("status")
        # status 0 covers BOTH a gate refusal and a transport failure — either way the target did not answer
        # this trial: report unreachable (the driver classifies it INCONCLUSIVE / TARGET_UNAVAILABLE).
        if status in (0, None):
            return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                    detail=f"trial not answered: {str((resp or {}).get('refused') or status)}")

        body = str((resp or {}).get("body") or "")
        ctx = self._context_from_body(body)
        if ctx is None:
            # The bytes could not be turned into a judgeable context — recorded but not counted (fail-closed:
            # never claim a silent/firing context we could not build).
            return TrialObservation(reachable=True, valid=False, oracle_context=None,
                                    detail="could not build oracle_context from the captured body")

        echoed = challenge in body
        # The adapter CLAIMS a freshness level; the driver CAPS it by what it can verify. With a
        # ``payload_template`` (VF-1a.3) the challenge rides the EXPLOIT payload; the driver credits F2 only when
        # the trial FIRES and the challenge is reflected IN the matched datastore-error line (came back through
        # the sink's own channel). Without a template the challenge is only on the separate ``nonce_param`` → F1
        # (the target is responsive this run). Either way the driver caps a SILENT trial at F1 — reflection can
        # never prove a REMOVED sink was traversed (an echoing app/edge would fake it) — so F2 is exclusive to a
        # firing trial, and a remediation is honestly reported at F1 (see module docstring).
        if not echoed:
            level = Freshness.F0_NONCE_GENERATED
        elif self.payload_template:
            level = Freshness.F2_PATH_TRAVERSED
        else:
            level = Freshness.F1_TARGET_ECHOES
        return TrialObservation(reachable=True, valid=True, oracle_context=ctx,
                                freshness_level=level, nonce_echoed=echoed,
                                detail=(f"live re-drive: status={status} echoed={echoed} claim=F{level} "
                                        f"template={'yes' if self.payload_template else 'no'}"))

    # ---- helpers ----------------------------------------------------------------------------------
    def _exploit_url(self, challenge: str) -> str:
        """The mutated exploit URL. The injectable ``param`` carries the exploit payload — with a
        ``payload_template`` the run ``challenge`` is woven INTO the payload (F2: nonce through the exploit path);
        otherwise the payload verbatim (F1). The separate ``nonce_param`` ALWAYS also carries the challenge, so a
        SILENT (patched) target — whose fixed sink would NOT reflect a payload-borne challenge — still echoes it,
        letting the driver establish liveness for the remediation case. ``urlencode`` preserves the payload's
        special chars over the wire (the target decodes them back). Deterministic (sorted params, no
        wallclock/rng)."""
        base = self.base_url.rstrip("/")
        path = "/" + self.endpoint_path.lstrip("/")
        # str.replace, NOT str.format: a real exploit payload may contain literal braces (JSON, ${...}); format()
        # would raise/misparse them. replace substitutes ONLY the {challenge} slot the __post_init__ check requires.
        param_value = (self.payload_template.replace("{challenge}", challenge)
                       if self.payload_template else self.payload)
        query = urlencode(sorted({self.param: param_value, self.nonce_param: challenge}.items()))
        return f"{base}{path}?{query}"

    def _control_url(self, marker: str) -> str:
        """The benign live positive-control URL (VF-1a.3): the injectable ``param`` carries a benign,
        metacharacter-free MARKER — proving the injectable parameter reaches the app WITHOUT being an injection.
        Deterministic (single sorted param, no wallclock/rng)."""
        base = self.base_url.rstrip("/")
        path = "/" + self.endpoint_path.lstrip("/")
        query = urlencode({self.param: marker})
        return f"{base}{path}?{query}"

    def _context_from_body(self, body: str) -> Optional[dict]:
        """Turn a captured response body into the ``error_signature`` ``oracle_context`` the ORIGINAL oracle
        re-fires over — the SAME translator the base RemediationCertificate uses. Returns None (fail-closed)
        if the capture cannot be reshaped. Framework imports are function-local (FATAL-2)."""
        from framework.v2.evidence.poc import CapturedExchange          # lazy — FATAL-2
        from framework.v2.verify.poc_translate import context_from_exchanges

        body_bytes = body.encode("utf-8", errors="replace")
        ex = CapturedExchange(channel=_ERROR_SIGNATURE_CHANNEL, role="mutated", response_bytes_ref="resp")
        ctx = context_from_exchanges([ex], bug_class=self.bug_class, resolve=lambda _ref: body_bytes)
        if ctx is None:
            return None
        return ctx.model_dump(mode="json")


# Structural conformance: assert LiveHttpAdapter satisfies the LiveTargetAdapter protocol at import time
# (a runtime_checkable Protocol check catches attribute/method drift here rather than at first drive).
def _assert_conforms() -> None:
    # A cheap, side-effect-free instance purely for the isinstance check (no executor call is made).
    probe = LiveHttpAdapter(executor=None, base_url="http://127.0.0.1/", endpoint_path="/", param="q",
                            payload="x", nonce_param="rc", original_firing_context={"bug_class": "error_based_sqli"})
    assert isinstance(probe, LiveTargetAdapter)


_assert_conforms()
