"""remediation.differential_adapter — a SECOND live-HTTP :class:`LiveTargetAdapter` for the boolean-blind
DIFFERENTIAL channel (TRUTHENOVATION R1, PR1).

Where :mod:`live_adapter` (``LiveHttpAdapter``) drives the response-side ``error_signature`` channel, this
adapter drives the boolean-inference channel: per exploit "trial" it builds a **matched-decoy round** from a
``clause_template`` and gated-fetches four probes through the SAME injectable parameter —

    baseline   — a benign value carrying the inert challenge marker, NO exploit metacharacters
    true       — a data-dependent predicate that is TRUE on the live DB, full exploit metacharacters
    false_a    — the SAME predicate made FALSE, metacharacter-IDENTICAL to ``true``
    false_b    — the FALSE predicate with a DIFFERENT inert marker (the dynamic-page control twin)

``true``/``false_a``/``false_b`` are metacharacter-identical in class (all carry ``'`` / ``AND`` / ``SELECT``
/ ``--``), so a content-inspecting WAF that blocks one blocks all — the matched decoy (DIFFERENTIAL-REMEDIATION
§3). They differ only in a **data-dependent predicate** the origin's DB must evaluate, so a *genuine* boolean
firing reflects origin data; the run ``challenge`` rides as an **inert freshness marker only**, NEVER the
discriminating predicate (§3 / §6).

The round is assembled into ``TrialObservation.oracle_context`` in the ``boolean_inference_oracle`` round shape
``{"true": …, "false_a": …, "false_b": …, "baseline": …}``; the driver runs the EXISTING
``boolean_inference_oracle`` (SPRT) over the collected rounds and — for REMEDIATED — the EXISTING
``differential_response_oracle`` WAF-closure test (``baseline`` vs ``false_a`` on ``status``+``structural``,
``expect=same``). This adapter invents no oracle; it arranges probes and computes an informational per-round
closure signal (the driver recomputes closure authoritatively).

FAIL-CLOSED (§4.4 / §8 case 10): if ANY of the four probes is undelivered or malformed, the WHOLE round is
returned ``valid=False`` with a reason, so the driver fails the run closed rather than letting
``boolean_inference_oracle`` silently ``continue`` past a malformed round.

Invariants mirrored from :mod:`live_adapter`:
  * FATAL-2 — every ``framework.v2`` import is function-local; module scope is stdlib + vigil_core only.
  * Determinism — no wallclock / rng. The driver supplies ``challenge``; the two false markers derive from it
    (``_marker_b``); the data-dependent predicate is a fixed ``clause_template``, never RNG.
  * Fail-closed — every error path yields ``reachable=False`` / an invalid round; a firing/silent round is
    NEVER fabricated (the bytes come from the wire or the round is invalid).
  * PR1 freshness — the differential channel is honestly **F1 for both verdicts** (§5): a genuine
    differential-firing F2 verifier is the separately-reviewed PR2.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlencode, urlsplit

from vigil_core import digest_payload   # stdlib+crypto only — FATAL-2 safe at module scope

# prove_driver's module scope is stdlib + vigil_core (+ the framework-free remediation_cert), so importing
# these observation/enum/type shapes here is FATAL-2 safe — no framework is pulled at import time.
from .prove_driver import (
    ControlObservation,
    EffectiveAuthorization,
    Freshness,
    LiveTargetAdapter,
    TrialObservation,
)

# The channel/oracle family this adapter drives. The driver reaches its DIFFERENTIAL branch on this family
# (or the ``differential_channel`` marker below).
_BOOLEAN_INFERENCE_CHANNEL = "boolean_inference"

# The lexical-sensitive boolean discriminator (§4.1: a real injection may change only reflected TEXT, invisible
# to status/structural alone) and the WAF-closure discriminator (§4.2). Kept here as the adapter's declared
# intent; the DRIVER owns the authoritative judgement (it re-runs the oracles under its own discriminators).
_BOOLEAN_DISCRIMINATOR = {"dimensions": ["status", "length", "lexical"]}
_CLOSURE_DISCRIMINATOR = {"dimensions": ["status", "structural"], "expect": "same"}


@dataclass(frozen=True)
class _HttpRequest:
    """The minimal duck-typed shape :meth:`HttpExecutor.gated_fetch` reads (``.method`` / ``.url`` /
    ``.headers`` / ``.body``). Kept local so the adapter never imports the scanner's request model."""

    url: str
    method: str = "GET"
    headers: tuple = ()
    body: Optional[str] = None


@dataclass
class DifferentialHttpAdapter:
    """A live-HTTP :class:`LiveTargetAdapter` for the boolean ``differential`` channel (``boolean_sqli``).

    Required construction inputs:
      * ``executor`` — a constructed CRUCIBLE ``HttpExecutor`` (holds the charter/scope/kill-switch/budget
        gate chain). Every send is a ``gated_fetch``; the adapter never bypasses it.
      * ``base_url`` — the target's scheme+host(:port); the target identity is derived from it.
      * ``endpoint_path`` / ``param`` — the injectable request.
      * ``nonce_param`` — a query param that ALWAYS also carries the run challenge (freshness / liveness).
      * ``base_value`` — the benign value the parameter normally carries (the baseline probe; NO metachars).
      * ``true_payload_template`` / ``false_payload_template`` — the data-dependent TRUE / FALSE predicate
        payloads, each carrying the literal ``{challenge}`` inert-marker slot; metacharacter-identical in class.
      * ``original_firing_rounds`` — RETAINED confirming ``probe_rounds`` (the harness-capability positive
        control: the SAME boolean oracle still CONFIRMS on the known-vulnerable rounds).
    """

    executor: Any
    base_url: str
    endpoint_path: str
    param: str
    nonce_param: str
    base_value: str
    true_payload_template: str
    false_payload_template: str
    original_firing_rounds: list = field(default_factory=list)

    bug_class: str = "boolean_sqli"
    oracle_family: str = _BOOLEAN_INFERENCE_CHANNEL
    oracle_id: str = "oracle:boolean_inference"
    oracle_version: str = "1.0"
    original_probe_recipe_digest: str = ""
    execution_profile_digest: str = ""
    destructive: bool = False
    # The explicit channel marker the driver keys its differential branch on (belt-and-suspenders alongside
    # ``oracle_family == "boolean_inference"``).
    differential_channel: bool = True
    engagement: str = ""

    _host: str = field(init=False, default="")
    _slug: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self._host = urlsplit(self.base_url).hostname or ""
        self._slug = str(self.engagement or getattr(self.executor, "engagement_slug", "") or "")
        # Each metachar payload MUST carry the {challenge} inert-marker slot, else it silently degrades to a
        # payload that cannot thread the freshness marker — fail-closed at construction (mirrors live_adapter).
        for name, tmpl in (("true_payload_template", self.true_payload_template),
                           ("false_payload_template", self.false_payload_template)):
            if "{challenge}" not in tmpl:
                raise ValueError(f"{name} must contain the literal '{{challenge}}' inert-marker slot "
                                 "(the run nonce rides the clause as a marker, never the predicate)")
        if not self.original_probe_recipe_digest:
            self.original_probe_recipe_digest = digest_payload({
                "endpoint_path": self.endpoint_path, "param": self.param, "nonce_param": self.nonce_param,
                "base_value": self.base_value, "true_payload_template": self.true_payload_template,
                "false_payload_template": self.false_payload_template, "bug_class": self.bug_class,
                "channel": _BOOLEAN_INFERENCE_CHANNEL, "method": "GET"})

    # ---- identity (mirrors live_adapter's gated-probe + optional TLS-SPKI binding) -----------------
    def identity_sample(self) -> dict:
        """Return the target's OBSERVED identity. A GATE refusal RAISES (the driver → REFUSED); a pure
        transport failure does NOT raise (a down target is an INCONCLUSIVE unreachable trial, not a refusal).
        For HTTPS the sample STRENGTHENS to the observed leaf-key SPKI. Never fabricates. FATAL-2: the TLS
        capture import is function-local."""
        try:
            resp = self.executor.gated_fetch(_HttpRequest(url=self.base_url, method="GET"))
        except Exception as exc:  # noqa: BLE001 — an executor crash is a genuine "cannot sample" (fail-closed)
            raise RuntimeError(f"identity sample failed: {exc}") from exc
        note = str((resp or {}).get("refused") or "")
        if "REFUSED:" in note:
            raise RuntimeError(f"identity sample refused by gate: {note}")
        sample = {"host": self._host}
        split = urlsplit(self.base_url)
        if (split.scheme or "").lower() == "https" and self._host:
            spki = self._observed_tls_spki(split)   # may RAISE on a GATE refusal (unauthorized active probe)
            if spki:
                sample["tls_spki_sha256"] = spki
        return sample

    def _observed_tls_spki(self, split) -> str:
        from framework.v2.verify.tls import capture_tls_handshake   # lazy — FATAL-2
        port = split.port or 443
        tls = capture_tls_handshake(self._host, int(port), slug=self._slug)
        if tls.get("connected"):
            return str(tls.get("spki_sha256") or "")
        err = str(tls.get("error") or "")
        if not self._looks_like_transport_failure(err):
            raise RuntimeError(f"identity sample TLS handshake refused by gate: {err}")
        return ""

    @staticmethod
    def _looks_like_transport_failure(err: str) -> bool:
        head = err.split(":", 1)[0].strip()
        return bool(head) and " " not in head

    # ---- positive control: a LIVE benign probe + the RETAINED confirming rounds --------------------
    def run_positive_control(self, *, challenge: str, auth: EffectiveAuthorization) -> ControlObservation:
        """Two jobs (kept separate and honest):
          1. HARNESS CAPABILITY — return the RETAINED confirming ``probe_rounds`` so the driver confirms the
             SAME boolean oracle STILL CONFIRMS on the known-vulnerable rounds (a live refute is then not a
             harness artefact). The driver independently re-fires the oracle over this context.
          2. LIVE CHANNEL — a REAL gated fetch this run of a BENIGN, challenge-bearing marker through the SAME
             injectable ``param``, proving the channel is exercised live NOW.
        A gate refusal RAISES (driver → INCONCLUSIVE/COLLECTOR_FAILED); a pure transport failure →
        ``reachable=False`` (driver → INCONCLUSIVE/TARGET_UNAVAILABLE). Never a fabricated live channel."""
        marker = f"vfctl{challenge}"
        req = _HttpRequest(url=self._probe_url(marker, challenge), method="GET")
        try:
            resp = self.executor.gated_fetch(req)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"positive control live probe failed: {exc}") from exc
        note = str((resp or {}).get("refused") or "")
        if "REFUSED:" in note:
            raise RuntimeError(f"positive control refused by gate: {note}")
        status = (resp or {}).get("status")
        if status in (0, None):
            return ControlObservation(
                reachable=False, channel_alive=False, oracle_context=self._firing_context(),
                definition_digest=self.original_probe_recipe_digest,
                detail=f"live control not answered: {note or status}")
        body = str((resp or {}).get("body") or "")
        return ControlObservation(
            reachable=True, channel_alive=True, oracle_context=self._firing_context(),
            freshness_level=Freshness.F0_NONCE_GENERATED,
            definition_digest=self.original_probe_recipe_digest,
            injectable_param_live=(marker in body),
            detail="live differential positive control: channel alive this run; harness capability from "
                   "retained confirming rounds")

    def _firing_context(self) -> dict:
        """The RETAINED confirming boolean ``FindingContext`` shape the driver re-fires ``boolean_inference_
        oracle`` over via the ORIGINAL oracle (harness capability). ``probe_rounds`` are the known-vulnerable
        rounds recorded when the finding was first confirmed."""
        return {"bug_class": self.bug_class, "probe_rounds": [dict(r) for r in self.original_firing_rounds],
                "discriminator": dict(_BOOLEAN_DISCRIMINATOR)}

    # ---- exploit trial: build + gated-fetch the matched-decoy round --------------------------------
    def run_exploit_trial(self, *, challenge: str, trial_index: int,
                          auth: EffectiveAuthorization) -> TrialObservation:
        """Build the four matched-decoy probes from the ``clause_template``, gated-fetch each through the
        injectable ``param``, and assemble the ``boolean_inference_oracle`` round. FAIL-CLOSED: any probe that
        is undelivered (gate refusal / transport failure / empty status) makes the WHOLE round ``valid=False``
        so the driver fails the run closed (never a silently-dropped probe)."""
        marker_b = self._marker_b(challenge)
        probes = {
            "baseline": self._baseline_value(challenge),
            "true": self.true_payload_template.replace("{challenge}", challenge),
            "false_a": self.false_payload_template.replace("{challenge}", challenge),
            "false_b": self.false_payload_template.replace("{challenge}", marker_b),
        }
        responses: dict[str, dict] = {}
        for name, value in probes.items():
            req = _HttpRequest(url=self._probe_url(value, challenge), method="GET")
            try:
                resp = self.executor.gated_fetch(req)
            except Exception as exc:  # noqa: BLE001 — a transport/executor crash → the round is invalid
                return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                        invalid_reason=f"{name} probe send crashed: {exc}",
                                        detail=f"{name} probe send crashed")
            status = (resp or {}).get("status")
            if status in (0, None):
                # A gate refusal or transport failure on ANY of the four probes makes the matched decoy
                # uninterpretable — fail the whole round closed (§4.4), never partial.
                return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                        invalid_reason=f"{name} probe not answered: "
                                                       f"{str((resp or {}).get('refused') or status)}",
                                        detail=f"{name} probe not answered")
            responses[name] = {"status": int(status), "body": str((resp or {}).get("body") or "")}

        round_ctx: dict[str, Any] = {
            "true": responses["true"], "false_a": responses["false_a"],
            "false_b": responses["false_b"], "baseline": responses["baseline"],
        }
        # Informational adapter-side WAF-closure (the DRIVER recomputes it authoritatively over the round).
        from framework.v2.verify.oracles import differential_response_oracle   # lazy — FATAL-2
        round_ctx["waf_closed"] = bool(differential_response_oracle(
            responses["baseline"], responses["false_a"], dict(_CLOSURE_DISCRIMINATOR)).fired)
        # Live-marker reflection (§4 / LOW-1): the inert challenge marker must come back on the un-WAF'd
        # baseline (a query-stripping cache / non-echoing edge that serves one body for all probes fails this).
        echoed = challenge in responses["baseline"]["body"] or challenge in responses["false_a"]["body"]
        return TrialObservation(reachable=True, valid=True, oracle_context=round_ctx,
                                freshness_level=Freshness.F1_TARGET_ECHOES, nonce_echoed=echoed,
                                detail=f"differential round {trial_index}: 4/4 matched-decoy probes delivered")

    # ---- helpers -----------------------------------------------------------------------------------
    @staticmethod
    def _marker_b(challenge: str) -> str:
        """A SECOND inert marker for ``false_b``, derived DETERMINISTICALLY from the challenge (no RNG), so
        ``false_a``/``false_b`` differ ONLY in the inert marker while staying metacharacter-identical."""
        return f"{challenge}~b"

    def _baseline_value(self, challenge: str) -> str:
        """The benign baseline value carrying the inert challenge marker and NO exploit metacharacters."""
        return f"{self.base_value}{challenge}"

    def _probe_url(self, value: str, challenge: str) -> str:
        """The probe URL: the injectable ``param`` carries ``value``; the separate ``nonce_param`` ALWAYS
        carries the challenge (freshness / liveness). ``urlencode`` preserves special chars over the wire.
        Deterministic (sorted params, no wallclock/rng)."""
        base = self.base_url.rstrip("/")
        path = "/" + self.endpoint_path.lstrip("/")
        query = urlencode(sorted({self.param: value, self.nonce_param: challenge}.items()))
        return f"{base}{path}?{query}"


# Structural conformance: assert DifferentialHttpAdapter satisfies the LiveTargetAdapter protocol at import
# time (a runtime_checkable Protocol check catches attribute/method drift here rather than at first drive).
def _assert_conforms() -> None:
    probe = DifferentialHttpAdapter(
        executor=None, base_url="http://127.0.0.1/", endpoint_path="/", param="q", nonce_param="rc",
        base_value="1", true_payload_template="1' AND SUBSTR(@@version,1,1)>'' -- {challenge}",
        false_payload_template="1' AND SUBSTR(@@version,1,1)>'~~~' -- {challenge}")
    assert isinstance(probe, LiveTargetAdapter)


_assert_conforms()
