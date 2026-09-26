"""remediation.differential_adapter — a SECOND live-HTTP :class:`LiveTargetAdapter` for the boolean-blind
DIFFERENTIAL channel (TRUTHENOVATION R1, PR1).

Where :mod:`live_adapter` (``LiveHttpAdapter``) drives the response-side ``error_signature`` channel, this
adapter drives the boolean-inference channel: per exploit "trial" it builds a **matched-decoy TRUTH-VALUE
ATTRIBUTION round** and gated-fetches ``1 + 2*K_T + 2*K_F`` probes through the SAME injectable parameter —

    baseline       — a benign value carrying the inert challenge marker, NO exploit metacharacters
    trues[i]       — K_T DISTINCT, syntactically-VARIED data-dependent predicates that are all TRUE on the
                     live DB, full exploit metacharacters
    falses[j]      — K_F DISTINCT, varied predicates that are all FALSE, metacharacter-identical in class
    *_repeats      — a byte-IDENTICAL repeat of EVERY one of those clauses (the determinism control: an
                     origin that varies to identical input hard-refutes the whole run)

Why more than one clause per truth value: "the true probe came back different from the false probe" is a
2-sample coincidence on any origin whose body varies INDEPENDENTLY of the input (rotating banner, A/B bucket,
two replicas), and a determinism SCREEN does not remove it — a window that looks deterministic still contains
the coincidence. The oracle therefore signals a round only when the response is a **function of the injected
boolean's TRUTH VALUE**: every TRUE-side response agrees with every other, every FALSE-side response agrees
with every other, and the two clusters are disjoint. An origin drawing INDEPENDENTLY per request must land
all ``2*K_T`` true-side draws on one variant and all ``2*K_F`` false-side draws on another —
``<= 2 * 2**-(2*K_T+2*K_F)`` per round (``3.1e-5`` at the ``K_T = K_F = 4`` floor, vs the SPRT's
``p0 = 0.1``). The oracle's docstring states the two cases that bound does NOT cover: a truth-correlated
LEXICAL filter (beaten by clause-SHAPE diversity, not by K) and a per-URL-CACHING origin (where the repeats
are cache hits and the bound degrades to ``2 * 2**-(K_T+K_F)``).

Every clause is metacharacter-identical in class (all carry ``'`` / ``AND`` / ``SELECT`` / ``--``), so a
content-inspecting WAF that blocks one blocks all — the matched decoy (DIFFERENTIAL-REMEDIATION §3). They
differ only in a **data-dependent predicate** the origin's DB must evaluate, so a *genuine* boolean firing
reflects origin data; the run ``challenge`` rides as an **inert freshness marker only**, NEVER the
discriminating predicate (§3 / §6).

The round is assembled into ``TrialObservation.oracle_context`` in the ``boolean_inference_oracle`` round shape
``{"trues": […], "falses": […], "true_repeats": […], "false_repeats": […], "baseline": …}``; the driver runs
the EXISTING ``boolean_inference_oracle`` (SPRT) over the collected rounds and — for REMEDIATED — the EXISTING
``differential_response_oracle`` WAF-closure test (``baseline`` vs each ``falses[j]`` on ``status``+
``structural``, ``expect=same``). This adapter invents no oracle; it arranges probes and computes an
informational per-round closure signal (the driver recomputes closure authoritatively).

FAIL-CLOSED (§4.4 / §8 case 10): if ANY probe of the round is undelivered or malformed, the WHOLE round is
returned ``valid=False`` with a reason, so the driver fails the run closed rather than letting
``boolean_inference_oracle`` silently ``continue`` past a malformed round.

CALLER OBLIGATION — EXECUTOR BUDGET. A round is ``1 + 2*K_T + 2*K_F`` gated fetches (17 at the shipped
``K_T = K_F = 4``), so a run needs ``min_valid_trials * 17`` for the EDGE leg, the same again when the R2
direct-to-origin re-drive is configured, plus the positive control. The ``HttpExecutor`` default
``request_budget`` (100) is BELOW that — size it at construction, or the origin leg fails closed to
"unavailable" (edge-only REMEDIATED, a-sanitize residual open) rather than silently under-probing.

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

# Fallback truncation proxy (chars) when the executor does not report ``truncated`` — mirrors the framework's
# HttpExecutor._BODY_EXCERPT_BYTES (8 KiB). The AUTHORITATIVE signal is the executor's ``truncated`` flag; this
# conservative proxy only over-triggers (→ INCONCLUSIVE, the safe direction), it never misses a flagged truncation.
_BODY_EXCERPT_CAP = 8 * 1024

# The boolean oracle will not CONFIRM below this many DISTINCT clauses per truth value. Enforced here too:
# an adapter built below the floor could never reach STILL_VULNERABLE (every round would be a non-signal),
# so it would silently answer "refute" for a live-vulnerable origin and lean entirely on the attribution
# gate. Fail loudly at construction instead.
_MIN_CLAUSES_PER_TRUTH_VALUE = 4


def _identical_request_samples(round_ctx: dict) -> list:
    """The observations in one round that answer the SAME BYTE-IDENTICAL request — ``falses[0]`` and its
    repeat. These are the only samples that may legitimately feed the oracle's identical-request determinism
    pre-filter; the OTHER clauses are DIFFERENT requests, so pooling them would make the "baseline" a
    cross-request comparison and silently over-refuse. The pre-filter is a cheap screen only: soundness comes
    from the per-round truth-value attribution the oracle recomputes."""
    if not isinstance(round_ctx, dict):
        return []
    out = []
    for key in ("falses", "false_repeats"):
        arm = round_ctx.get(key)
        if isinstance(arm, (list, tuple)) and arm and isinstance(arm[0], dict):
            out.append(arm[0])
    return out


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
        MUST DIFFER from ``param`` (a collision silently overwrites the probe value — refused in
        ``__post_init__``).
      * ``base_value`` — the benign value the parameter normally carries (the baseline probe; NO metachars).
      * ``true_payload_templates`` / ``false_payload_templates`` — ``K_T >= 2`` DISTINCT always-TRUE and
        ``K_F >= 2`` DISTINCT always-FALSE data-dependent predicate payloads, each carrying the literal
        ``{challenge}`` inert-marker slot; metacharacter-identical in class. Two CALLER OBLIGATIONS the
        constructor cannot check (both undecidable from the template string, like data-dependence itself,
        and both stated in full as residual (a) on ``boolean_inference_oracle``):
          * they must VARY IN COMPARISON SHAPE (``=`` / ``>`` / ``LIKE`` / a compound), not merely in
            their literals — a set whose truth value tracks one SURFACE feature is partitioned by a
            CRS-942130-shape regex with no SQL engine at all (measured: mints at rate 1.0); and
          * at least one pair must be SQL-EVALUATED rather than constant-foldable (e.g.
            ``1 IN (SELECT 1)`` vs ``1 IN (SELECT 2)``) — shape diversity ALONE is partitioned by a
            complete ~60-line constant folder, also with no SQL engine (measured 500/500).
        FOUR per truth value is the hard floor (the oracle's CONFIRM floor — fewer can only ever refute,
        which on the REMEDIATED branch is the dangerous direction); more distinct clauses is also what
        lowers the per-URL-caching residual the oracle docstring states.
      * ``original_firing_rounds`` — RETAINED confirming ``probe_rounds`` in the same truth-value shape (the
        harness-capability positive control: the SAME boolean oracle still CONFIRMS on the known-vulnerable
        rounds).
    """

    executor: Any
    base_url: str
    endpoint_path: str
    param: str
    nonce_param: str
    base_value: str
    true_payload_templates: tuple
    false_payload_templates: tuple
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

    # --- R2 direct-to-origin re-drive (closes the a-sanitize residual) -------------------------------------
    # When ``origin_ip`` is set the adapter can ALSO re-drive the SAME matched-decoy round DIRECTLY at the
    # origin — connecting to the origin IP with the ``Host`` header PINNED to the target hostname — to bypass a
    # sanitizing/virtual-patching EDGE. PLAINTEXT HTTP only in PR1 (HTTPS origin-SNI is a later slice). The
    # re-drive is STILL a ``gated_fetch``: it passes ONLY if the charter scopes the origin IP (the scope gate
    # matches an IP literal against an IP scope entry) — otherwise it fails closed to edge-only, NEVER bypassing
    # the gate to reach a raw IP.
    origin_ip: str = ""
    origin_host: str = ""          # the Host header to pin; defaults to the target hostname (``_host``)
    origin_port: int = 0           # 0 → 80 (plaintext); the origin's HTTP port

    _host: str = field(init=False, default="")
    _slug: str = field(init=False, default="")

    def __post_init__(self) -> None:
        self._host = urlsplit(self.base_url).hostname or ""
        self._slug = str(self.engagement or getattr(self.executor, "engagement_slug", "") or "")
        # normalise to tuples so the recipe digest and the probe order are stable (the dataclass is mutable
        # only during __post_init__; nothing rewrites these afterwards)
        self.true_payload_templates = tuple(self.true_payload_templates)
        self.false_payload_templates = tuple(self.false_payload_templates)
        # TRUTH-VALUE ATTRIBUTION floor: one clause per truth value is ONE DRAW — it cannot attribute a
        # response to a truth VALUE, only to a request. Fail closed at construction (the oracle would refuse
        # such a round anyway; refusing here makes the misuse loud instead of a silent permanent INCONCLUSIVE).
        for name, tmpls in (("true_payload_templates", self.true_payload_templates),
                            ("false_payload_templates", self.false_payload_templates)):
            if len(tmpls) < _MIN_CLAUSES_PER_TRUTH_VALUE:
                raise ValueError(
                    f"{name} needs >= {_MIN_CLAUSES_PER_TRUTH_VALUE} DISTINCT clauses of the SAME truth value "
                    "that VARY IN COMPARISON SHAPE (= / > / LIKE / compound), not merely in their literals — "
                    "too few draws cannot attribute a response to a TRUTH VALUE (an input-independent origin "
                    "separates by coincidence), and a set whose truth value tracks one SURFACE feature is "
                    "partitionable by a regex WAF with no SQL engine at all")
            if len(set(tmpls)) != len(tmpls):
                raise ValueError(f"{name} contains duplicate clauses — duplicates are not independent draws, "
                                 "so they do not raise the attribution bar (spec §3/§8.5)")
        # Each metachar payload MUST carry the {challenge} inert-marker slot, else it silently degrades to a
        # payload that cannot thread the freshness marker — fail-closed at construction (mirrors live_adapter).
        for name, tmpls in (("true_payload_templates", self.true_payload_templates),
                            ("false_payload_templates", self.false_payload_templates)):
            for tmpl in tmpls:
                if "{challenge}" not in tmpl:
                    raise ValueError(f"{name} entries must each contain the literal '{{challenge}}' "
                                     "inert-marker slot (the run nonce rides the clause as a marker, never "
                                     "the predicate)")
        # SYNTACTIC non-degeneracy (spec §3 / §8.5): reject the two TRIVIAL degenerate forms — clauses that are
        # IDENTICAL, or that differ ONLY in the {challenge} marker (which would make the inert nonce FLIP the
        # boolean, forbidden by §3/§6). This is a STRING-level guard ONLY. It does NOT — and cannot — enforce
        # genuine DATA-DEPENDENCE (that the two clauses hold OPPOSITE truth values the origin's DB evaluates):
        # that is UNDECIDABLE from the template string (whitespace / case / different-constant / comment-padding
        # pairs of equal truth value pass this guard). Genuine data-dependence is a CALLER OBLIGATION, ATTESTED at
        # RUNTIME by the positive control — the retained ``original_firing_rounds`` must re-fire (SPRT confirm),
        # i.e. they genuinely SEPARATED true from false on the known-vulnerable origin when the finding was
        # confirmed. A caller that pairs degenerate live templates with non-degenerate retained rounds is the
        # disclosed residual (DIFFERENTIAL-REMEDIATION §7), not caught here.
        for t in self.true_payload_templates:
            for f in self.false_payload_templates:
                if t == f:
                    raise ValueError("a true and a false payload template are IDENTICAL — the clauses must "
                                     "differ in a data-dependent predicate (a degenerate round cannot separate "
                                     "true from false and would trivially refute → a false REMEDIATED, spec "
                                     "§3/§8.5)")
                if t.replace("{challenge}", "") == f.replace("{challenge}", ""):
                    raise ValueError("a true/false payload template pair differs ONLY in the {challenge} "
                                     "marker — the inert freshness nonce must NOT be the discriminating "
                                     "predicate (spec §3/§6); the data-dependent predicate difference must be "
                                     "independent of the challenge")
        # Same collision guard as ``live_adapter``: ``_probe_url`` builds ``{param: value, nonce_param:
        # challenge}``, so a collision drops the BASELINE/TRUE/FALSE value and every probe in a round becomes
        # the SAME request — the run-level challenge is one value for all trials. That is exactly the
        # degenerate round the identical-template guard above rejects (a round that cannot separate true from
        # false, spec §3/§8.5). Fail-closed at construction for the same reason, not left to the SPRT.
        if self.param and self.param == self.nonce_param:
            raise ValueError(
                f"param and nonce_param are both {self.param!r} — the freshness challenge would OVERWRITE the "
                "probe value, making every probe in a round the SAME request; such a round cannot separate "
                "true from false (spec §3/§8.5). They MUST differ.")
        if not self.original_probe_recipe_digest:
            self.original_probe_recipe_digest = digest_payload({
                "endpoint_path": self.endpoint_path, "param": self.param, "nonce_param": self.nonce_param,
                "base_value": self.base_value,
                "true_payload_templates": list(self.true_payload_templates),
                "false_payload_templates": list(self.false_payload_templates), "bug_class": self.bug_class,
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
        TRUTH-VALUE ATTRIBUTION rounds recorded when the finding was first confirmed — the positive control is
        now held to the SAME 2-cluster bar a fresh mint is, not to a weaker derived-baseline gate.
        ``false_baseline_samples`` is the determinism pre-filter derived from the ONE identical request the
        retained rounds repeat (``falses[0]`` + its byte-identical ``false_repeats[0]``)."""
        rounds = [dict(r) for r in self.original_firing_rounds]
        baseline = [x for r in rounds for x in _identical_request_samples(r)]
        return {"bug_class": self.bug_class, "probe_rounds": rounds,
                "discriminator": dict(_BOOLEAN_DISCRIMINATOR), "false_baseline_samples": baseline}

    @property
    def origin_redrive_available(self) -> bool:
        """True iff a direct-to-origin re-drive is CONFIGURED (an origin IP is set). The driver only ATTEMPTS
        the R2 leg when this holds; whether it SUCCEEDS still depends on the scope gate admitting that IP."""
        return bool(self.origin_ip)

    # ---- exploit trial: build + gated-fetch the matched-decoy round --------------------------------
    def run_exploit_trial(self, *, challenge: str, trial_index: int,
                          auth: EffectiveAuthorization) -> TrialObservation:
        """The EDGE-observed matched-decoy round (through the target hostname / any interposing edge)."""
        return self._drive_round(challenge=challenge, trial_index=trial_index, origin=False)

    def run_origin_trial(self, *, challenge: str, trial_index: int,
                         auth: EffectiveAuthorization) -> TrialObservation:
        """R2 — the SAME matched-decoy round re-driven DIRECTLY at the origin IP (``Host`` pinned), bypassing a
        sanitizing edge. Same fail-closed contract as the edge trial; when no origin is configured, or the scope
        gate refuses the IP, or the origin is unreachable, the round comes back ``valid=False`` — which the
        driver reads as "origin re-drive UNAVAILABLE" (→ edge-only REMEDIATED, residual open), NEVER as a
        fabricated origin silence."""
        if not self.origin_redrive_available:
            return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                    invalid_reason="no origin_ip configured — direct-to-origin re-drive unavailable")
        return self._drive_round(challenge=challenge, trial_index=trial_index, origin=True)

    def _drive_round(self, *, challenge: str, trial_index: int, origin: bool) -> TrialObservation:
        """Build the matched-decoy TRUTH-VALUE ATTRIBUTION probes and gated-fetch each — through the edge, or
        DIRECT-to-origin when ``origin`` — assembling the ``boolean_inference_oracle`` round: the baseline, the
        ``K_T`` distinct always-TRUE clauses, the ``K_F`` distinct always-FALSE clauses, and a byte-IDENTICAL
        repeat of every one of those clauses. FAIL-CLOSED: any probe that is undelivered (gate refusal /
        transport failure / empty status) makes the WHOLE round ``valid=False`` so the driver fails the run
        closed (never a silently-dropped probe)."""
        trues = [t.replace("{challenge}", challenge) for t in self.true_payload_templates]
        falses = [f.replace("{challenge}", challenge) for f in self.false_payload_templates]
        probes: dict[str, str] = {"baseline": self._baseline_value(challenge)}
        for i, v in enumerate(trues):
            probes[f"true[{i}]"] = v
            probes[f"true_repeat[{i}]"] = v      # byte-identical repeat — the determinism control
        for j, v in enumerate(falses):
            probes[f"false[{j}]"] = v
            probes[f"false_repeat[{j}]"] = v
        via = "origin" if origin else "edge"
        responses: dict[str, dict] = {}
        for name, value in probes.items():
            req = self._probe_request(value, challenge, origin=origin)
            try:
                resp = self.executor.gated_fetch(req)
            except Exception as exc:  # noqa: BLE001 — a transport/executor crash → the round is invalid
                return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                        invalid_reason=f"{via} {name} probe send crashed: {exc}",
                                        detail=f"{via} {name} probe send crashed")
            status = (resp or {}).get("status")
            if status in (0, None):
                # A gate refusal or transport failure on ANY of the five probes makes the matched decoy
                # uninterpretable — fail the whole round closed (§4.4), never partial. For the ORIGIN leg this
                # is exactly the "origin unreachable / IP out of charter scope" case → edge-only, residual open.
                return TrialObservation(reachable=False, valid=False, oracle_context=None,
                                        invalid_reason=f"{via} {name} probe not answered: "
                                                       f"{str((resp or {}).get('refused') or status)}",
                                        detail=f"{via} {name} probe not answered")
            body = str((resp or {}).get("body") or "")
            # ``truncated`` (authoritative from the executor: the full body exceeded the capture cap) — a
            # differential closure attribution over a truncated body is UNSOUND (a leak past the cap is invisible).
            # The executor flag is AUTHORITATIVE when present (a byte-length compare that catches multibyte bodies
            # the char proxy would miss, and does NOT over-flag a full 8192-byte capture). Fall back to the
            # conservative excerpt-length proxy ONLY when the executor did not report the flag at all.
            flag = (resp or {}).get("truncated")
            truncated = bool(flag) if flag is not None else (len(body) >= _BODY_EXCERPT_CAP)
            responses[name] = {"status": int(status), "body": body, "truncated": truncated}

        round_ctx: dict[str, Any] = {
            "trues": [responses[f"true[{i}]"] for i in range(len(trues))],
            "true_repeats": [responses[f"true_repeat[{i}]"] for i in range(len(trues))],
            "falses": [responses[f"false[{j}]"] for j in range(len(falses))],
            "false_repeats": [responses[f"false_repeat[{j}]"] for j in range(len(falses))],
            "baseline": responses["baseline"],
        }
        # Informational adapter-side WAF-closure (the DRIVER recomputes it authoritatively over the round).
        from framework.v2.verify.oracles import differential_response_oracle   # lazy — FATAL-2
        round_ctx["waf_closed"] = all(
            differential_response_oracle(responses["baseline"], f, dict(_CLOSURE_DISCRIMINATOR)).fired
            for f in round_ctx["falses"])
        # Live-marker reflection (§4 / LOW-1): the inert challenge marker must come back on the un-WAF'd
        # baseline (a query-stripping cache / non-echoing edge that serves one body for all probes fails this).
        echoed = (challenge in responses["baseline"]["body"]
                  or any(challenge in f["body"] for f in round_ctx["falses"]))
        n = len(probes)
        return TrialObservation(reachable=True, valid=True, oracle_context=round_ctx,
                                freshness_level=Freshness.F1_TARGET_ECHOES, nonce_echoed=echoed,
                                detail=f"{via} differential round {trial_index}: {n}/{n} matched-decoy probes "
                                       "delivered")

    def _probe_request(self, value: str, challenge: str, *, origin: bool) -> _HttpRequest:
        """The gated request for one probe. EDGE: the target hostname URL, no extra headers. ORIGIN (R2): the
        origin-IP URL over plaintext HTTP with the ``Host`` header PINNED to the target hostname, so the send
        reaches the origin directly while the app still routes on Host. The scope gate validates the URL host,
        so the origin re-drive is admitted ONLY when the charter scopes the origin IP (else gated_fetch refuses
        → the round is invalid → edge-only). The Host header is passed through untouched by gated_fetch."""
        if not origin:
            return _HttpRequest(url=self._probe_url(value, challenge), method="GET")
        path = "/" + self.endpoint_path.lstrip("/")
        query = urlencode(sorted({self.param: value, self.nonce_param: challenge}.items()))
        port = self.origin_port or 80
        netloc = f"{self.origin_ip}:{port}" if port != 80 else self.origin_ip
        host = self.origin_host or self._host
        return _HttpRequest(url=f"http://{netloc}{path}?{query}", method="GET", headers=(("Host", host),))

    # ---- helpers -----------------------------------------------------------------------------------
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
        base_value="1",
        true_payload_templates=("1' AND SUBSTR(@@version,1,1)>'' -- {challenge}",
                                "1' AND 17=17 -- {challenge}", "1' AND 'b'>'a' -- {challenge}",
                                "1' AND 'ab' LIKE 'a%' -- {challenge}"),
        false_payload_templates=("1' AND SUBSTR(@@version,1,1)>'~~~' -- {challenge}",
                                 "1' AND 17=18 -- {challenge}", "1' AND 'a'>'b' -- {challenge}",
                                 "1' AND 'ab' LIKE 'z%' -- {challenge}"))
    assert isinstance(probe, LiveTargetAdapter)


_assert_conforms()
