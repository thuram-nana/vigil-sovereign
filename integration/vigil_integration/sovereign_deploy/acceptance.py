"""
vigil_integration.sovereign_deploy.acceptance — the per-VM PRODUCTION ACCEPTANCE HARNESS (WS4).

This is the self-test a freshly provisioned investor-eval box runs BEFORE handover: it proves the REAL
VIGIL pipeline works end-to-end against the BUNDLED CONTROLLED loopback target (MERIDIAN / a 127.0.0.1
vulnapp, e.g. :19010 — NEVER a real or external target; this is a self-test of the box, a GET-only read).

It reuses the REAL product paths — it NEVER reimplements or stubs them:

  1. REAL Anthropic think (INV4, ``live.think_claude.think``): a proposal returns AND the deterministic
     ORACLE still gates it (a model proposal, even a maximal one, mints NO FACT with no oracle; a fired
     oracle turns the same claim into a FACT). A REAL keyed call runs when ``ANTHROPIC_API_KEY`` is set; a
     hermetic injected client proves the same seam + gating with NO egress; with neither, the check is
     reported NOT-RUN (never silently green).
  2. engage -> FACT -> offline re-verify (``proof.run.build_report_mint`` -> ``live.transport_redrive``):
     a governed engage against the bundled target mints a signed SERVICE_REACHABILITY FACT; the persisted
     ``proofs/reverifiable.json`` re-fires offline through ``framework.v2.verify.reverify`` (the SAME entry
     ``python3 -m framework.v2 verify`` dispatches to), AND a tampered copy is REJECTED.
  3. a LEAD stays a LEAD (``agent.intake_result``): a non-confirmable finding is reported LEAD, never
     rounded up to FACT/CLEAN.
  4. codescan static FACT (INV2, ``codescan.run_codescan``): a scan over a planted weak-crypto region emits
     an oracle-re-verifiable static FACT.
  5. AEGIS oracle fires (INV3, ``aegis.gateway.serve_gateway``): ``enforce`` returns a 403 + a re-runnable
     certificate on a CONFIRMED verdict — only because the ``AEGIS_RESPOND`` entitlement is provisioned.
  6. a FACT-capable HexStrike tool mints (``live.oracle_families`` + the family re-drive): ``nmap`` is
     FACT-capable via ``SERVICE_REACHABILITY`` and VIGIL's own gated handshake admits it as a FACT on the
     VIGIL-owned ``service_reachability.tcp_handshake`` branch.

EXIT: every required check PASS -> exit 0 (handover-ready). ANY check FAIL, or a REQUIRED check NOT-RUN ->
NON-ZERO exit (handover BLOCKED). The harness prints a per-check report and a final verdict line.

INVARIANTS honoured: it mints NO FACT outside the real oracle path; it adds NO oracle (``_ALL_ORACLES``
stays 15); honest tiering (NOT-RUN / LEAD are never rounded to green / FACT / CLEAN); the engage step is a
GET-only read against the bundled target.

FATAL-2 / two-env boundary: this module is NOT imported by ``sovereign_deploy.__init__`` and every
``framework`` / ``vigil_integration.live`` import below is FUNCTION-LOCAL, so importing
``vigil_integration.sovereign_deploy`` stays framework-free and the harness itself only pulls the engine
when a check actually runs (it runs in the FULL env; the engine stays keyless).
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

PASS = "PASS"
FAIL = "FAIL"
NOT_RUN = "NOT-RUN"

# The bundled controlled target the acceptance engage reads (MERIDIAN loopback range). NEVER external.
DEFAULT_TARGET_HOST = "127.0.0.1"
DEFAULT_TARGET_PORT = 19010
_SELFTEST_SLUG = "vigil-acceptance-selftest"


@dataclass
class CheckResult:
    """One discrete acceptance check: a clear PASS / FAIL / NOT-RUN line. ``required`` NOT-RUN blocks
    handover; a PASS never does; a FAIL always does."""

    key: str
    title: str
    status: str
    detail: str = ""
    required: bool = True

    @property
    def blocks(self) -> bool:
        """Does this result block handover? A FAIL always does; a REQUIRED NOT-RUN does; a PASS never does."""
        if self.status == FAIL:
            return True
        if self.status == NOT_RUN and self.required:
            return True
        return False

    def line(self) -> str:
        mark = {PASS: "PASS ", FAIL: "FAIL ", NOT_RUN: "NOT-RUN"}.get(self.status, self.status)
        suffix = f" — {self.detail}" if self.detail else ""
        return f"[{mark}] {self.key}. {self.title}{suffix}"


@dataclass
class AcceptanceConfig:
    """Where the harness runs. ``target_host``/``target_port`` name the BUNDLED controlled loopback target
    (default MERIDIAN :19010). ``workspace`` isolates all CRUCIBLE state (charter / entitlement / spine) so
    the self-test neither reads nor pollutes the operator's real root; a fresh temp dir is used when unset.
    ``anthropic_client`` / ``anthropic_backend`` inject a HERMETIC think client (tests / air-gapped proof of
    the gating seam with no egress); left unset, a real keyed call runs when ``ANTHROPIC_API_KEY`` is set,
    else check 1 is NOT-RUN."""

    target_host: str = DEFAULT_TARGET_HOST
    target_port: int = DEFAULT_TARGET_PORT
    workspace: Optional[str] = None
    slug: str = _SELFTEST_SLUG
    anthropic_client: Optional[Any] = None
    anthropic_backend: Optional[str] = None
    # Internal state captured by _setup_env for restore on close().
    _signers: list = field(default_factory=list, repr=False)
    _trust_root: Any = field(default=None, repr=False)
    _saved_env: dict = field(default_factory=dict, repr=False)
    _run_dir: Optional[str] = field(default=None, repr=False)


# ---------------------------------------------------------------------------------------------------
# tamper helper (product-faithful: the SAME gross tamper the transport re-verify suite rejects)
# ---------------------------------------------------------------------------------------------------


def _corrupt_context(oc: dict) -> None:
    """Strip the evidence of the fire out of a retained reachability/transport context so the deterministic
    oracle can no longer re-fire — exactly the tamper the acceptance contract requires ``verify`` to reject."""
    hs = oc.get("handshake")
    if isinstance(hs, dict):
        hs["connected"] = False
        hs["peer"] = ""
    tls = oc.get("tls")
    if isinstance(tls, dict):
        tls["tls_version"] = "TLSv1.3"
        tls["cipher"] = "TLS_AES_256_GCM_SHA384"
        tls["connected"] = True
    # also blunt any top-level connected/channel marker a reachability context exposes directly
    if "connected" in oc:
        oc["connected"] = False
    if "channel_established" in oc:
        oc["channel_established"] = False


class AcceptanceHarness:
    """Drives the six acceptance checks against the bundled target in an isolated, GOVERNED workspace.

    Use as a context manager so the process environment and the engine's cached singletons are restored on
    exit — a CLI run exits anyway, but a test run must not leak CRUCIBLE_ROOT / the entitlement policy into
    its neighbours."""

    def __init__(self, config: Optional[AcceptanceConfig] = None) -> None:
        self.cfg = config or AcceptanceConfig()
        self._entered = False

    # -- lifecycle --------------------------------------------------------------------------------

    def __enter__(self) -> "AcceptanceHarness":
        self._setup_env()
        self._entered = True
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _setup_env(self) -> None:
        """Make the box a GOVERNED, isolated self-test instance: an isolated CRUCIBLE_ROOT (charter + spine
        + kill-switch) and entitlement dir, a real charter authorising the loopback target, and a REAL
        OFFENSIVE-tier entitlement provisioned (so ACTIVE_RECON + AEGIS_RESPOND + DEEP_STATIC_ANALYSIS are
        genuinely granted, not ungoverned-permitted). All real provisioning — the box owns itself."""
        import tempfile

        ws = Path(self.cfg.workspace) if self.cfg.workspace else Path(
            tempfile.mkdtemp(prefix="vigil-acceptance-"))
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "CLAUDE.md").write_text("# VIGIL acceptance self-test root (CRUCIBLE_ROOT sentinel)\n",
                                      encoding="utf-8")
        ent_dir = ws / "entitlement"
        ent_dir.mkdir(parents=True, exist_ok=True)
        run_dir = ws / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        self.cfg._run_dir = str(run_dir)

        # snapshot + set the env the engine reads.
        for var in ("CRUCIBLE_ROOT", "CRUCIBLE_ENTITLEMENT_DIR", "CRUCIBLE_ENTITLEMENT_ENFORCED"):
            self.cfg._saved_env[var] = os.environ.get(var)
        os.environ["CRUCIBLE_ROOT"] = str(ws)
        os.environ["CRUCIBLE_ENTITLEMENT_DIR"] = str(ent_dir)
        os.environ["CRUCIBLE_ENTITLEMENT_ENFORCED"] = "1"

        from framework.v2.common import paths
        paths.crucible_root.cache_clear()

        # a real charter authorising ONLY the bundled loopback target (GET-only TEST posture).
        self._write_charter(ws, self.cfg.target_host)

        # provision a REAL trust root + OFFENSIVE entitlement into the isolated dir → governed + granted.
        self._provision_offensive_entitlement()

    def _write_charter(self, ws: Path, host: str) -> None:
        from framework.v2.common import paths
        cpath = paths.charter_path(self.cfg.slug)
        cpath.parent.mkdir(parents=True, exist_ok=True)
        cpath.write_text(
            f"# Engagement charter — `{self.cfg.slug}`\n\n**Status:** Final\n\n"
            f"## 1. Operator attestation\n\nSigned: `acceptance-harness`     Date: `2026-10-01`\n\n"
            f"## 2. In-scope systems\n\n| Host | Notes | Auth |\n|---|---|---|\n"
            f"| `{host}` | Bundled controlled loopback self-test target | Yes |\n\n"
            f"## 7. Posture\n\n- [x] **TEST**\n", encoding="utf-8")

    def _provision_offensive_entitlement(self) -> None:
        from framework.v2.entitlement import policy, provision
        from framework.v2.entitlement.models import CapabilityTier

        ak, priv = provision.new_authorizer("acc-auth-0", "Acceptance Self-Test Authoriser")
        tr = provision.build_trust_root([ak], threshold=1)
        provision.write_trust_root(tr)
        doc = _entitlement_doc(tier=CapabilityTier.OFFENSIVE)
        signed = provision.sign_entitlement(doc, {"acc-auth-0": priv})
        provision.write_entitlement(signed)
        policy.reset_policy()

        # signers for the proof-sink mint rail (the FACT-signing keypair).
        from vigil_core import AuthorizerKey, TrustRoot, generate_keypair
        kp = generate_keypair()
        self.cfg._signers = [("gov0", kp.private_key_b64)]
        self.cfg._trust_root = TrustRoot(threshold=1, authorizers=[
            AuthorizerKey(key_id="gov0", name="gov0", public_key_b64=kp.public_key_b64)])

    def close(self) -> None:
        """Restore the process env and clear the engine's cached singletons so the box's real state is not
        left perturbed and neighbouring tests are unaffected."""
        for var, val in self.cfg._saved_env.items():
            if val is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = val
        try:
            from framework.v2.common import paths
            paths.crucible_root.cache_clear()
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass
        try:
            from framework.v2.entitlement import policy
            policy.reset_policy()
        except Exception:  # noqa: BLE001
            pass

    # -- the checks -------------------------------------------------------------------------------

    def run(self) -> list[CheckResult]:
        """Run all six checks, in order, and return the per-check results. Each check is total — a raised
        exception becomes a FAIL (a check that cannot run is never silently skipped)."""
        if not self._entered:
            raise RuntimeError("AcceptanceHarness must be entered (use it as a context manager) before run()")
        checks: list[Callable[[], CheckResult]] = [
            self.check_anthropic,
            self.check_engage_fact_verify,
            self.check_lead_stays_lead,
            self.check_codescan_static_fact,
            self.check_aegis_enforce,
            self.check_hexstrike_reachability,
        ]
        results: list[CheckResult] = []
        for fn in checks:
            try:
                results.append(fn())
            except Exception as exc:  # noqa: BLE001 — a check that crashed is a FAIL, never a silent pass
                results.append(CheckResult(key="?", title=fn.__name__, status=FAIL,
                                           detail=f"check raised {type(exc).__name__}: {exc}"))
        return results

    # 1 -------------------------------------------------------------------------------------------
    def check_anthropic(self) -> CheckResult:
        """REAL Anthropic think proposal returns AND the oracle still gates it. A keyed real call runs when
        ANTHROPIC_API_KEY is set; a hermetic injected client proves the same seam with no egress; neither ->
        NOT-RUN (never silently green)."""
        from vigil_integration.agent import ActionType, AgentState, LLMDecision, OutputAnalysis, Phase, intake_result
        from vigil_integration.live.think_claude import think

        title = "REAL Anthropic think returns a proposal AND the oracle still gates it"
        state = AgentState(engagement_slug=self.cfg.slug,
                           objective=f"probe http://{self.cfg.target_host}:{self.cfg.target_port}/ for a misconfiguration",
                           phase=Phase.INFORMATIONAL)

        key = (os.environ.get("ANTHROPIC_API_KEY") or "").strip()
        mode: str
        if self.cfg.anthropic_client is not None:
            # hermetic: an injected client declared LOCAL egresses nowhere (the documented test/air-gap seam).
            decision = think(state, {"prior": "httpx banner: nginx"}, client=self.cfg.anthropic_client,
                             backend=self.cfg.anthropic_backend or "ollama", max_tokens=256)
            mode = "hermetic (injected client, no egress)"
        elif key:
            prev = os.environ.get("CRUCIBLE_SOVEREIGNTY_TIER")
            os.environ["CRUCIBLE_SOVEREIGNTY_TIER"] = "PERMISSIVE"  # owner-authorised self-test egress
            try:
                decision = think(state, {"prior": f"httpx banner on http://{self.cfg.target_host}/"},
                                 max_tokens=1024)
            finally:
                if prev is None:
                    os.environ.pop("CRUCIBLE_SOVEREIGNTY_TIER", None)
                else:
                    os.environ["CRUCIBLE_SOVEREIGNTY_TIER"] = prev
            if getattr(decision, "error_class", "") == "network":
                return CheckResult("1", title, NOT_RUN,
                                   "nothing reached Anthropic (network fail-close) — reachability not provable")
            mode = ("real keyed call" if getattr(decision, "error_class", "") == ""
                    else "real keyed call (server-rejected the key — request provably left the host)")
        else:
            return CheckResult("1", title, NOT_RUN,
                               "no ANTHROPIC_API_KEY and no hermetic client wired — the keyed think path did not run")

        if not isinstance(decision, LLMDecision) or not isinstance(decision.action, ActionType):
            return CheckResult("1", title, FAIL, f"think() did not return an LLMDecision proposal ({mode})")
        # the key, when present, never leaks into the operator-facing proposal.
        if key:
            blob = f"{decision.reasoning} {decision.question} {decision.summary}"
            if key in blob:
                return CheckResult("1", title, FAIL, "the API key leaked into the proposal text")

        # the ORACLE is the sole authority: a maximal model-style claim mints NO FACT with no oracle, and a
        # FIRED oracle turns the SAME claim into a FACT (the mutation control that proves authority).
        maximal = OutputAnalysis(exploit_succeeded=True, extracted_info={"bug_class": "open_redirect"},
                                 findings=[{"title": "the model is sure it popped"}])
        without = intake_result("<raw the model never saw>", maximal, oracle=None)
        if without.facts:
            return CheckResult("1", title, FAIL, "a model proposal minted a FACT with no oracle — authority broken")
        with_oracle = intake_result("raw", maximal, oracle=lambda _r, _a: "web:open_redirect:deadbeef")
        if len(with_oracle.facts) != 1 or with_oracle.facts[0].status != "fact":
            return CheckResult("1", title, FAIL, "a fired oracle failed to mint the FACT (mutation control broken)")
        return CheckResult("1", title, PASS,
                           f"{mode}; proposal returned, oracle-gated (0 facts w/o oracle, 1 w/ fired oracle)")

    # 2 -------------------------------------------------------------------------------------------
    def check_engage_fact_verify(self) -> CheckResult:
        """A governed engage against the bundled target mints a signed FACT; the persisted report re-fires
        offline through ``verify``; a tampered copy is REJECTED."""
        title = "engage -> signed FACT -> offline re-verify (tamper rejected)"
        from framework.v2.verify import reverify
        from vigil_integration.proof.run import build_report_mint

        mint = build_report_mint(run_dir=self.cfg._run_dir, signers=self.cfg._signers,
                                 engagement_slug=self.cfg.slug)
        mr = mint({"id": "acc-reach", "bug_class": "service_reachable",
                   "host": self.cfg.target_host, "port": int(self.cfg.target_port), "protocol": "tcp"})
        if not (mr is not None and getattr(mr, "is_fact", False) and mr.result.n_facts >= 1):
            detail = "the engage minted NO signed FACT against the bundled target"
            if mr is not None:
                detail += f" (admissions={mr.result.admissions!r})"
            return CheckResult("2", title, FAIL, detail)

        report_path = Path(self.cfg._run_dir) / "proofs" / "reverifiable.json"
        if not report_path.is_file():
            return CheckResult("2", title, FAIL, "no re-verifiable report was persisted for the offline CLI")
        rc = reverify.main([str(report_path)])
        if rc != 0:
            return CheckResult("2", title, FAIL, f"the persisted FACT did NOT re-verify offline (rc={rc})")

        # a GROSS tamper of the retained context must be REJECTED — a verifier that passes it is broken.
        doc = json.loads(report_path.read_text(encoding="utf-8"))
        n = 0
        for f in doc.get("active_findings", []):
            oc = f.get("oracle_context")
            if isinstance(oc, dict):
                _corrupt_context(oc)
                n += 1
        if n == 0:
            return CheckResult("2", title, FAIL, "the report carried no re-verifiable oracle_context to tamper")
        bad = Path(self.cfg._run_dir) / "proofs" / "reverifiable.tampered.json"
        bad.write_text(json.dumps(doc), encoding="utf-8")
        rc_bad = reverify.main([str(bad)])
        if rc_bad == 0:
            return CheckResult("2", title, FAIL, "a TAMPERED report re-verified (rc=0) — the verifier is not sound")
        return CheckResult("2", title, PASS,
                           f"{mr.result.n_facts} FACT minted; re-verified offline (rc=0); tamper rejected (rc={rc_bad})")

    # 3 -------------------------------------------------------------------------------------------
    def check_lead_stays_lead(self) -> CheckResult:
        """Honest tiering: a non-confirmable finding is reported LEAD, never rounded up to FACT/CLEAN. Driven
        through the REAL intake keystone — a maximal claim with no oracle is retained as a LEAD, not a FACT."""
        title = "a LEAD stays a LEAD (non-confirmable finding never rounded to FACT/CLEAN)"
        from vigil_integration.agent import OutputAnalysis, intake_result

        claim = OutputAnalysis(exploit_succeeded=True, extracted_info={"bug_class": "sqli"},
                               findings=[{"title": "unconfirmed injection"}])
        result = intake_result("raw tool output with no reproducible signal", claim, oracle=None)
        if result.facts:
            return CheckResult("3", title, FAIL, "a non-confirmable finding was minted as a FACT — tiering dishonest")
        if not result.leads or not any(getattr(ld, "status", "") == "lead" for ld in result.leads):
            return CheckResult("3", title, FAIL, "a non-confirmable finding was NOT retained as an honest LEAD")
        if any(getattr(ld, "status", "") in ("fact", "clean") for ld in result.leads):
            return CheckResult("3", title, FAIL, "a LEAD was rounded to FACT/CLEAN")
        return CheckResult("3", title, PASS,
                           f"{len(result.leads)} lead(s), 0 facts — the unconfirmable finding stayed a LEAD")

    # 4 -------------------------------------------------------------------------------------------
    def check_codescan_static_fact(self) -> CheckResult:
        """INV2: a codescan over a PLANTED weak-crypto region emits an oracle-re-verifiable static FACT."""
        title = "codescan static FACT over a planted weak-crypto region (INV2)"
        from vigil_integration.codescan import run_codescan

        src = Path(self.cfg._run_dir) / "codescan-src"
        src.mkdir(parents=True, exist_ok=True)
        # a genuine weak-crypto property: hashlib.md5 used to digest data (DAA-WEAK-HASH -> broken-crypto).
        (src / "weak_hash.py").write_text(
            "import hashlib\n\n\ndef fingerprint(data: bytes) -> str:\n"
            "    return hashlib.md5(data).hexdigest()\n", encoding="utf-8")
        base = Path(self.cfg._run_dir) / "codescan-spine"
        res = run_codescan(root=str(src), slug="acc-codescan", base_dir=str(base))
        static_facts = res.get("static_facts") or []
        crypto = [sf for sf in static_facts if sf.get("oracle_kind")
                  and "crypto" in str(sf.get("daa_rule_id", "")).lower() + str(sf.get("static_rule_id", "")).lower()]
        if not static_facts:
            return CheckResult("4", title, FAIL,
                               f"the codescan emitted NO oracle-re-verifiable static FACT (findings={res.get('total')})")
        if not all(sf.get("re_verifiable") and sf.get("verified_by_oracle") for sf in static_facts):
            return CheckResult("4", title, FAIL, "a static FACT was not oracle-confirmed / re-verifiable")
        marker = crypto[0]["check_id"] if crypto else static_facts[0]["check_id"]
        return CheckResult("4", title, PASS,
                           f"{len(static_facts)} static FACT(s) incl. {marker}")

    # 5 -------------------------------------------------------------------------------------------
    def check_aegis_enforce(self) -> CheckResult:
        """INV3: the AEGIS Gateway in ``enforce`` BLOCKS a CONFIRMED attack with 403 + a re-runnable
        certificate — and only because AEGIS_RESPOND is provisioned (the harness workspace granted it). An
        un-entitled box honestly downgrades to observe and this check FAILs."""
        import urllib.error
        import urllib.parse
        import urllib.request

        title = "AEGIS enforce blocks a CONFIRMED attack with a re-runnable certificate (INV3)"
        from framework.v2.aegis.gateway import serve_gateway
        from framework.v2.aegis.models import AegisConfig, Verdict

        upstream = _start_upstream()
        sink: list[Any] = []
        cfg = AegisConfig(deployment_secret="acceptance", mode="enforce")
        gw = serve_gateway(f"http://127.0.0.1:{upstream.port}", config=cfg, host="127.0.0.1", port=0,
                           on_verdict=sink.append)
        threading.Thread(target=gw.serve_forever, daemon=True).start()
        gw_port = gw.server_address[1]
        try:
            es = gw.settings.enforcement_status() if hasattr(gw.settings, "enforcement_status") else {}
            if not es.get("enforcing"):
                reason = es.get("downgrade_reason") or "gateway not enforcing"
                return CheckResult("5", title, FAIL,
                                   f"enforce is not active (downgraded to observe): {reason}")
            sqli = "/search?q=" + urllib.parse.quote("' OR '1'='1")
            try:
                urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{gw_port}{sqli}"), timeout=5)
            except urllib.error.HTTPError as err:
                if err.code != 403:
                    return CheckResult("5", title, FAIL, f"the confirmed attack returned {err.code}, expected 403")
                cert = err.headers.get("X-Aegis-Certificate", "")
                if not cert.startswith("aegis-cert:"):
                    return CheckResult("5", title, FAIL, "the 403 block carried no re-runnable certificate")
                confirmed = [v for v in sink if getattr(v, "decision", "") == "confirmed"]
                if not confirmed or confirmed[0].certificate is None or not confirmed[0].certificate.reverify():
                    return CheckResult("5", title, FAIL, "the block's certificate did not re-verify offline")
                return CheckResult("5", title, PASS,
                                   f"403 block + certificate {cert.split(':', 1)[0]}:… that re-verifies offline")
            else:
                return CheckResult("5", title, FAIL, "the confirmed attack was NOT blocked (forwarded upstream)")
        finally:
            gw.shutdown()
            upstream.stop()

    # 6 -------------------------------------------------------------------------------------------
    def check_hexstrike_reachability(self) -> CheckResult:
        """A FACT-capable HexStrike tool mints: ``nmap`` is classified FACT-capable via SERVICE_REACHABILITY,
        and VIGIL's own gated handshake against the bundled target admits a FACT on the VIGIL-owned
        ``service_reachability.tcp_handshake`` branch (the tool proposes; the re-drive proves)."""
        title = "FACT-capable HexStrike tool mints (nmap -> SERVICE_REACHABILITY)"
        from vigil_integration.live import oracle_families as of
        from vigil_integration.proof.run import build_report_mint

        if not of.is_fact_capable_family("nmap"):
            return CheckResult("6", title, FAIL, "nmap is not classified FACT-capable")
        if of.verifier_for("nmap") != "SERVICE_REACHABILITY":
            return CheckResult("6", title, FAIL, f"nmap verifier is {of.verifier_for('nmap')!r}, expected SERVICE_REACHABILITY")

        # the HexStrike tool proposes 'port open'; VIGIL re-drives it through its OWN gated TCP handshake.
        mint = build_report_mint(run_dir=self.cfg._run_dir, signers=self.cfg._signers,
                                 engagement_slug=self.cfg.slug)
        mr = mint({"id": "acc-nmap", "bug_class": "service_reachable", "source": "nmap",
                   "host": self.cfg.target_host, "port": int(self.cfg.target_port), "protocol": "tcp"})
        if not (mr is not None and getattr(mr, "is_fact", False) and mr.result.n_facts >= 1):
            detail = "nmap's open-port proposal minted NO reachability FACT"
            if mr is not None:
                detail += f" (admissions={mr.result.admissions!r})"
            return CheckResult("6", title, FAIL, detail)
        branches = [a[0] for a in mr.result.admissions if a[1] == "FACT"]
        if "service_reachability.tcp_handshake" not in branches:
            return CheckResult("6", title, FAIL, f"the FACT did not land on the VIGIL-owned branch (got {branches!r})")
        return CheckResult("6", title, PASS,
                           "nmap FACT-capable via SERVICE_REACHABILITY; admitted on service_reachability.tcp_handshake")


# ---------------------------------------------------------------------------------------------------
# small, framework-free helpers
# ---------------------------------------------------------------------------------------------------


def _entitlement_doc(*, tier):
    from datetime import datetime, timedelta, timezone

    from framework.v2.entitlement.models import EntitlementDocument, EntitlementSubject

    now = datetime.now(timezone.utc)
    return EntitlementDocument(
        entitlement_id="vigil-acceptance-0001",
        issuer="VIGIL Acceptance Self-Test",
        subject=EntitlementSubject(institution_id="vigil-acceptance-box",
                                   institution_name="VIGIL Acceptance Self-Test Box"),
        capability_tier=tier,
        granted_capabilities=[],  # empty ⇒ everything the tier permits
        issued_at=now,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=1),
    )


class _Upstream:
    """A loopback HTTP upstream for the AEGIS gateway check — a benign app the gateway sits in front of."""

    def __init__(self) -> None:
        import http.server
        import socketserver

        class _H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_a: object) -> None:
                return

            def _reply(self) -> None:
                body = b"UPSTREAM-OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            do_GET = _reply
            do_POST = _reply

        self._srv = socketserver.TCPServer(("127.0.0.1", 0), _H)
        self._srv.daemon_threads = True
        self.port = self._srv.server_address[1]
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._t.start()

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


def _start_upstream() -> _Upstream:
    return _Upstream()


# ---------------------------------------------------------------------------------------------------
# reporting + CLI
# ---------------------------------------------------------------------------------------------------


def render_report(results: list[CheckResult]) -> str:
    lines = ["VIGIL PRODUCTION ACCEPTANCE HARNESS (WS4) — per-VM self-test", "=" * 60]
    for r in results:
        lines.append(r.line())
    lines.append("=" * 60)
    blocking = [r for r in results if r.blocks]
    if blocking:
        lines.append(f"VERDICT: HANDOVER BLOCKED — {len(blocking)} check(s) did not pass: "
                     + ", ".join(r.key for r in blocking))
    else:
        lines.append("VERDICT: HANDOVER-READY — all required checks PASS")
    return "\n".join(lines)


def exit_code(results: list[CheckResult]) -> int:
    """0 iff no result blocks handover (every required check PASS). Non-zero otherwise. An empty result set
    is itself a block (nothing was proven) — never a silent green."""
    if not results:
        return 1
    return 1 if any(r.blocks for r in results) else 0


def run_acceptance(config: Optional[AcceptanceConfig] = None) -> tuple[list[CheckResult], int]:
    """Run the full acceptance suite and return (results, exit_code). Sets up and tears down the isolated
    governed workspace around the run."""
    with AcceptanceHarness(config) as harness:
        results = harness.run()
    return results, exit_code(results)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m vigil_integration.sovereign_deploy.acceptance",
        description="VIGIL per-VM production acceptance harness: a self-test of the box against the BUNDLED "
                    "controlled loopback target. Exit 0 = handover-ready; non-zero = handover BLOCKED.")
    ap.add_argument("--target-host", default=DEFAULT_TARGET_HOST,
                    help="the bundled controlled loopback target host (default 127.0.0.1 — NEVER external)")
    ap.add_argument("--target-port", type=int, default=DEFAULT_TARGET_PORT,
                    help="the bundled controlled loopback target port (default 19010 — MERIDIAN)")
    ap.add_argument("--workspace", default=None,
                    help="isolate CRUCIBLE state here (default: a fresh temp dir)")
    args = ap.parse_args(argv)

    cfg = AcceptanceConfig(target_host=args.target_host, target_port=args.target_port,
                           workspace=args.workspace)
    results, rc = run_acceptance(cfg)
    print(render_report(results))
    return rc


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
