"""cloud_live_posture — VIGIL-owned LIVE cloud-capture posture FACT capability (Wave #4 Track B, the
CLOUD_POSTURE + POLICY_PATH oracle families over a LIVE, SCOPED capture).

The live-state column of prove-don't-guess, and the ONE track whose FACT may speak about LIVE infrastructure
(Track A's IaC/manifest FACTs are bounded to the represented artifact; a live claim needs a VIGIL-OWNED
query). VIGIL's own read-only cloud collector (``sensors.cloud_live``) captures the target's real inventory as
the SAME native inventory the offline importers produce, VIGIL normalises it, and the deterministic
``cloud_posture`` + ``policy_path`` oracles re-derive the insecure achieved state / anonymous grant path over
the RETAINED capture. The collector mints only a LEAD (a native inventory); a FACT exists only when VIGIL's
own oracle re-fires — the collector's say-so is never trusted (criterion 6).

EVIDENCE AUTHORITY. Because the capture is VIGIL-OWNED, gated, and scoped, a FACT here is a bounded claim
about the CAPTURED, SCOPED LIVE STATE — "in {provider} account {account}[/{region}], resource R is publicly
exposed as captured at T" — NOT a claim about the whole cloud. The capture is a PARTIAL snapshot (one scoped
enumeration), so a non-fire is INCONCLUSIVE, NEVER a labelled-clean negative: CLEAN would require a
completeness proof (that the enumeration covered every in-scope resource), which this slice does not assert.

D5 SCOPE GATE (fail-closed, the load-bearing pre-flight). Every capture is authorised by CLOUD-NATIVE identity
— ``(provider, account[, region][, resource])`` matched EXACTLY against the signed charter's cloud scope via
:class:`~vigil_integration.live.cloud_scope.CloudScopeGate` — BEFORE any adjudication. A URL-host gate is
insufficient for a cloud API (one endpoint fronts every tenant); the gate refuses an out-of-scope /
wildcard / kill-switched request and mints NOTHING. And because a live capture can OVER-RETURN (an
account-wide list even when the charter authorised only ``acme-*``), EACH captured subject is
independently re-authorised through the SAME gate — with its RAW case-exact id — before it is minted;
an out-of-scope subject is skipped, never certified. The requested scope and each FACT's own subject
scope are bound into the signed certificate (bounded honesty).

ADMISSION, not a direct mint (Phase-D BLOCKER-1). Every registered branch is ``clean_capable:false`` in
``docs/capability-matrix/evidence-branches.json``; a conclusive non-fire is demoted to INCONCLUSIVE, never
escapes as CLEAN. The oracle yields ``(fired, conclusive, rules)`` (``rules`` = the fired evidence-rule ids);
this producer USES ``rules`` for PER-RULE BRANCH ATTRIBUTION: a cloud_posture firing whose rule is
``named_cross_account_principal`` is admitted under the registered ``cloud_live.cloud_posture.cross_account_principal``
branch (whose extra precondition ``owner_account_supplied`` is evaluated over the retained control), every
other cloud firing under ``cloud_live.cloud_posture.achieved_state`` → ``verdict.admit(fired, conclusive, ...)``
→ ``certify_admitted`` mints ONLY a FACT. provenance="reproduced" (VIGIL re-derives the evidence over the retained capture bytes).

D2 BINDING. The captured evidence sha256, ``capture_method="api:list"``, the per-FACT ``resource_scope``
(provider/account/region/resource) naming the FACT's ACTUAL subject, the requested scope,
``completeness="partial"``, collector id and (optional) capture time are bound into the signed certificate;
``artifact_recheck_required`` makes verification recompute sha256 over the retained capture and fail closed
if it was swapped (BLOCK #3). NB there is deliberately no ``returned_scope`` — this slice measures no
requested-vs-returned identity set, so asserting one would fabricate a measurement (``completeness="partial"``
already states the capture cannot prove absence).

FATAL-2: every framework import is FUNCTION-LOCAL; the module is pure stdlib + the ``safe_parse`` sibling +
``vigil_core`` only, so importing it co-loads no offense engine. LIVE-FIRE (running the real collector against
a cloud) needs operator-provisioned read-only credentials; this module + its fixtures are the offline,
credential-free half (a captured native inventory stands in for a real capture in tests).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .safe_parse import ParseBudget, safe_json

# The registered LIVE-capture evidence branches (docs/capability-matrix/evidence-branches.json). All
# fact_capable:true (an unambiguous insecure achieved state / a real anon grant path in a scoped live capture
# is a FACT), clean_capable:false (a partial capture cannot prove ABSENCE). Namespaced under ``cloud_live.`` so
# they never collide with the Track-A ``iac.`` branches or a bare cloud_posture/policy_path branch. The
# cloud_posture family splits by fired rule into two branches (achieved_state / cross_account_principal).
_BRANCH_CLOUD = "cloud_live.cloud_posture.achieved_state"
# The NAMED-cross-account-principal branch: the same cloud_posture oracle, but attributed to its OWN registered
# branch when the fired evidence rule is the cross-account rule (rather than filed under the generic
# achieved_state branch). This is the per-rule branch-attribution the ``rules`` return value was added for, and
# it is what makes this branch's extra precondition — ``owner_account_supplied`` — evaluated by a real code
# path over THIS retained control (before this wiring the branch was registered but cited by nothing).
_BRANCH_CROSS_ACCOUNT = "cloud_live.cloud_posture.cross_account_principal"
# The oracle rule id (``observed["rule"]``) that the cross-account branch attributes.
_CROSS_ACCOUNT_RULE = "named_cross_account_principal"
_BRANCH_POLICY = "cloud_live.policy_path.iam_grant_path"

_CAPTURE_BUDGET = ParseBudget(max_bytes=32_000_000, max_depth=200, max_nodes=1_000_000, max_aliases=200)


@dataclass
class CloudLivePostureResult:
    """The outcome of a live-capture posture pass over ONE scoped capture."""

    provider: str
    account: str
    refused: bool = False                             # the D5 scope gate refused — nothing was adjudicated
    refusal_reason: str = ""
    resources: int = 0
    facts: list = field(default_factory=list)         # AdapterResult (status=="fact"), signed
    leads: list = field(default_factory=list)
    inconclusive: list = field(default_factory=list)  # AdapterResult outcome=="inconclusive" — NEVER clean
    admissions: list = field(default_factory=list)    # (branch_id, verdict, reason) — the admission trail
    contexts: dict = field(default_factory=dict)      # finding_ref -> oracle_context (offline re-verify)
    notes: list = field(default_factory=list)
    artifact_bytes: bytes = b""                       # the canonical captured-inventory bytes the FACTs bind
    skipped_out_of_scope: int = 0                     # captured subjects refused by the per-resource scope gate

    @property
    def n_facts(self) -> int:
        return len(self.facts)

    def family_verdict(self) -> str:
        if self.facts:
            return "FACT"
        return "INCONCLUSIVE"                          # never CLEAN (a partial capture cannot prove absence)


def _oracle_signal(bug_class: str, oracle_context: dict) -> "tuple[bool, bool, frozenset]":
    """Run the deterministic oracle over the retained context and return ``(fired, conclusive, rules)``
    WITHOUT minting. All framework imports are function-local (FATAL-2).

    ``rules`` is the set of ``observed["rule"]`` values the FIRED signals reported. It comes out of the SAME
    ``VerificationResult`` the verdict does — never a second, parallel oracle call, which could disagree
    with the one that actually decided (the divergence bug this program keeps re-learning). It exists so a
    caller can attribute a firing to the registered evidence branch that describes it, rather than filing
    every firing under one branch (readiness audit 2.7)."""
    from framework.v2.scanner.engine import probe_verdict  # noqa: PLC0415
    from framework.v2.verify.confirmation import adjudicate_finding, confirmed_from_result  # noqa: PLC0415
    from framework.v2.verify.verifier import OracleVerifier  # noqa: PLC0415

    verifier = OracleVerifier()
    finding = {"bug_class": bug_class, "oracle_context": oracle_context}
    result = adjudicate_finding(finding, oracle_context, verifier)
    fired = confirmed_from_result(result, finding, verifier) is not None
    verdict, _kinds = probe_verdict(result)
    conclusive = fired or verdict == "clean"
    rules = frozenset(
        str(r) for s in (result.signals or [])
        if getattr(s, "fired", False)
        for r in [(getattr(s, "observed", None) or {}).get("rule")]
        if r
    )
    return fired, conclusive, rules


def _owner_account_supplied(control: "dict") -> bool:
    """Whether the RETAINED control threads the owner's own-account id(s) — the precondition
    ``cloud_live.cloud_posture.cross_account_principal`` declares.

    Re-uses the oracle's OWN canonicaliser (``_cloud_owner_accounts``) rather than re-reading the keys here:
    a parallel matcher would drift from the rule it is supposed to gate, and a token the oracle drops (a
    labelled id, a leading-zero-dropped numeric) must count as NOT supplied here too. Fail-closed: any error
    reading the control is "not supplied", which yields INCONCLUSIVE rather than a FACT."""
    try:
        from framework.v2.verify.oracles import _cloud_owner_accounts  # noqa: PLC0415
        return bool(_cloud_owner_accounts(dict(control or {})))
    except Exception:      # noqa: BLE001 — an un-evaluable precondition is NOT a held precondition
        return False


def _canonical_capture(capture: "dict | bytes | str", budget: ParseBudget) -> "tuple[bytes, Any] | None":
    """Return ``(canonical_bytes, export)`` for the capture, or ``None`` if it cannot be parsed safely. A dict
    is a VIGIL-owned capture ({"export": <native>, "format": "native"} or a bare inventory); bytes/str are
    resource-governed-parsed. The canonical bytes are what artifact_sha256 binds (so verify can recompute)."""
    if isinstance(capture, dict):
        obj = capture
    else:
        parsed = safe_json(capture, budget)
        if not parsed.ok or not isinstance(parsed.value, dict):
            return None
        obj = parsed.value
    export = obj.get("export", obj) if isinstance(obj, dict) else obj
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return raw, export


def cloud_live_verify(
    capture: "dict | bytes | str",
    *,
    provider: str,
    account: str,
    scope_gate,
    engagement_slug: str,
    signers: "list[tuple[str, str]]",
    region: str = "",
    resource: str = "",
    collector_id: str = "cloud-live",
    capture_time_epoch: "int | None" = None,
    completeness: str = "partial",
    budget: "ParseBudget | None" = None,
) -> CloudLivePostureResult:
    """Authorise a scoped live cloud capture through the D5 gate, then — THROUGH ADMISSION — mint a signed FACT
    for every resource whose CAPTURED achieved state the ``cloud_posture`` oracle proves insecure and every
    firing anonymous IAM grant PATH ``policy_path`` re-derives. FAIL-CLOSED on the gate (nothing adjudicated).

    ``scope_gate`` is a :class:`cloud_scope.CloudScopeGate`; ``capture`` is a VIGIL-owned native inventory (or
    the collector's {export, format} wrapper). The FACT is bounded to the captured, scoped live state; a
    non-fire is INCONCLUSIVE (a partial capture cannot prove absence)."""
    from ..oracle_adapter import certify_admitted  # noqa: PLC0415 (FATAL-2: function-local)
    from .verdict import admit  # noqa: PLC0415 (FATAL-2: function-local — pure stdlib module)

    res = CloudLivePostureResult(provider=str(provider), account=str(account))

    # 0. D5 SCOPE GATE (fail-closed): a cloud-native identity must match the signed charter BEFORE any capture
    #    is adjudicated. Out-of-scope / wildcard / kill-switched -> refuse, mint NOTHING.
    allowed, reason = scope_gate.authorize(provider, account, region, resource)
    if not allowed:
        res.refused = True
        res.refusal_reason = reason
        res.notes.append(f"cloud scope gate refused ({provider}:{account}:{region or '*'}:{resource or '*'}): "
                         f"{reason}")
        return res

    parsed = _canonical_capture(capture, budget or _CAPTURE_BUDGET)
    if parsed is None:
        res.notes.append("live capture did not parse as a native inventory (typed error, no facts)")
        return res
    raw, export = parsed
    res.artifact_bytes = raw

    from framework.v2.sensors.cloud import (  # noqa: PLC0415 (FATAL-2: function-local)
        confirm_cloud_posture_facts,
        normalize_cloud_export,
    )
    from framework.v2.verify.cloud_posture import cloud_posture_context  # noqa: PLC0415
    from framework.v2.verify.policy_path import build_policy_graph, policy_path_context  # noqa: PLC0415

    inv = normalize_cloud_export(export, "native")
    res.resources = len(inv.get("resources") or [])

    requested_scope = f"{provider}:{account}:{region or '*'}:{resource or '*'}"
    # Capture-level binding shared by every FACT (the artifact identity + how/when captured). The
    # per-FACT ``resource_scope`` is added below and names the FACT's ACTUAL subject, never the request glob.
    # NB there is deliberately NO ``returned_scope`` here: this slice does not measure a requested-vs-returned
    # identity set, so asserting one (the prior ``returned_scope = requested_scope``) fabricated a
    # measurement — dropped. ``completeness="partial"`` already states the capture cannot prove absence.
    base_binding: dict = {
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "collector_id": collector_id,
        "capture_method": "api:list",          # a VIGIL-owned live read (not an artifact file)
        "completeness": completeness,          # "partial" — a scoped capture cannot prove absence
        "requested_scope": requested_scope,
        # BLOCK #3: verify recomputes sha256 over the retained capture bytes + cross-checks (a swap fails).
        "artifact_recheck_required": True,
        "artifact_encoding": "canonical_text",
    }
    if capture_time_epoch is not None:
        base_binding["capture_time_epoch"] = int(capture_time_epoch)
    observed = {"artifact_parsed": True}

    def _subject_scope(resource_id: str) -> dict:
        """The authorised scope bound into a FACT, naming its ACTUAL subject (BLOCK #3 subject discipline):
        the FACT speaks about THIS resource, so ``resource_scope.resource`` is THIS resource's id — never the
        request glob shared across unrelated subjects."""
        m = {"provider": str(provider), "account": str(account)}
        if region:
            m["region"] = str(region)
        m["resource"] = str(resource_id)
        return m

    def _subject_authorized(resource_id: str) -> "tuple[bool, str]":
        """BLOCK-1: the D5 gate authorised the CAPTURE REQUEST tuple, but a capture can OVER-RETURN (an
        ``s3api list-buckets`` yields the whole account even when the charter authorised only ``acme-*``).
        Every MINTED SUBJECT must therefore independently match the signed charter. We re-use the SAME audited
        gate (never a parallel matcher that could drift from it — the recurring divergence bug this program
        keeps re-learning) with the resource's RAW, case-exact id — the id the gate matches CASE-SENSITIVELY;
        a lowercased/normalised id would launder an out-of-scope raw id ('…:ACME-evil') into an in-scope match
        ('…:acme-evil'). A subject outside the signed scope is SKIPPED, so an over-returning capture can never
        yield an over-scoped / false-subject FACT. Returns the gate's ``(allowed, reason)`` so a refusal is
        logged accurately (a mid-loop kill-switch trip reads as a kill-switch refusal, not a scope miss)."""
        return scope_gate.authorize(provider, account, region, str(resource_id))

    # --- CLOUD_POSTURE: per resource, over its CAPTURED achieved state alone ----------------------------
    for r in inv.get("resources") or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        rid = str(r["id"])                          # the RAW captured id (what the gate matches, what we bind)
        allowed, why = _subject_authorized(rid)
        if not allowed:
            res.skipped_out_of_scope += 1
            res.notes.append(f"skipped captured resource {rid!r}: {why}")
            continue
        oracle_context = cloud_posture_context(dict(r))
        finding = {
            "check_id": f"cloud_live:{provider}:{account}:cloud_posture:{rid}",
            "bug_class": "cloud_misconfiguration",
            "insertion_point": f"cloud_live:{provider}:{account}:{rid}",
            "oracle_context": oracle_context,
        }
        binding = {**base_binding, "resource_scope": _subject_scope(rid)}
        # PER-RULE BRANCH ATTRIBUTION (readiness audit 2.7). ``rules`` is the set of fired evidence-rule ids.
        # A firing whose rule is the NAMED cross-account-principal rule IS the distinct registered
        # ``cross_account_principal`` branch — a real code path now evaluates that branch's extra precondition
        # (``owner_account_supplied``) over THIS retained control. Every other firing, and every non-firing,
        # stays under the generic ``achieved_state`` branch (a non-firing has no rule to attribute). Both
        # branches are fact_capable:true / clean_capable:false, so the VERDICT is identical either way; what
        # changes is the branch a FACT is filed under (honest attribution) and that the precondition is
        # actually checked — with no owner-account threaded in, the cross-account rule cannot fire, so the
        # precondition holds by construction whenever this arm is taken (belt-and-suspenders: if it somehow did
        # not, admission demotes to INCONCLUSIVE rather than minting).
        fired, conclusive, rules = _oracle_signal("cloud_misconfiguration", oracle_context)
        if _CROSS_ACCOUNT_RULE in rules:
            branch_id = _BRANCH_CROSS_ACCOUNT
            branch_observed = {**observed, "owner_account_supplied": _owner_account_supplied(r)}
        else:
            branch_id = _BRANCH_CLOUD
            branch_observed = observed
        admitted = admit(branch_id, fired=fired, conclusive=conclusive, observed=branch_observed)
        res.admissions.append((branch_id, admitted.verdict.value, admitted.reason))
        out = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                               provenance="reproduced", binding=binding)
        if out.is_fact:
            res.contexts[out.finding_ref] = oracle_context
            res.facts.append(out)
        elif out.outcome == "inconclusive":
            res.inconclusive.append(out)
        else:
            res.leads.append(out)

    # --- POLICY_PATH: per firing anonymous / over-privileged IAM grant path ----------------------------
    graph = build_policy_graph(inv)
    # ``confirm_cloud_posture_facts`` returns resource ids CANONICALISED (lowercased/stripped) to the graph
    # keys, but the D5 gate matches resource ids CASE-SENSITIVELY. Scope-checking/binding the canonical form
    # would launder an out-of-scope raw id ('…:ACME-evil') into an in-scope match ('…:acme-evil') — an
    # over-scope + false-subject leak (the red-pen fix-of-the-fix). Recover the RAW captured id and use it as
    # the scope-check subject and the bound subject, matching the cloud_posture loop: the gate authorises its
    # stripped form and the oracle additionally case-folds it for the graph match, so the SAME resource is
    # gated, judged, and bound as the faithful captured id — no out-of-scope id can enter. A canonical id that
    # maps to NO raw id, or to MULTIPLE distinct raw ids (a case-collision we cannot attribute to one
    # case-exact subject nor prove wholly in-scope), is SKIPPED fail-closed.
    raw_by_canonical: "dict[str, list[str]]" = {}
    for r in inv.get("resources") or []:
        if isinstance(r, dict) and r.get("id"):
            rid = str(r["id"])
            raw_by_canonical.setdefault(rid.strip().lower(), []).append(rid)
    for pf in confirm_cloud_posture_facts(inv):
        principal, canon_resource, access = pf.get("principal", ""), pf.get("resource", ""), pf.get("access", "")
        raws = raw_by_canonical.get(str(canon_resource).strip().lower(), [])
        if len(raws) != 1:
            res.skipped_out_of_scope += 1
            res.notes.append(
                f"skipped grant-path subject {canon_resource!r}: "
                + ("no case-exact captured resource" if not raws
                   else f"ambiguous case-collision across {sorted(set(raws))!r} "
                        "— cannot bind a single case-exact subject (fail-closed)"))
            continue
        resource_id = raws[0]                        # the RAW, case-exact captured id (what the gate matches)
        allowed, why = _subject_authorized(resource_id)
        if not allowed:
            res.skipped_out_of_scope += 1
            res.notes.append(f"skipped grant-path subject {resource_id!r}: {why}")
            continue
        # The oracle canonicalises internally (``policy_path_context`` -> ``_nid``), so passing the RAW id
        # re-fires identically over the lowercased graph while keeping the bound subject case-exact.
        oracle_context = policy_path_context(graph, principal, resource_id, access)
        claim = hashlib.sha256(f"{principal}\x00{resource_id}\x00{access}".encode()).hexdigest()[:12]
        finding = {
            "check_id": (f"cloud_live:{provider}:{account}:policy_path:{principal}->{resource_id}"
                         f"#{access or '-'}#{claim}"),
            "bug_class": "privilege_path",
            "insertion_point": f"cloud_live:{provider}:{account}:{resource_id}",
            "oracle_context": oracle_context,
        }
        binding = {**base_binding, "resource_scope": _subject_scope(resource_id)}
        # ``rules`` unused here (single registered ``_BRANCH_POLICY`` branch — see the cloud_posture loop);
        # unpacked in full because ``_oracle_signal`` returns ``(fired, conclusive, rules)``.
        fired, conclusive, _rules = _oracle_signal("privilege_path", oracle_context)
        admitted = admit(_BRANCH_POLICY, fired=fired, conclusive=conclusive, observed=observed)
        res.admissions.append((_BRANCH_POLICY, admitted.verdict.value, admitted.reason))
        out = certify_admitted(finding, admitted, engagement_slug=engagement_slug, signers=signers,
                               provenance="reproduced", binding=binding)
        if out.is_fact:
            res.contexts[out.finding_ref] = oracle_context
            res.facts.append(out)
        elif out.outcome == "inconclusive":
            res.inconclusive.append(out)
        else:
            res.leads.append(out)

    return res
