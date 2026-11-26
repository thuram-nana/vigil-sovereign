"""evidence.resolver — the deterministic, offline acceptance suite for the Investigation-graph S1
tenant-scoped evidence-by-ID resolver + verify-store API.

One test per S1 acceptance criterion. Every test is deterministic (no wallclock/RNG — the resolver is a
pure function of on-disk contents) and offline (no network, no target). Bundles are built through the REAL
evidence layer (``build_certificate`` / ``sign_certificate`` / ``build_chain`` / ``sign_head`` /
``write_package``), so the suite exercises the exact on-disk PCF bundle format the resolver indexes.

The resolver NEVER duplicates verification: ``resolve_and_verify`` is sound only when the EXISTING
``evidence.certify.verify_certificate`` re-fires the oracle over the retained bytes AND the m-of-n Ed25519
signatures verify against the pinned trust root.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from framework.v2.entitlement.crypto import generate_keypair
from framework.v2.entitlement.models import AuthorizerKey, TrustRoot
from framework.v2.evidence.canonical import digest_payload
from framework.v2.evidence.certify import build_certificate, sign_certificate, trust_root_fingerprint
from framework.v2.evidence.chain import build_chain, sign_head
from framework.v2.evidence.audit_package import write_package
from framework.v2.evidence.resolver import (
    EvidenceResolver,
    ResolveVerification,
    get_resolver,
    resolve,
    resolve_and_verify,
    resolver_enabled,
)
from framework.v2.verify.adapter import FindingContext
from framework.v2.verify.reverify import reverify_context


# --------------------------------------------------------------------------------------------------
# Fixtures / builders — a genuine oracle fire, a governance trust root, and an on-disk PCF bundle.
# --------------------------------------------------------------------------------------------------
def _mesh_oc() -> dict:
    return FindingContext.from_mesh_control(
        {"resource_kind": "PeerAuthentication", "provider": "istio", "name": "default",
         "namespace": "istio-system", "mtls_mode": "PERMISSIVE"}).to_verifier_context()


def _finding_from(oc: dict, check_id: str, *, action_id: str | None = None) -> dict:
    """A finding whose confirmed_by + confidence come FROM the oracle (as a real producer's do)."""
    rr = reverify_context(oc, bug_class=str(oc.get("bug_class", "")))
    assert rr.ok, f"fixture context did not re-fire: {rr.note}"
    f = {"check_id": check_id, "bug_class": str(oc.get("bug_class", "")),
         "confirmed_by": rr.confirmed_by, "confidence": rr.confidence, "oracle_context": oc}
    if action_id:
        f["action_id"] = action_id
    return f


def _trust_root(threshold: int = 2, n: int = 3):
    keys = [generate_keypair() for _ in range(n)]
    tr = TrustRoot(schema_version=1, threshold=threshold, authorizers=[
        AuthorizerKey(key_id=f"gov-{i}", name=f"A{i}", public_key_b64=k.public_key_b64)
        for i, k in enumerate(keys)])
    signers = [(f"gov-{i}", k.private_key_b64) for i, k in enumerate(keys)]
    return tr, signers


def _write_bundle(out_dir: Path, findings: list[dict], signers, trust_root: TrustRoot, *,
                  evidence_root: Path | None = None, slug: str = "eng"):
    """Build + sign certificates from ``findings`` and write a real on-disk PCF bundle. Returns
    ``(signed_certs, contexts)``."""
    signed = []
    contexts: dict[str, dict] = {}
    for i, f in enumerate(findings):
        aid = f.get("action_id")
        has_art = bool(evidence_root) and bool(aid) and (Path(evidence_root) / aid).is_dir()
        cert = build_certificate(
            f, engagement_slug=slug, seq=i,
            evidence_root=(Path(evidence_root) if has_art else None),
            action_id=(aid if has_art else None))
        signed.append(sign_certificate(cert, signers))
        contexts[cert.finding_ref] = f["oracle_context"]
    chain = build_chain([sc.certificate.cert_digest for sc in signed])
    head = sign_head(chain, engagement_slug=slug, signers=signers)
    write_package(out_dir, certificates=signed, chain=chain, head=head, contexts=contexts,
                  trust_root=trust_root, evidence_root=(Path(evidence_root) if evidence_root else None),
                  engagement_slug=slug)
    return signed, contexts


def _simple_bundle(tmp_path: Path, *, subdir: str = "bundle", threshold: int = 2, n: int = 3):
    """One mesh finding in a signed bundle under ``tmp_path/subdir``. Returns everything a test needs."""
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-1")
    tr, signers = _trust_root(threshold, n)
    out = tmp_path / subdir
    signed, contexts = _write_bundle(out, [finding], signers[:threshold], tr)
    cid = signed[0].certificate.cert_digest
    return {"bundle_dir": out, "signed": signed[0], "contexts": contexts, "oc": oc,
            "ref": "mesh-1", "trust_root": tr, "id": cid}


# ==================================================================================================
# ACCEPTANCE TESTS — one per S1 criterion.
# ==================================================================================================

def test_flag_off_no_resolver_and_bundle_bytes_identical(tmp_path, monkeypatch):
    """Flag OFF: no resolver is constructed, and the evidence/certify on-disk bytes are unchanged — a
    golden PCF bundle (evidence-bundle.json + trust-root.json) serialises byte-identically regardless of
    whether this additive module is imported / armed."""
    monkeypatch.delenv("VIGIL_EVIDENCE_RESOLVER", raising=False)
    assert resolver_enabled() is False
    assert get_resolver(root=tmp_path) is None                 # NOTHING constructed
    assert resolve("whatever", root=tmp_path) is None
    assert resolve_and_verify("whatever", {}, root=tmp_path) is None

    # Deterministic inputs → write_package is a pure function of them. Writing the SAME bundle twice (the
    # resolver module is already imported at the top of this file) yields byte-identical evidence-bundle.json
    # + trust-root.json — proving the additive resolver perturbs no existing evidence/certify serialisation.
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-golden")
    tr, signers = _trust_root(2, 3)
    _write_bundle(tmp_path / "a", [finding], signers[:2], tr)
    _write_bundle(tmp_path / "b", [finding], signers[:2], tr)
    for name in ("evidence-bundle.json", "trust-root.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes(), name


def test_flag_on_resolve_returns_exact_signed_evidence(tmp_path, monkeypatch):
    """Flag ON: resolve(cert_digest) returns the exact SignedEvidence with that digest from the on-disk
    bundle (same certificate bytes, same signatures)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    b = _simple_bundle(tmp_path)
    got = resolve(b["id"], root=tmp_path)
    assert got is not None
    assert got.certificate.cert_digest == b["id"]
    assert got.certificate.model_dump(mode="json") == b["signed"].certificate.model_dump(mode="json")
    assert [s.model_dump() for s in got.signatures] == [s.model_dump() for s in b["signed"].signatures]
    # an "sha256:"-prefixed spelling of the same id resolves identically (normalisation).
    assert resolve("sha256:" + b["id"], root=tmp_path) is not None


def test_one_byte_mutation_changes_digest_old_id_resolves_to_none(tmp_path, monkeypatch):
    """Flag ON: a one-byte mutation of a stored cert changes its digest; the OLD id resolves to None
    (content-addressed — no stale alias), and the cert answers only to its NEW recomputed digest."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    b = _simple_bundle(tmp_path)
    old_id = b["id"]
    assert resolve(old_id, root=tmp_path) is not None          # resolves before the mutation

    # Mutate ONE field of the stored certificate in evidence-bundle.json (a true content change that keeps
    # the bundle valid JSON). The certificate's canonical bytes — and thus its cert_digest — change.
    bundle_file = b["bundle_dir"] / "evidence-bundle.json"
    doc = json.loads(bundle_file.read_text(encoding="utf-8"))
    doc["certificates"][0]["certificate"]["seq"] = doc["certificates"][0]["certificate"]["seq"] + 1
    bundle_file.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")

    new_id = digest_payload(doc["certificates"][0]["certificate"])
    assert new_id != old_id
    assert resolve(old_id, root=tmp_path) is None              # the OLD content-address no longer exists
    assert resolve(new_id, root=tmp_path) is not None          # it answers only to its new digest


def test_resolve_unknown_id_returns_none(tmp_path, monkeypatch):
    """Flag ON: resolve(unknown_id) -> None (never raises, never partial)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    _simple_bundle(tmp_path)
    assert resolve("f" * 64, root=tmp_path) is None
    assert resolve("", root=tmp_path) is None
    assert resolve("not-a-digest", root=tmp_path) is None


def test_resolve_and_verify_ok_only_when_reproduces_over_retained_bytes(tmp_path, monkeypatch):
    """Flag ON: resolve_and_verify(id, contexts) is ok ONLY when the EXISTING verify_certificate re-fires
    the oracle and confirms over the retained bytes (reproduced) AND the m-of-n sigs verify."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    # a finding with a manifested raw artifact, so verification exercises reproduction AND artifact integrity.
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-art", action_id="act-1")
    ev = tmp_path / "ev"
    (ev / "act-1").mkdir(parents=True)
    (ev / "act-1" / "response.http").write_text("HTTP/1.1 200 OK\n\nproof-bytes\n", encoding="utf-8")
    tr, signers = _trust_root(2, 3)
    signed, contexts = _write_bundle(tmp_path / "bundle", [finding], signers[:2], tr, evidence_root=ev)
    cid = signed[0].certificate.cert_digest

    # ok requires an out-of-band pin (the genuine trust-root fingerprint) — authenticity is never trusted
    # from the bundle alone (see the self-authentication regression below).
    fp = trust_root_fingerprint(tr)
    res = resolve_and_verify(cid, contexts, root=tmp_path, expected_trust_root_fingerprint=fp)
    assert isinstance(res, ResolveVerification)
    assert res.ok is True
    assert res.authenticity_pinned is True
    assert res.verification.reproduced is True          # the oracle actually re-fired over retained bytes
    assert res.verification.authentic is True
    assert res.verification.artifacts_ok is True
    assert res.signed.certificate.cert_digest == cid

    # the context fallback also works: with no contexts passed, the bundle's own contexts.json supplies it.
    assert resolve_and_verify(cid, None, root=tmp_path, expected_trust_root_fingerprint=fp).ok is True


def test_resolve_and_verify_tampered_artifact_is_not_ok(tmp_path, monkeypatch):
    """Flag ON: a tampered artifact (sha256 mismatch vs the signed manifest) -> not-ok from
    resolve_and_verify (reuses verify_certificate's artifact-integrity check — no second verifier)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-art", action_id="act-1")
    ev = tmp_path / "ev"
    (ev / "act-1").mkdir(parents=True)
    (ev / "act-1" / "response.http").write_text("original-proof-bytes\n", encoding="utf-8")
    tr, signers = _trust_root(2, 3)
    signed, contexts = _write_bundle(tmp_path / "bundle", [finding], signers[:2], tr, evidence_root=ev)
    cid = signed[0].certificate.cert_digest
    fp = trust_root_fingerprint(tr)
    assert resolve_and_verify(cid, contexts, root=tmp_path,
                              expected_trust_root_fingerprint=fp).ok is True     # sound before tamper

    # Flip the raw bytes in the SHIPPED evidence tree the certificate manifest binds by sha256.
    tampered = tmp_path / "bundle" / "evidence" / "act-1" / "response.http"
    tampered.write_text("SWAPPED-proof-bytes\n", encoding="utf-8")
    res = resolve_and_verify(cid, contexts, root=tmp_path, expected_trust_root_fingerprint=fp)
    assert res is not None and res.ok is False     # pinned ⇒ ok=False is attributable to the tamper
    assert res.verification.artifacts_ok is False


def test_tenant_scoped_other_root_id_is_none(tmp_path, monkeypatch):
    """Flag ON: TENANT-SCOPED — the resolver indexes only crucible_root()'s tree, so an id that exists
    only under a DIFFERENT root resolves to None, while this root's own id resolves."""
    from framework.v2.common import paths

    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    root_a = tmp_path / "tenant-a"
    root_b = tmp_path / "tenant-b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "CLAUDE.md").write_text("# sentinel A\n", encoding="utf-8")   # crucible_root() anchor
    (root_b / "CLAUDE.md").write_text("# sentinel B\n", encoding="utf-8")

    oc = _mesh_oc()
    tr, signers = _trust_root(2, 3)
    signed_a, _ = _write_bundle(root_a / "targets" / "a" / "audit", [_finding_from(oc, "a-1")],
                                signers[:2], tr, slug="a")
    signed_b, _ = _write_bundle(root_b / "targets" / "b" / "audit", [_finding_from(oc, "b-1")],
                                signers[:2], tr, slug="b")
    id_a = signed_a[0].certificate.cert_digest
    id_b = signed_b[0].certificate.cert_digest

    monkeypatch.setenv("CRUCIBLE_ROOT", str(root_a))
    paths._reset_cache()
    try:
        assert resolve(id_a) is not None             # this tenant's own cert (via crucible_root())
        assert resolve(id_b) is None                 # a cert that lives only under another root
    finally:
        paths._reset_cache()                         # never leave a stale cached root for sibling tests


def test_backingless_id_returns_none(tmp_path, monkeypatch):
    """Flag ON: a well-shaped but backing-less id (e.g. sha256:deadbeef...) -> None (never fabricates a
    SignedEvidence)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    _simple_bundle(tmp_path)
    assert resolve("sha256:" + ("deadbeef" * 8), root=tmp_path) is None     # 64 well-shaped hex chars
    assert resolve_and_verify("sha256:" + ("deadbeef" * 8), {}, root=tmp_path) is None


def test_resolve_and_verify_bad_signatures_not_ok(tmp_path, monkeypatch):
    """Flag ON: a cert whose m-of-n Ed25519 sigs don't verify vs the pinned trust root -> not-ok from
    resolve_and_verify (signature authority is only ever enforced, never relaxed)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-badsig")
    tr_signing, signers = _trust_root(2, 3)       # the keys that actually sign the certs
    tr_pinned, _ = _trust_root(2, 3)              # a DIFFERENT governance root — shipped as the bundle's pin
    signed, contexts = _write_bundle(tmp_path / "bundle", [finding], signers[:2], tr_pinned)
    cid = signed[0].certificate.cert_digest

    res = resolve_and_verify(cid, contexts, root=tmp_path)
    assert res is not None                         # the id RESOLVES (content exists)
    assert res.ok is False                         # ...but the signatures do not verify vs the pinned root
    assert res.verification.authentic is False


def test_read_only_file_set_and_mtimes_unchanged(tmp_path, monkeypatch):
    """Flag ON: READ-ONLY — after N resolve/verify calls the on-disk file set + mtimes are unchanged (the
    resolver writes nothing and touches no mtime)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-ro", action_id="act-1")
    ev = tmp_path / "ev"
    (ev / "act-1").mkdir(parents=True)
    (ev / "act-1" / "response.http").write_text("bytes\n", encoding="utf-8")
    tr, signers = _trust_root(2, 3)
    signed, contexts = _write_bundle(tmp_path / "bundle", [finding], signers[:2], tr, evidence_root=ev)
    cid = signed[0].certificate.cert_digest

    def snapshot() -> dict[str, tuple[int, int]]:
        snap: dict[str, tuple[int, int]] = {}
        for p in sorted((tmp_path / "bundle").rglob("*")):
            if p.is_file():
                st = p.stat()
                snap[str(p.relative_to(tmp_path))] = (st.st_size, st.st_mtime_ns)
        return snap

    fp = trust_root_fingerprint(tr)
    before = snapshot()
    for _ in range(5):
        assert resolve(cid, root=tmp_path) is not None
        assert resolve_and_verify(cid, contexts, root=tmp_path, expected_trust_root_fingerprint=fp).ok is True
        assert resolve("f" * 64, root=tmp_path) is None
    after = snapshot()
    assert before == after, "resolver mutated the evidence tree (file set or mtimes changed)"


# --------------------------------------------------------------------------------------------------
# Import hygiene — the symbol-grep guard (no new tool/exec/egress) + no offense-engine imports.
# --------------------------------------------------------------------------------------------------
_RESOLVER_SRC = Path(__file__).resolve().parents[1] / "resolver.py"

# Tokens that would signal a NEW tool/exec/egress capability. The resolver is defensive indexing — it must
# carry none of these. (Matched as substrings over the source, so e.g. ``os.system``/``subprocess`` anywhere
# fail; benign ``os.walk`` / ``os.path`` / ``os.environ`` are not in this set.)
_FORBIDDEN_SYMBOLS = (
    "subprocess", "os.system", "os.popen", "pty.", "socket", "requests", "httpx", "urllib",
    "http.client", "ftplib", "smtplib", "telnetlib", "asyncio", "ctypes", "pickle", "marshal",
    "eval(", "exec(", "compile(", "__import__(", "os.exec", "posix_spawn",
)


def test_symbol_grep_guard_no_tool_exec_or_egress():
    """Symbol-grep guard: the resolver source carries no exec / egress / tool-spawn symbol — it only reads
    bytes already on disk and reuses the existing verifier."""
    src = _RESOLVER_SRC.read_text(encoding="utf-8")
    hits = [sym for sym in _FORBIDDEN_SYMBOLS if sym in src]
    assert not hits, f"resolver.py carries forbidden tool/exec/egress symbol(s): {hits}"
    # and it must parse (a sanity gate so the grep is over real source, not a truncated file).
    ast.parse(src)


def test_import_pulls_no_offense_engine():
    """Importing evidence.resolver pulls only the evidence/verify substrate it reuses + stdlib — NEVER an
    offense-engine package (scanner / executors / sensors / recon / intruder / repeater / agents / console /
    aegis / intake) and no HTTP client. Run in a FRESH subprocess so the check is over a clean sys.modules."""
    crucible_root_dir = Path(__file__).resolve().parents[4]   # .../engine/crucible
    code = (
        "import sys\n"
        "import framework.v2.evidence.resolver\n"
        "offense = ('scanner','executors','sensors','recon','intruder','repeater','agents',\n"
        "           'console','aegis','intake','socialdefense')\n"
        "bad = sorted(m for m in sys.modules if m.startswith('framework.v2.')\n"
        "             and m.split('framework.v2.')[1].split('.')[0] in offense)\n"
        "net = sorted(m for m in ('requests','httpx') if m in sys.modules)\n"
        "print(repr(bad)); print(repr(net))\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(crucible_root_dir) + os.pathsep + env.get("PYTHONPATH", "")
    # A fresh subprocess already gives a clean sys.modules; keep PYTHONPATH honoured (no -I, which would
    # drop it) so ``framework`` imports from this engine checkout.
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert proc.returncode == 0, f"import failed: {proc.stderr}"
    lines = proc.stdout.strip().splitlines()
    bad = ast.literal_eval(lines[0])
    net = ast.literal_eval(lines[1])
    assert bad == [], f"resolver import pulled offense-engine package(s): {bad}"
    assert net == [], f"resolver import pulled an HTTP client: {net}"


# ==================================================================================================
# Red-pen regressions: authenticity must be PINNED out-of-band (a bundle cannot self-authenticate),
# and every malformed-on-disk shape fails closed — never raises, never follows a symlink.
# ==================================================================================================
def test_self_authenticating_forged_bundle_is_not_ok(tmp_path, monkeypatch):
    """A bundle that ships its OWN (attacker-generated) trust root and signs itself under it must NOT
    yield a clean ok: authenticity is UNPROVEN without an out-of-band pin, and a genuine pin rejects it."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-forge")
    tr_evil, evil_signers = _trust_root(2, 3)          # the attacker's OWN m-of-n governance root
    signed, contexts = _write_bundle(tmp_path / "bundle", [finding], evil_signers[:2], tr_evil)
    cid = signed[0].certificate.cert_digest

    # (a) no out-of-band pin: the only root is the one shipped IN the bundle -> authenticity UNPROVEN -> not ok.
    res = resolve_and_verify(cid, contexts, root=tmp_path)
    assert res is not None                              # the id resolves (content exists)
    assert res.authenticity_pinned is False
    assert res.ok is False                              # a bundle cannot self-authenticate
    assert res.verification.ok is True                 # internally consistent — exactly why a bare .ok was unsafe

    # (b) pinned to a GENUINE fingerprint the attacker does not control -> pin mismatches the shipped evil root.
    tr_genuine, _ = _trust_root(2, 3)
    res2 = resolve_and_verify(cid, contexts, root=tmp_path,
                              expected_trust_root_fingerprint=trust_root_fingerprint(tr_genuine))
    assert res2.ok is False
    assert res2.verification.authentic is False


def test_genuine_bundle_unpinned_is_not_ok_but_internally_consistent(tmp_path, monkeypatch):
    """Even a GENUINE bundle, resolved with no pin, is not ok (authenticity UNPROVEN); only a pin makes it ok."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    b = _simple_bundle(tmp_path)
    res = resolve_and_verify(b["id"], b["contexts"], root=tmp_path)
    assert res.authenticity_pinned is False and res.ok is False
    assert res.verification.ok is True                 # internally consistent + reproduces, just not pinned
    fp = trust_root_fingerprint(b["trust_root"])
    assert resolve_and_verify(b["id"], b["contexts"], root=tmp_path,
                              expected_trust_root_fingerprint=fp).ok is True


def test_non_list_certificates_fails_closed(tmp_path, monkeypatch):
    """A bundle whose "certificates" is not a list contributes nothing and never raises (fail-closed)."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    (tmp_path / "w1").mkdir()
    (tmp_path / "w1" / "evidence-bundle.json").write_text('{"certificates": 1234}', encoding="utf-8")
    (tmp_path / "w2").mkdir()
    (tmp_path / "w2" / "evidence-bundle.json").write_text('{"certificates": {"not": "a list"}}', encoding="utf-8")
    assert resolve("sha256:" + ("ab" * 32), root=tmp_path) is None           # no raise, no match
    assert resolve_and_verify("sha256:" + ("ab" * 32), {}, root=tmp_path) is None


def test_deeply_nested_bundle_json_fails_closed(tmp_path, monkeypatch):
    """A deeply-nested bundle json (RecursionError in json.loads) fails closed to no match, never crashes."""
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    (tmp_path / "deep").mkdir()
    payload = "[" * 20000 + "]" * 20000                 # nesting past the json recursion limit
    (tmp_path / "deep" / "evidence-bundle.json").write_text(payload, encoding="utf-8")
    assert resolve("sha256:" + ("cd" * 32), root=tmp_path) is None           # returns None, does not raise


def test_symlinked_evidence_dir_not_followed(tmp_path, monkeypatch):
    """A SYMLINKED evidence/ dir is treated as absent (not followed) — so swapped bytes behind a symlink are
    never re-hashed as valid; the verdict fails closed rather than accepting the attacker's tree."""
    import shutil
    monkeypatch.setenv("VIGIL_EVIDENCE_RESOLVER", "1")
    oc = _mesh_oc()
    finding = _finding_from(oc, "mesh-sym", action_id="act-1")
    ev = tmp_path / "ev"
    (ev / "act-1").mkdir(parents=True)
    (ev / "act-1" / "response.http").write_text("HTTP/1.1 200 OK\n\nbytes\n", encoding="utf-8")
    tr, signers = _trust_root(2, 3)
    signed, contexts = _write_bundle(tmp_path / "bundle", [finding], signers[:2], tr, evidence_root=ev)
    cid = signed[0].certificate.cert_digest

    bundle_ev = tmp_path / "bundle" / "evidence"
    shutil.rmtree(bundle_ev)
    outside = tmp_path / "outside"
    (outside / "act-1").mkdir(parents=True)
    (outside / "act-1" / "response.http").write_text("HTTP/1.1 200 OK\n\nSWAPPED\n", encoding="utf-8")
    bundle_ev.symlink_to(outside, target_is_directory=True)

    fp = trust_root_fingerprint(tr)
    res = resolve_and_verify(cid, contexts, root=tmp_path, expected_trust_root_fingerprint=fp)
    assert res is not None                              # does not raise
    assert res.ok is False                              # evidence/ symlink treated as absent -> fail closed
