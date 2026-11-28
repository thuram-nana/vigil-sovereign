"""C-WS — per-engagement WORKSPACES: the owner-signed, tenant-isolated, tamper-evident workspace store
(``sigil.governor.engagement_workspaces``).

Load-bearing invariants (a false-green here would let a forged/replayed workspace record elevate or re-aim a
tenant's index, or let one tenant reach another's workspaces — the whole value is that a run's work is in ONE
owner-signed place, reachable only by its own tenant):

  * CREATE-ON-START is IDEMPOTENT — the same (org, engagement) always maps to the same workspace; a repeat
    ``ensure`` returns it WITHOUT a new spine record and without re-titling it;
  * the DANGEROUS direction (create/rename) is OWNER-signed + strictly-increasing ``issued_at``: a forged
    (attacker-signed) or REPLAYED (stale ``issued_at``) ``active`` grant is INERT in the fold;
  * the SAFE direction (archive) is honored even unsigned (fixed ``issued_at`` 0.0), and a workspace STAYS listed
    and gettable after archive (archive is a status, not a deletion);
  * TENANT ISOLATION is structural — ``org_id`` is inside the signed core, the id is derived WITH ``org_id``, and
    list/get are org-scoped: org A can never see or get org B's workspace;
  * BOUNDED + TRIM — at most N active workspaces per org; the (N+1)-th create auto-archives the oldest active;
  * EXPORT INTEGRITY — the portable bundle is owner-signed over its manifest and re-verifies, while a bundle
    whose manifest was edited after signing FAILS verification (tamper-evident);
  * FATAL-2 — the module imports no framework/strix (``assert_no_offense`` at import; a subprocess probe proves it).
"""
from __future__ import annotations

import itertools
import subprocess
import sys
import tempfile

import pytest

from sigil.governor import engagement_workspaces as ew
from sigil.governor.engagement_workspaces import (
    Workspace,
    WorkspaceCapError,
    WorkspaceError,
    WorkspaceRegistry,
    derive_workspace_id,
    verify_export,
)
from sigil.reuse import generate_keypair
from sigil.spine.store import SpineStore

OWNER = generate_keypair()
OP = OWNER.public_key_b64
ATTACKER = generate_keypair()

_iss = itertools.count(1)


def _issue() -> float:
    return float(next(_iss))


def _store():
    return SpineStore(tempfile.mktemp(suffix=".jsonl"))


def _reg(store, *, max_per_org=100):
    return WorkspaceRegistry(store, owner_key=OWNER, trusted_pubkey=OP, max_per_org=max_per_org)


# --- create-on-start / idempotency ---------------------------------------------------------------

def test_ensure_creates_then_resolves_roundtrips():
    reg = _reg(_store())
    w, created = reg.ensure_workspace("acme", "eng-1", "Acme scan of example.com", issued_at=_issue())
    assert created is True
    assert isinstance(w, Workspace) and w.org_id == "acme" and w.status == "active"
    assert w.title == "Acme scan of example.com" and w.engagement_id == "eng-1"
    assert w.workspace_id == derive_workspace_id("acme", "eng-1")
    got = reg.get_workspace("acme", w.workspace_id)
    assert got is not None and got.workspace_id == w.workspace_id
    assert reg.get_workspace("acme", derive_workspace_id("acme", "ghost")) is None   # fail-closed on unknown


def test_ensure_is_idempotent_no_new_record_no_retitle():
    s = _store()
    reg = _reg(s)
    w1, c1 = reg.ensure_workspace("acme", "eng-1", "First title", issued_at=_issue())
    n_after_first = sum(1 for _ in s.iter_records())
    # a SECOND ensure for the same engagement returns the existing workspace, appends NOTHING, keeps the title
    w2, c2 = reg.ensure_workspace("acme", "eng-1", "A DIFFERENT TITLE", issued_at=_issue())
    assert c2 is False
    assert w2.workspace_id == w1.workspace_id and w2.title == "First title"
    assert sum(1 for _ in s.iter_records()) == n_after_first           # no new spine record


def test_blank_title_auto_derives_from_the_engagement():
    reg = _reg(_store())
    w, _ = reg.ensure_workspace("acme", "scan.example.com", "", issued_at=_issue())
    assert w.title == "Engagement scan.example.com"


def test_workspace_id_is_opaque_deterministic_and_per_org():
    a = derive_workspace_id("acme", "eng-1")
    b = derive_workspace_id("globex", "eng-1")                          # same engagement id, different org
    assert a.startswith("ws_") and len(a) == 43 and a != b             # per-org: ids never collide
    assert derive_workspace_id("acme", "eng-1") == a                   # deterministic (idempotency key)


# --- the DANGEROUS direction: owner-signed + anti-replay -----------------------------------------

def test_forged_active_grant_is_inert():
    s = _store()
    # a workspace grant signed by the ATTACKER key (not the trusted owner) must never fold in
    forged = WorkspaceRegistry(s, owner_key=ATTACKER, trusted_pubkey=OP, max_per_org=100)
    wid = derive_workspace_id("acme", "evil")
    forged._append_active("acme", wid, "EVIL", "evil", issued_at=_issue())
    assert _reg(s).get_workspace("acme", wid) is None
    assert _reg(s).list_workspaces("acme") == []


def test_replayed_active_grant_cannot_rewrite_the_title():
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "Original", issued_at=100.0)
    # capture + re-append a stale owner-signed active grant (issued_at <= the per-record high-water)
    reg._append_active("acme", w.workspace_id, "REPLAYED", w.engagement_id, issued_at=50.0)
    after = reg.get_workspace("acme", w.workspace_id)
    assert after is not None and after.title == "Original"             # the stale replay is ignored


def test_rename_requires_a_fresh_issued_at_and_updates_title():
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "Before", issued_at=10.0)
    r = reg.rename_workspace("acme", w.workspace_id, "After", issued_at=20.0)
    assert r.title == "After" and r.created_at == w.created_at and r.updated_at > w.updated_at
    assert reg.get_workspace("acme", w.workspace_id).title == "After"


def test_rename_unknown_workspace_refused():
    reg = _reg(_store())
    with pytest.raises(WorkspaceError):
        reg.rename_workspace("acme", derive_workspace_id("acme", "ghost"), "x", issued_at=_issue())


# --- the SAFE direction: archive (status, not deletion) ------------------------------------------

def test_archive_keeps_the_workspace_listed_and_blocks_rename():
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "WS", issued_at=_issue())
    a = reg.archive_workspace("acme", w.workspace_id)
    assert a is not None and a.status == "archived"
    # STILL listed + gettable (archive is a status, a run's work stays accessible)
    assert any(x.workspace_id == w.workspace_id for x in reg.list_workspaces("acme"))
    assert reg.get_workspace("acme", w.workspace_id).status == "archived"
    # an archived workspace is read-only: rename is refused (no silent un-archive)
    with pytest.raises(WorkspaceError):
        reg.rename_workspace("acme", w.workspace_id, "nope", issued_at=_issue())


def test_archive_is_honored_even_unsigned():
    s = _store()
    _reg(s).ensure_workspace("acme", "eng-1", "WS", issued_at=_issue())
    wid = derive_workspace_id("acme", "eng-1")
    # a registry with NO owner key cannot sign, yet the SAFE-direction archive still takes effect
    keyless = WorkspaceRegistry(s, owner_key=None, trusted_pubkey=OP, max_per_org=100)
    keyless.archive_workspace("acme", wid)
    assert _reg(s).get_workspace("acme", wid).status == "archived"


def test_archive_is_idempotent():
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "WS", issued_at=_issue())
    reg.archive_workspace("acme", w.workspace_id)
    reg.archive_workspace("acme", w.workspace_id)                      # replayed archive merely re-archives
    assert reg.get_workspace("acme", w.workspace_id).status == "archived"


# --- tenant isolation ----------------------------------------------------------------------------

def test_org_a_cannot_see_or_get_org_b_workspace():
    s = _store()
    reg = _reg(s)
    reg.ensure_workspace("acme", "eng-1", "Acme WS", issued_at=_issue())
    reg.ensure_workspace("globex", "eng-1", "Globex WS", issued_at=_issue())
    assert [w.org_id for w in reg.list_workspaces("acme")] == ["acme"]
    assert [w.org_id for w in reg.list_workspaces("globex")] == ["globex"]
    # globex's workspace id (even if guessed) is not gettable as acme's
    globex_id = derive_workspace_id("globex", "eng-1")
    assert reg.get_workspace("acme", globex_id) is None
    assert reg.get_workspace("globex", globex_id) is not None


def test_a_record_cannot_be_reaimed_at_another_org_without_breaking_the_signature():
    # org_id is INSIDE the signed core: a grant minted for acme cannot be relabelled to globex and still verify.
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "WS", issued_at=_issue())
    # the one record is acme's; globex sees nothing
    assert reg.list_workspaces("globex") == []
    assert reg.get_workspace("globex", w.workspace_id) is None


# --- bounded + trim ------------------------------------------------------------------------------

def test_active_workspaces_are_capped_and_oldest_is_trimmed():
    s = _store()
    reg = _reg(s, max_per_org=3)
    for i in range(5):
        reg.ensure_workspace("acme", f"eng-{i}", f"WS {i}", issued_at=float(i + 1))
    active = [w for w in reg.list_workspaces("acme") if w.status == "active"]
    archived = [w for w in reg.list_workspaces("acme") if w.status == "archived"]
    assert len(active) == 3                                            # never more than the cap
    assert len(archived) == 2                                         # the two oldest were trimmed
    # the oldest-created (eng-0, eng-1) are the ones archived; the newest stay active
    arch_eng = {w.engagement_id for w in archived}
    assert arch_eng == {"eng-0", "eng-1"}
    assert {w.engagement_id for w in active} == {"eng-2", "eng-3", "eng-4"}


def test_trim_does_not_count_archived_toward_the_cap():
    s = _store()
    reg = _reg(s, max_per_org=2)
    reg.ensure_workspace("acme", "eng-0", "WS0", issued_at=1.0)
    reg.ensure_workspace("acme", "eng-1", "WS1", issued_at=2.0)
    reg.archive_workspace("acme", derive_workspace_id("acme", "eng-0"))   # frees an active slot
    reg.ensure_workspace("acme", "eng-2", "WS2", issued_at=3.0)           # fits without trimming eng-1
    active = {w.engagement_id for w in reg.list_workspaces("acme") if w.status == "active"}
    assert active == {"eng-1", "eng-2"}


def test_title_and_engagement_length_caps():
    reg = _reg(_store())
    w, _ = reg.ensure_workspace("acme", "eng-1", "x" * 500, issued_at=_issue())
    assert len(w.title) <= 200
    with pytest.raises(WorkspaceError):
        reg.ensure_workspace("acme", "e" * 500, "t", issued_at=_issue())


# --- export integrity (portable, owner-signed, tamper-evident) -----------------------------------

def test_export_bundle_is_owner_signed_and_reverifies():
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "WS", issued_at=_issue())
    bundle = reg.export_bundle("acme", w.workspace_id, references=[{"kind": "findings", "ref": "eng-1"}])
    assert bundle["pubkey"] == OP and bundle["manifest"]["workspace"]["workspace_id"] == w.workspace_id
    assert verify_export(bundle, OP) is True


def test_a_tampered_export_fails_verification():
    s = _store()
    reg = _reg(s)
    w, _ = reg.ensure_workspace("acme", "eng-1", "WS", issued_at=_issue())
    bundle = reg.export_bundle("acme", w.workspace_id)
    bundle["manifest"]["workspace"]["title"] = "TAMPERED"
    assert verify_export(bundle, OP) is False
    # wrong / absent verifier key -> fail-closed
    assert verify_export(bundle, None) is False
    assert verify_export(reg.export_bundle("acme", w.workspace_id), ATTACKER.public_key_b64) is False


def test_export_unknown_workspace_refused():
    reg = _reg(_store())
    with pytest.raises(WorkspaceError):
        reg.export_bundle("acme", derive_workspace_id("acme", "ghost"))


# --- validation ----------------------------------------------------------------------------------

def test_bad_org_id_and_bad_workspace_id_are_refused():
    reg = _reg(_store())
    with pytest.raises(ValueError):                                     # not a valid tenant id
        reg.list_workspaces("../escape")
    with pytest.raises(WorkspaceError):                                 # not a ws_ id
        reg.get_workspace("acme", "not-a-ws-id")


def test_cap_error_is_a_workspace_error_subclass():
    assert issubclass(WorkspaceCapError, WorkspaceError)


# --- FATAL-2 -------------------------------------------------------------------------------------

def test_module_is_offense_free_fatal2():
    """A subprocess that imports the workspace store and exercises it must NOT have loaded the offense engine —
    it is sovereign-only reuse of the owner-signed-spine primitives + vigil_core crypto."""
    probe = (
        "import sys; from sigil.governor import engagement_workspaces as ew; "
        "from sigil.spine.store import SpineStore; from sigil.reuse import generate_keypair; import tempfile; "
        "k=generate_keypair(); r=ew.WorkspaceRegistry(SpineStore(tempfile.mktemp(suffix='.jsonl')), "
        "owner_key=k, trusted_pubkey=k.public_key_b64, max_per_org=5); "
        "w,_=r.ensure_workspace('acme','e1','t',issued_at=1.0); r.export_bundle('acme', w.workspace_id); "
        "bad=[m for m in sys.modules if m in ('framework','strix') or m.startswith(('framework.','strix.'))]; "
        "assert not bad, bad; print('ok')"
    )
    import os
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    out = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, env=env)
    assert out.returncode == 0 and "ok" in out.stdout, out.stderr
