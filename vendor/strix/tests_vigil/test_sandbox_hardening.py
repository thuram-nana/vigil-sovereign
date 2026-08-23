"""VIGIL S5 — least-privilege hardening of the Strix runtime container.

These assert the pure create-kwargs transforms, the fail-closed image-pin gate, and the orphan
reaper / container kill switch. They are SDK-FREE and docker-FREE (like the module they test, and
like ``vigil_upstream.py``): a control whose tests can only ``importorskip`` the SDK is a control
whose tests never run in CI. Everything here runs with just pytest — no docker daemon, no SDK.
"""
from __future__ import annotations

import os

import pytest

from strix.runtime import sandbox_hardening as sh


# --- image digest pinning (fail-closed) -----------------------------------------------------------

@pytest.mark.parametrize(
    "image,acceptable",
    [
        ("vigil/strix-sandbox:local", True),            # first-party: provenance is the tree
        ("vigil-gateway:latest", True),                 # first-party prefix
        ("ghcr.io/x/strix-sandbox@sha256:" + "a" * 64, True),   # digest-pinned
        ("ghcr.io/usestrix/strix-sandbox:1.0.0", False),        # mutable upstream tag
        ("strix-sandbox:latest", False),
        ("ghcr.io/x/y@sha256:" + "A" * 64, False),      # uppercase hex is not a valid digest
        ("ghcr.io/x/y@sha256:" + "a" * 63, False),      # wrong length
        ("", False),
        (None, False),
    ],
)
def test_is_runtime_image_acceptable(image, acceptable):
    assert sh.is_runtime_image_acceptable(image) is acceptable


def test_assert_runtime_image_pinned_passes_first_party_and_pinned():
    sh.assert_runtime_image_pinned("vigil/strix-sandbox:local")
    sh.assert_runtime_image_pinned("ghcr.io/x/strix-sandbox@sha256:" + "b" * 64)


def test_assert_runtime_image_pinned_refuses_mutable_tag(monkeypatch):
    monkeypatch.delenv(sh.ALLOW_UNPINNED_ENV, raising=False)
    with pytest.raises(sh.UnpinnedRuntimeImageError):
        sh.assert_runtime_image_pinned("ghcr.io/usestrix/strix-sandbox:1.0.0")


def test_assert_runtime_image_pinned_loud_opt_out(monkeypatch):
    monkeypatch.setenv(sh.ALLOW_UNPINNED_ENV, "1")
    # opt-out proceeds (no raise) — the warning is logged, not asserted here.
    sh.assert_runtime_image_pinned("ghcr.io/usestrix/strix-sandbox:1.0.0")


# --- no-new-privileges (and do-not-weaken the FUSE/SYS_ADMIN branch) ---

def test_no_new_privileges_added_on_normal_branch():
    kw: dict = {}
    sh.apply_security_hardening(kw, privileged=False)
    assert kw["security_opt"] == ["no-new-privileges:true"]


def test_no_new_privileges_not_added_when_privileged():
    kw = {"security_opt": ["apparmor:unconfined"], "cap_add": ["SYS_ADMIN"]}
    sh.apply_security_hardening(kw, privileged=True)
    assert kw["security_opt"] == ["apparmor:unconfined"]  # FUSE branch untouched
    assert "SYS_ADMIN" in kw["cap_add"]


def test_no_new_privileges_not_duplicated():
    kw = {"security_opt": ["no-new-privileges:true"]}
    sh.apply_security_hardening(kw, privileged=False)
    assert kw["security_opt"].count("no-new-privileges:true") == 1


# --- resource limits (pids/shm default-on; mem/cpu opt-in) ---

def _clear_res_env(monkeypatch):
    for k in ("STRIX_SANDBOX_MEM_LIMIT", "STRIX_SANDBOX_CPUS",
              "STRIX_SANDBOX_PIDS_LIMIT", "STRIX_SANDBOX_SHM_SIZE"):
        monkeypatch.delenv(k, raising=False)


def test_resource_defaults_are_bounded_and_do_not_touch_mem_cpu(monkeypatch):
    _clear_res_env(monkeypatch)
    kw: dict = {}
    sh.apply_resource_limits(kw)
    assert kw["pids_limit"] == 4096          # fork-bomb guard, default-on
    assert kw["shm_size"] == "1g"            # Chromium-friendly but bounded
    assert "mem_limit" not in kw             # opt-in: not forced on an unknown host
    assert "nano_cpus" not in kw


def test_resource_env_overrides(monkeypatch):
    _clear_res_env(monkeypatch)
    monkeypatch.setenv("STRIX_SANDBOX_MEM_LIMIT", "2g")
    monkeypatch.setenv("STRIX_SANDBOX_CPUS", "1.5")
    monkeypatch.setenv("STRIX_SANDBOX_PIDS_LIMIT", "1024")
    monkeypatch.setenv("STRIX_SANDBOX_SHM_SIZE", "512m")
    kw: dict = {}
    sh.apply_resource_limits(kw)
    assert kw["mem_limit"] == "2g"
    assert kw["nano_cpus"] == 1_500_000_000
    assert kw["pids_limit"] == 1024
    assert kw["shm_size"] == "512m"


def test_resource_caps_can_be_disabled(monkeypatch):
    _clear_res_env(monkeypatch)
    monkeypatch.setenv("STRIX_SANDBOX_PIDS_LIMIT", "off")
    monkeypatch.setenv("STRIX_SANDBOX_SHM_SIZE", "0")
    kw: dict = {}
    sh.apply_resource_limits(kw)
    assert "pids_limit" not in kw
    assert "shm_size" not in kw


# --- optional isolation (read-only rootfs / non-root user) — OPT-IN, default off ---

def test_optional_isolation_default_off(monkeypatch):
    for k in ("STRIX_SANDBOX_READ_ONLY", "STRIX_SANDBOX_USER", "STRIX_SANDBOX_TMPFS_SIZE"):
        monkeypatch.delenv(k, raising=False)
    kw: dict = {}
    sh.apply_optional_isolation(kw)
    assert "read_only" not in kw and "user" not in kw


def test_optional_isolation_opt_in(monkeypatch):
    monkeypatch.setenv("STRIX_SANDBOX_READ_ONLY", "1")
    monkeypatch.setenv("STRIX_SANDBOX_USER", "65534:65534")
    monkeypatch.delenv("STRIX_SANDBOX_TMPFS_SIZE", raising=False)
    kw: dict = {}
    sh.apply_optional_isolation(kw)
    assert kw["read_only"] is True
    assert kw["tmpfs"]["/tmp"] == "rw,size=256m"  # noqa: S108 - container mount, not host
    assert kw["user"] == "65534:65534"


# --- lifecycle labels + --rm ----------------------------------------------------------------------

def test_run_labels_and_autoremove(monkeypatch):
    monkeypatch.delenv(sh.KEEP_CONTAINER_ENV, raising=False)
    kw: dict = {}
    sh.apply_run_labels(kw, session_id="deadbeef")
    labels = kw["labels"]
    assert labels[sh.LABEL_MANAGED] == "1"
    assert labels[sh.LABEL_OWNER_PID] == str(os.getpid())
    assert labels[sh.LABEL_SESSION] == "deadbeef"
    assert sh.LABEL_CREATED in labels
    assert kw["auto_remove"] is True


def test_keep_container_disables_autoremove(monkeypatch):
    monkeypatch.setenv(sh.KEEP_CONTAINER_ENV, "1")
    kw: dict = {}
    sh.apply_run_labels(kw)
    assert "auto_remove" not in kw


def test_apply_all_detects_privileged_branch_and_does_not_weaken_it(monkeypatch):
    _clear_res_env(monkeypatch)
    monkeypatch.delenv(sh.KEEP_CONTAINER_ENV, raising=False)
    kw = {"cap_add": ["SYS_ADMIN", "NET_RAW"], "security_opt": ["apparmor:unconfined"]}
    sh.apply_all(kw, session_id=None)
    # privileged branch: no-new-privileges NOT added, apparmor kept
    assert "no-new-privileges:true" not in kw["security_opt"]
    assert kw["security_opt"] == ["apparmor:unconfined"]
    # but the other hardening still applies
    assert kw["pids_limit"] == 4096
    assert kw["auto_remove"] is True
    assert kw["labels"][sh.LABEL_MANAGED] == "1"


def test_apply_all_normal_branch(monkeypatch):
    _clear_res_env(monkeypatch)
    monkeypatch.delenv(sh.KEEP_CONTAINER_ENV, raising=False)
    kw = {"cap_add": ["NET_RAW"]}
    sh.apply_all(kw, session_id=None)
    assert "no-new-privileges:true" in kw["security_opt"]


# --- reaper / kill switch (fake, duck-typed docker client) ---

class _FakeContainer:
    def __init__(self, labels, cid):
        self.labels = labels
        self.id = cid
        self.short_id = cid[:12]
        self.removed = False

    def remove(self, force=False):
        assert force is True
        self.removed = True


class _FakeContainers:
    def __init__(self, containers):
        self._all = containers

    def list(self, all=False, filters=None):  # noqa: A002,ARG002 - docker-py signature
        want = (filters or {}).get("label", [])
        if isinstance(want, str):
            want = [want]
        out = []
        for c in self._all:
            matches = True
            for lbl in want:  # every requested "k=v" must match
                k, _, v = lbl.partition("=")
                if c.labels.get(k) != v:
                    matches = False
                    break
            if matches:
                out.append(c)
        return out


class _FakeClient:
    def __init__(self, containers):
        self.containers = _FakeContainers(containers)


def test_reaper_reaps_dead_owner_and_prior_boot_but_spares_live_and_unknown(monkeypatch):
    monkeypatch.setattr(sh, "owner_boot_id", lambda: "BOOT-A")
    monkeypatch.setattr(sh, "pid_alive", lambda pid: pid == os.getpid())

    live = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: str(os.getpid()),
                           sh.LABEL_OWNER_BOOT: "BOOT-A"}, "live")
    dead = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: "999999",
                           sh.LABEL_OWNER_BOOT: "BOOT-A"}, "dead")
    prior_boot = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: "4242",
                                 sh.LABEL_OWNER_BOOT: "BOOT-OLD"}, "oldboot")
    unknown = _FakeContainer({sh.LABEL_MANAGED: "1"}, "nolabel")  # ownership unreadable -> spare

    client = _FakeClient([live, dead, prior_boot, unknown])
    reaped = sh.reap_orphan_containers(client)

    assert reaped == 2
    assert dead.removed and prior_boot.removed
    assert not live.removed and not unknown.removed


def test_reaper_never_raises_on_a_broken_client():
    class _Boom:
        @property
        def containers(self):
            raise RuntimeError("daemon down")
    assert sh.reap_orphan_containers(_Boom()) == 0


def test_kill_scan_container_removes_by_session_label():
    target = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_SESSION: "abc123"}, "t")
    other = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_SESSION: "zzz999"}, "o")
    client = _FakeClient([target, other])
    removed = sh.kill_scan_container(client, "abc123")
    assert removed == 1
    assert target.removed and not other.removed


def test_pid_alive_and_boot_id_basic():
    assert sh.pid_alive(os.getpid()) is True
    assert sh.pid_alive(-1) is False
    assert isinstance(sh.owner_boot_id(), str)


# --- S10: kill switch by OWNER pid (the console's cross-process reap) ------------------------------

def test_kill_containers_for_owner_removes_the_owners_box_and_spares_others():
    # The console SIGKILLs the host pid, then reaps the container that pid spawned — addressed by the
    # LABEL_OWNER_PID label (the console never holds the SDK session id). A container owned by a
    # DIFFERENT pid is untouched.
    mine = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: "4242",
                           sh.LABEL_OWNER_BOOT: "BOOT-A"}, "mine")
    other = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: "9999",
                            sh.LABEL_OWNER_BOOT: "BOOT-A"}, "other")
    client = _FakeClient([mine, other])
    removed = sh.kill_containers_for_owner(client, owner_pid=4242, owner_boot="BOOT-A")
    assert removed == 1
    assert mine.removed and not other.removed          # only the target owner's box dies


def test_kill_containers_for_owner_ignores_liveness_so_a_SIGKILLED_run_is_reaped(monkeypatch):
    # The SIGKILL case: the owner pid is DEAD and never ran its own teardown. Unlike the reaper, this
    # does NOT gate on liveness — the caller already decided this owner must die — so the stranded box
    # is removed even though (here) we assert pid_alive is never consulted.
    monkeypatch.setattr(sh, "pid_alive", lambda pid: (_ for _ in ()).throw(AssertionError("liveness must not be checked")))
    dead = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: "4242",
                           sh.LABEL_OWNER_BOOT: "BOOT-A"}, "dead")
    assert sh.kill_containers_for_owner(_FakeClient([dead]), owner_pid=4242) == 1
    assert dead.removed


def test_kill_containers_for_owner_spares_a_same_pid_from_a_different_boot():
    # NEGATIVE CONTROL: a pid number recycled across a reboot must not be mistaken for the target when
    # a boot id is supplied. Same LABEL_OWNER_PID, different LABEL_OWNER_BOOT -> spared.
    recycled = _FakeContainer({sh.LABEL_MANAGED: "1", sh.LABEL_OWNER_PID: "4242",
                               sh.LABEL_OWNER_BOOT: "BOOT-OLD"}, "recycled")
    client = _FakeClient([recycled])
    assert sh.kill_containers_for_owner(client, owner_pid=4242, owner_boot="BOOT-NOW") == 0
    assert not recycled.removed


def test_kill_containers_for_owner_bad_pid_and_broken_client_are_a_clean_zero():
    # NEGATIVE CONTROL: a non-numeric / non-positive pid removes nothing, and a broken daemon never
    # raises into the caller (a reap failure must not turn a successful cancel into an error).
    assert sh.kill_containers_for_owner(_FakeClient([]), owner_pid=None) == 0
    assert sh.kill_containers_for_owner(_FakeClient([]), owner_pid=0) == 0

    class _Boom:
        @property
        def containers(self):
            raise RuntimeError("daemon down")
    assert sh.kill_containers_for_owner(_Boom(), owner_pid=4242) == 0
