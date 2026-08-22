"""Content-addressing the gateway image so an UPGRADE actually takes effect (issue #511 / W5-6).

The defect: `ensure_image` returned early when the `vigil-gateway:latest` tag existed, and
`docker compose up -d` will not recreate an unchanged tag — so after a `git pull` the OLD egress gate kept
running with no diff and no signal. The fix content-addresses the image by a digest of its build context:
a source change flips the tag, forces a rebuild, and forces a recreate; an unchanged context is a no-op.

Exercised against a TAG-AWARE fake docker (existence is per-tag, a build creates its tags), so the
rebuild-on-change LOGIC is CI-testable without a daemon. A real build+smoke stays opt-in in
test_docker_bringup.py.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vigil_gateway import docker as dmod
from vigil_gateway.docker import (
    DEFAULT_IMAGE,
    PIN_SCHEMA,
    SandboxNetworking,
    content_addressed_tag,
    context_digest,
    load_pin,
    write_pin,
)


class TagAwareDocker:
    """A fake docker whose image existence is keyed on the SPECIFIC tag (unlike a single bool), so a test
    can distinguish "the :latest tag exists" from "the content-addressed tag exists" — the exact
    distinction the #511 fix turns on. A successful build creates the tags it is given."""

    def __init__(self, *, present=(), container="running", running_id="sha256:built", compose_rc=0):
        self.images: dict[str, str] = {t: f"sha256:{t}" for t in present}
        self.container = container
        self.running_id = running_id
        self.compose_rc = compose_rc
        self.calls: list[list[str]] = []

    def run(self, args, capture_output=True, text=True, env=None, **kw):
        self.calls.append(list(args))
        sub = list(args[1:])
        if sub[:2] == ["image", "inspect"]:
            tag = sub[-1]
            if tag not in self.images:
                return SimpleNamespace(returncode=1, stdout="", stderr="no such image")
            out = self.images[tag] if "-f" in sub else ""
            return SimpleNamespace(returncode=0, stdout=out, stderr="")
        if sub[:1] == ["build"]:
            tags = [sub[i + 1] for i, a in enumerate(sub) if a == "-t"]
            # the built image has ONE content id; both tags (ctx-<digest> and :latest) point at it
            iid = f"sha256:{tags[0]}"
            for t in tags:
                self.images[t] = iid
            self.running_id = iid       # after a real `up` the container would run exactly this image
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if sub[:1] == ["compose"]:
            return SimpleNamespace(returncode=self.compose_rc, stdout="", stderr=("boom" if self.compose_rc else ""))
        if sub[:1] == ["inspect"]:
            fmt = sub[sub.index("-f") + 1] if "-f" in sub else ""
            if self.container == "absent":
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            out = self.running_id if "{{.Image}}" in fmt else self.container
            return SimpleNamespace(returncode=0, stdout=out, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def verbs(self):
        return [c[1] for c in self.calls]


@pytest.fixture
def tagfake(monkeypatch):
    def _install(**kw):
        fd = TagAwareDocker(**kw)
        monkeypatch.setattr(dmod.shutil, "which", lambda name: "/usr/bin/docker")
        monkeypatch.setattr(dmod.subprocess, "run", fd.run)
        return fd
    return _install


def _ctx(tmp_path, name="gateway", extra=""):
    ctx = tmp_path / name
    ctx.mkdir()
    (ctx / "Dockerfile").write_text("FROM scratch\n" + extra, encoding="utf-8")
    (ctx / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    return ctx


# ------------------------------- the content address itself -------------------------------

def test_context_digest_is_deterministic_and_content_sensitive(tmp_path):
    a = _ctx(tmp_path, "a")
    b = _ctx(tmp_path, "b")                                   # byte-identical files
    assert context_digest(a) == context_digest(b)            # deterministic — path names of the dir don't matter
    (b / "Dockerfile").write_text("FROM scratch\nENV X=1\n", encoding="utf-8")
    assert context_digest(a) != context_digest(b)            # a content change changes the digest


def test_context_digest_ignores_vcs_and_cache_junk(tmp_path):
    a = _ctx(tmp_path, "a")
    before = context_digest(a)
    (a / "__pycache__").mkdir()
    (a / "__pycache__" / "x.pyc").write_bytes(b"\x00\x01")
    (a / ".git").mkdir()
    (a / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    assert context_digest(a) == before                       # cache/VCS churn never perturbs the address


def test_content_addressed_tag_shape_and_change(tmp_path):
    ctx = _ctx(tmp_path)
    tag = content_addressed_tag(ctx)
    assert tag.startswith("vigil-gateway:ctx-") and len(tag.split("ctx-")[1]) == 16
    (ctx / "Dockerfile").write_text("FROM scratch\nENV Y=2\n", encoding="utf-8")
    assert content_addressed_tag(ctx) != tag                 # stale is detectable BY TAG ALONE


# ------------------------------- rebuild on change / negative control -------------------------------

def test_ensure_content_addressed_image_builds_when_absent(tagfake, tmp_path):
    fd = tagfake(present=())
    built, tag = SandboxNetworking().ensure_content_addressed_image(_ctx(tmp_path))
    assert built is True and tag.startswith("vigil-gateway:ctx-")
    assert "build" in fd.verbs()


def test_ensure_content_addressed_image_no_rebuild_when_unchanged(tagfake, tmp_path):
    # NEGATIVE CONTROL: the content-addressed tag already exists (unchanged context) → NO build. This proves
    # the mechanism is not simply "always rebuild".
    ctx = _ctx(tmp_path)
    fd = tagfake(present=(content_addressed_tag(ctx),))
    built, tag = SandboxNetworking().ensure_content_addressed_image(ctx)
    assert built is False
    assert "build" not in fd.verbs()


def test_upgrade_forces_rebuild_even_when_latest_exists(tagfake, tmp_path):
    """THE test that fails on a tree WITHOUT the #511 fix.

    Pre-#511, `compose_up` called `ensure_image(context_dir, "vigil-gateway:latest")`, which short-circuits
    when `:latest` exists — so with `:latest` present it does NOT build, and the assertions below fail. With
    the fix, `compose_up` checks the CONTENT-ADDRESSED tag (absent after a source change) and DOES build +
    recreate. So: `:latest` present, the ctx tag absent → a build must run and compose must recreate.
    """
    ctx = _ctx(tmp_path)
    fd = tagfake(present=(DEFAULT_IMAGE,))                    # only the stale :latest tag exists
    assert content_addressed_tag(ctx) not in fd.images       # the current source has never been built
    res = SandboxNetworking().compose_up("compose.yml", context_dir=ctx, pin_path=tmp_path / "pin.json")
    assert res["image_built"] is True, "an upgrade with :latest present must still rebuild (the #511 defect)"
    assert res["image_tag"] == content_addressed_tag(ctx)
    verbs = fd.verbs()
    assert "build" in verbs and "compose" in verbs and verbs.index("build") < verbs.index("compose")


# ------------------------------- the runtime pin (round-trip + negative control) -------------------------------

def test_write_and_load_pin_roundtrip(tmp_path):
    p = tmp_path / "nested" / "pin.json"
    rec = write_pin(p, context_digest_hex="abc123", image_tag="vigil-gateway:ctx-abc123", image_id="sha256:zzz")
    assert rec["schema"] == PIN_SCHEMA
    loaded = load_pin(p)
    assert loaded is not None
    assert loaded["context_digest"] == "abc123" and loaded["image_id"] == "sha256:zzz"


def test_load_pin_rejects_foreign_and_corrupt(tmp_path):
    # NEGATIVE CONTROL for the loader: a foreign schema / corrupt file / absent file all read as None (the
    # caller treats None as "the runtime is invisible", never as "verified").
    foreign = tmp_path / "foreign.json"
    foreign.write_text(json.dumps({"schema": "something-else", "image_id": "sha256:evil"}), encoding="utf-8")
    assert load_pin(foreign) is None
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert load_pin(corrupt) is None
    assert load_pin(tmp_path / "absent.json") is None


# ------------------------------- the two context-digest impls must agree -------------------------------

def _load_a14_image_pins():
    """Load infra/supply-chain/image_pins.py by path (it is not a package). Registered in sys.modules
    BEFORE exec so @dataclass can resolve its string annotations."""
    import importlib.util
    import pathlib
    import sys
    repo = pathlib.Path(__file__).resolve().parents[2]
    path = repo / "infra" / "supply-chain" / "image_pins.py"
    name = "vigil_a14_image_pins"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        del sys.modules[name]
        raise
    return mod


def test_context_digest_matches_the_a14_checker(tmp_path):
    """The A14 runtime check (infra/supply-chain/image_pins.py) MUST compute the SAME context digest as the
    builder (vigil_gateway.docker) — otherwise the check would flag every freshly-built gateway as stale.
    The two live in trees that cannot import each other, so this pins the duplicated algorithm together."""
    ip = _load_a14_image_pins()
    ctx = _ctx(tmp_path)
    assert context_digest(ctx) == ip.context_digest(ctx)
    assert dmod._CONTEXT_IGNORE == ip._CONTEXT_IGNORE
    # …and on the REAL gateway build context, not just a toy one
    import pathlib
    real_ctx = pathlib.Path(__file__).resolve().parents[2] / "gateway"
    assert context_digest(real_ctx) == ip.context_digest(real_ctx)
