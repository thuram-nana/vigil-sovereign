"""
evidence.poc — the typed, deterministic shape of a reproduce-from-raw Proof-of-Concept (Proof Studio B0).

A Strix agent PROPOSES a finding with a free-text ``poc_script_code``. That text is never evidence.
What IS evidence is the raw traffic an EXECUTOR captured while driving the target — the request/response
bytes, the process exit, the environment the capture ran in. This module gives those captured facts a
typed home so they can be (a) serialised to files the EXISTING :mod:`evidence.manifest` hashes into a
certificate's ``artifacts`` list, and (b) translated (:mod:`verify.poc_translate`) into a
``FindingContext`` the deterministic oracle re-fires over.

It introduces NO new ``EvidenceCertificate`` field and changes no signed bytes: a ``PoCArtifact`` is a
plain record the mint writes to disk NEXT TO the raw bytes; the certificate binds it exactly as it binds
any other raw artifact (by per-file sha256). Everything here is deterministic — ``extra="forbid"``, no
wallclock, no rng (any ``seed``/``nonce`` is passed in by the capturer, never generated here) — so the
same capture serialises to the same bytes on producer and verifier.

The models are pure data: nothing in this file imports a target, sends traffic, or runs an oracle.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

# A relative, confined artifact reference: same discipline as ``evidence.models.ArtifactRef.path`` — a
# byte-ref points at a file UNDER the engagement evidence root, never an absolute path or a ``..`` escape.
_SHA256_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")


def _reject_escaping_ref(v: str, *, field: str) -> str:
    """Fail-closed at PARSE time: a byte/artifact reference must be a relative, ``..``-free path so a
    hostile capture cannot point the manifest/replay at a file outside the evidence tree. Empty is
    allowed (an optional channel — e.g. a response-only capture — carries no request ref)."""
    if v == "":
        return v
    from pathlib import PurePosixPath, PureWindowsPath

    if PurePosixPath(v).is_absolute() or PureWindowsPath(v).is_absolute():
        raise ValueError(f"{field} must be a relative path, got absolute: {v!r}")
    if any(part == ".." for part in PurePosixPath(v).parts):
        raise ValueError(f"{field} must not contain '..', got {v!r}")
    return v


class CapturedExchange(BaseModel):
    """ONE executor-captured interaction with the target — the non-LLM channel a FACT rests on.

    ``channel`` names the transport/oracle family the exchange belongs to ("http_differential",
    "process", ...); ``role`` distinguishes the halves of a PAIRED oracle (a differential needs a
    ``"baseline"`` and a ``"mutated"`` exchange, a control/treatment pair, a true/false probe round).
    ``request_bytes_ref`` / ``response_bytes_ref`` are relative paths to the raw bytes on disk (the
    manifest hashes them; the translator reads them). ``status`` is the HTTP status, ``exit_code`` a
    process exit; ``bug_class`` is the class this exchange helps prove. Deterministic, ``extra`` forbidden."""

    model_config = ConfigDict(extra="forbid")

    channel: str
    role: str = ""                       # baseline|mutated|control|treatment|true|false_a|false_b|"" (single)
    request_bytes_ref: str = ""          # relative path under the evidence root (empty for response-only)
    response_bytes_ref: str = ""
    status: int | None = None
    exit_code: int | None = None
    bug_class: str = ""

    @field_validator("request_bytes_ref", "response_bytes_ref")
    @classmethod
    def _confined_refs(cls, v: str, info) -> str:  # noqa: ANN001 - pydantic ValidationInfo
        return _reject_escaping_ref(v, field=str(info.field_name))


class EnvironmentManifest(BaseModel):
    """The sandbox the capture ran in — pinned so a replay is reproducible, not "worked on my machine".

    ``image_digest`` MUST be a content digest (``sha256:<64hex>`` or a bare 64-hex), never a mutable tag
    like ``:latest`` — a tag can be re-pointed under a signed proof, so a tag is refused at parse time.
    ``tool_versions`` pins the binaries; ``payload_sha256`` + ``payload_ref`` bind the exact payload;
    ``seed``/``nonce`` record any injected non-determinism (captured, never generated here);
    ``seccomp_profile_sha256`` pins the syscall filter; ``cgroup_limits`` the cpu/mem bound. All optional
    (a capture may not fill every field yet — the replay harness documents which gaps remain), but any
    value present is pinned by content. Deterministic, ``extra`` forbidden."""

    model_config = ConfigDict(extra="forbid")

    image_digest: str = ""               # sha256:<64hex> or <64hex> — NOT a tag
    tool_versions: dict[str, str] = Field(default_factory=dict)
    payload_sha256: str = ""
    payload_ref: str = ""
    seed: str = ""
    nonce: str = ""
    seccomp_profile_sha256: str = ""
    cgroup_limits: dict[str, str] = Field(default_factory=dict)

    @field_validator("image_digest")
    @classmethod
    def _digest_not_tag(cls, v: str) -> str:
        if v and not _SHA256_RE.match(v.strip().lower()):
            raise ValueError(
                f"image_digest must be a content digest (sha256:<64hex>), not a mutable tag: {v!r}"
            )
        return v

    @field_validator("payload_sha256", "seccomp_profile_sha256")
    @classmethod
    def _valid_sha(cls, v: str) -> str:
        if v and not _SHA256_RE.match(v.strip().lower()):
            raise ValueError(f"expected a sha256 digest, got {v!r}")
        return v

    @field_validator("payload_ref")
    @classmethod
    def _confined_payload_ref(cls, v: str) -> str:
        return _reject_escaping_ref(v, field="payload_ref")


class ToolInvocation(BaseModel):
    """One command the capture ran, with its exit and captured stdout/stderr byte-refs — the raw
    provenance behind an exchange. Deterministic, ``extra`` forbidden."""

    model_config = ConfigDict(extra="forbid")

    argv: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    stdout_ref: str = ""
    stderr_ref: str = ""

    @field_validator("stdout_ref", "stderr_ref")
    @classmethod
    def _confined_refs(cls, v: str, info) -> str:  # noqa: ANN001
        return _reject_escaping_ref(v, field=str(info.field_name))


class PoCArtifact(BaseModel):
    """The whole reproduce-from-raw PoC for one finding: the captured exchanges, the environment they
    ran in, the tool invocations, and a binding to the (content-gated) poc code by digest.

    This is NOT the certificate — it is a plain record the mint serialises to a file under the evidence
    dir, which the EXISTING manifest hashes into the certificate's ``artifacts`` list. ``gate_verdict``
    records the :mod:`proof.content_gate` decision so the stored proof carries WHY it was allowed to
    exist; ``poc_code_sha256`` binds the exact screened code without embedding the raw payload text in
    the record. Deterministic, ``extra`` forbidden."""

    model_config = ConfigDict(extra="forbid")

    finding_ref: str
    bug_class: str = ""
    exchanges: list[CapturedExchange] = Field(default_factory=list)
    env: EnvironmentManifest = Field(default_factory=EnvironmentManifest)
    invocations: list[ToolInvocation] = Field(default_factory=list)
    poc_code_ref: str = ""
    poc_code_sha256: str = ""
    gate_verdict: str = ""               # "allow" | "deny" | "" — the content-gate decision

    @field_validator("poc_code_ref")
    @classmethod
    def _confined_code_ref(cls, v: str) -> str:
        return _reject_escaping_ref(v, field="poc_code_ref")

    @field_validator("poc_code_sha256")
    @classmethod
    def _valid_code_sha(cls, v: str) -> str:
        if v and not _SHA256_RE.match(v.strip().lower()):
            raise ValueError(f"poc_code_sha256 must be a sha256 digest, got {v!r}")
        return v
