"""The host-backend contract (Phase 7, WS-D). A `HostBackend` captures screen/camera into the same
`Frame` the perception stack already consumes, and advertises what the host can do. The capability
descriptor is what the mesh routes on (see `sigil.mesh`): which host has a camera, a GPU for a local
VLM, and is always-on — so vision/compute go to the best-capable ONLINE host while authority stays
in the one signed spine."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable

from ..perception.capture import Frame


@dataclass(frozen=True)
class CapabilityDescriptor:
    host_id: str
    os: str
    has_screen: bool
    has_camera: bool
    has_gpu_vlm: bool          # a local moondream-class VLM is reachable (Ollama up)
    always_on: bool

    def to_dict(self) -> dict:
        return {"host_id": self.host_id, "os": self.os, "has_screen": self.has_screen,
                "has_camera": self.has_camera, "has_gpu_vlm": self.has_gpu_vlm, "always_on": self.always_on}


@runtime_checkable
class HostBackend(Protocol):
    def capture_screen(self) -> Optional[Frame]: ...
    def capture_camera(self) -> Optional[Frame]: ...
    def capabilities(self) -> CapabilityDescriptor: ...


# --- shared, OS-agnostic probes ---------------------------------------------------------------------
def host_id() -> str:
    """A stable per-host id (persisted once under SIGIL_HOME). Identifies this host in the mesh."""
    import uuid

    from ..config import SIGIL_HOME
    f = SIGIL_HOME / "host_id"
    try:
        v = f.read_text(encoding="utf-8").strip()
        if v:
            return v
    except OSError:
        pass
    SIGIL_HOME.mkdir(parents=True, exist_ok=True)
    hid = uuid.uuid4().hex[:16]
    try:
        f.write_text(hid, encoding="utf-8")
    except OSError:
        pass
    return hid


def probe_gpu_vlm() -> bool:
    """True iff a local moondream-class VLM endpoint (Ollama) is reachable — cheap TCP probe."""
    import os
    import socket
    from urllib.parse import urlparse
    u = urlparse(os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))
    try:
        with socket.create_connection((u.hostname or "127.0.0.1", u.port or 11434), timeout=0.5):
            return True
    except OSError:
        return False


def probe_always_on() -> bool:
    import os
    return os.environ.get("SIGIL_ALWAYS_ON", "").lower() in ("1", "true", "yes")
