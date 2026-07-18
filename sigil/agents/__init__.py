"""SIGIL agent mesh (Phase 3, SIGIL §4) — ARCHIVIST, SENTINEL, STEWARD, ENVOY (drafts-only).
Each agent has an autonomy ceiling and writes provenance-linked spine records; sensitive
proposals queue for human approval and ENVOY outbound never auto-sends. Offense-free by
doctrine (assert_no_offense at import) — BASTION monitors own infrastructure only (Phase 5)."""
from ..reuse import assert_no_offense

assert_no_offense()

from .archivist import Archivist  # noqa: E402
from .artificer import Artificer  # noqa: E402
from .base import Agent, AgentResult, Proposal, Tier  # noqa: E402
from .bastion import Asset, Bastion  # noqa: E402
from .envoy import Envoy, FileInbox  # noqa: E402
from .scholar import Scholar  # noqa: E402
from .sentinel import Sentinel  # noqa: E402
from .steward import Steward  # noqa: E402

__all__ = ["Agent", "AgentResult", "Proposal", "Tier",
           "Archivist", "Sentinel", "Steward", "Envoy", "FileInbox", "Artificer", "Scholar",
           "Bastion", "Asset"]
