"""
detection.credential — the authentication-attack oracles (CREDENTIAL-SENTINEL).

Fires at the credential-access stage over ``auth.log`` (``<ts>  src=.. user=.. result=..``):

  * ``brute_force``    — per-account authentication-FAILURE velocity: one account accrues >=
    ``FAIL_THRESHOLD`` failures in a window (Hydra/Medusa/Patator hammering one user). Narrow + deep.
  * ``password_spray`` — one SOURCE fails against >= ``ACCOUNT_SPREAD`` DISTINCT accounts, each shallow
    (<= ``PER_ACCOUNT_MAX`` failures), in a window. Broad + shallow — the spray fingerprint.

Benign twins that must stay silent: a user mistyping a few times then succeeding (below the per-account
threshold), and a legitimate login SURGE (many DISTINCT users SUCCEEDING — spray needs cross-account
FAILURES, brute needs one account's failures). Windows come from the records' ts/seq, never a clock;
pure/deterministic/total.

Honest note (recorded on every spray detection): the loopback ``auth.log`` retains ``src/user/result``
but NOT the attempted password, so ``password_spray`` proves the SOURCE-FANOUT fingerprint (one origin,
many accounts, shallow failures) — not, literally, "the same password". Same-password confirmation needs
richer auth telemetry (absent) and is stated, not faked.

Import-clean: stdlib + the detection base.
"""

from __future__ import annotations

from typing import Any, Optional

from .base import DetectionOracle, Grade, OracleHit, group_by, windowed


def _failures(window: Any) -> list:
    return [e for e in window if getattr(e, "result", "") == "failure"]


class BruteForceOracle(DetectionOracle):
    """One account accrues >= ``FAIL_THRESHOLD`` authentication FAILURES in a window. A forgetful user
    mistyping 3-4 times stays below the threshold → silent."""

    name = "brute_force"
    bug_class = "cred.brute_force"
    severity = "high"
    evidence_kind = "auth_log"
    default_grade = Grade.FACT
    window_seconds = 120
    window_events = 40
    FAIL_THRESHOLD = 8

    def _params(self) -> dict:
        return {**super()._params(), "fail_threshold": self.FAIL_THRESHOLD}

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        # group by the ACCOUNT under attack (per-account velocity).
        for user, evs in group_by(records, "user").items():
            def _velocity(window: list) -> bool:
                return len(_failures(window)) >= self.FAIL_THRESHOLD
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_velocity)
            if window:
                fails = _failures(window)
                srcs = sorted({getattr(e, "src", "") for e in fails if getattr(e, "src", "")})
                return OracleHit(
                    signature_kind="per-account-failure-velocity",
                    summary=f"brute force: account {user!r} saw {len(fails)} failures "
                            f"(>= {self.FAIL_THRESHOLD}) in a window from {srcs or ['?']}",
                    evidence_records=tuple(fails), source=srcs[0] if srcs else "",
                    params={"account": user, "failures": len(fails)},
                )
        return None


class PasswordSprayOracle(DetectionOracle):
    """One SOURCE fails against >= ``ACCOUNT_SPREAD`` distinct accounts, each with <= ``PER_ACCOUNT_MAX``
    failures, in a window (broad + shallow). A brute (one deep account) has spread 1 → does not fire
    here; a benign login surge is successes across accounts → no cross-account failures → silent."""

    name = "password_spray"
    bug_class = "cred.password_spray"
    severity = "high"
    evidence_kind = "auth_log"
    default_grade = Grade.FACT
    window_seconds = 300
    window_events = 200
    ACCOUNT_SPREAD = 8
    PER_ACCOUNT_MAX = 2

    def _params(self) -> dict:
        return {**super()._params(), "account_spread": self.ACCOUNT_SPREAD,
                "per_account_max": self.PER_ACCOUNT_MAX}

    def evaluate(self, records: Any) -> Optional[OracleHit]:
        # group by the SOURCE (spray is one origin fanning across accounts).
        for src, evs in group_by(records, "src").items():
            def _fanout(window: list) -> bool:
                per_user: dict = {}
                for e in _failures(window):
                    u = getattr(e, "user", "")
                    if u:
                        per_user[u] = per_user.get(u, 0) + 1
                broad = {u for u, c in per_user.items() if c <= self.PER_ACCOUNT_MAX}
                return len(broad) >= self.ACCOUNT_SPREAD
            window = windowed(evs, window_seconds=self.window_seconds,
                              window_events=self.window_events, predicate=_fanout)
            if window:
                fails = _failures(window)
                per_user2: dict = {}
                for e in fails:
                    u = getattr(e, "user", "")
                    if u:
                        per_user2[u] = per_user2.get(u, 0) + 1
                shallow = sorted(u for u, c in per_user2.items() if c <= self.PER_ACCOUNT_MAX)
                # evidence = only the shallow-account failures that constitute the fanout signature.
                ev = tuple(e for e in fails
                           if per_user2.get(getattr(e, "user", ""), 0) <= self.PER_ACCOUNT_MAX)
                return OracleHit(
                    signature_kind="cross-account-fanout",
                    summary=f"password spray: {src} failed against {len(shallow)} distinct accounts "
                            f"(>= {self.ACCOUNT_SPREAD}), each <= {self.PER_ACCOUNT_MAX} failures — "
                            f"source-fanout fingerprint (password not in auth.log)",
                    evidence_records=ev, source=src,
                    params={"account_spread": len(shallow), "accounts": shallow[:20]},
                )
        return None
