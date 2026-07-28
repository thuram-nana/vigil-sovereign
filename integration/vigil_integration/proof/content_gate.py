"""
proof.content_gate — the ONE new safety layer of the Proof Studio (B2), fail-closed by construction.

WARDEN gates tool *calls*; the destruction gate gates irreversible *actions*. Neither looks at the
CONTENT of a generated proof-of-concept. This gate does: before a ``poc_script_code`` is stored,
surfaced, replayed, or minted into a signed proof, it is screened for payload classes that must never be
persisted or re-run as part of a "proof" — detection-evasion, persistence, destructive wipes,
self-propagation (worming), and credential exfiltration. A pentest PoC demonstrates a vulnerability; it
does not need to disable the defender, install a backdoor, wipe the disk, spread to other hosts, or ship
the victim's secrets off-box, and a proof engine that would re-run such content is a liability.

Fail-closed discipline, modelled on :mod:`destruction_gate` (first failure wins; any error or malformed
input is a DENY):

  * A non-``str`` input, or content over the screen cap, is a DENY (a payload we cannot fully read is a
    payload we do not clear).
  * Any single category match is a DENY, labelled with the category and the matched token — the caller
    quarantines the content and the finding stays LEAD/CLEAR (no mint, replay refused).
  * The analyzer itself running into any exception is a DENY (``screen_poc_content`` never raises into a
    caller who might swallow it into an allow — it returns a DENY verdict).

Import-clean: stdlib only. No ``framework.*`` / ``strix.*`` / ``vigil_core`` — this runs in either env and
the mint consults it; it imports nothing back.

Scope, stated honestly: this is a deterministic PATTERN screen over known-dangerous constructs, not a
semantic analyzer. It is a fail-closed floor (it can only DENY, never bless), sized to catch the payload
classes above with near-zero false positives on ordinary injection PoCs (a SQLi tautology, a reflected-XSS
``<script>``, an SSRF URL are NOT flagged — they demonstrate the bug without the five dangerous behaviours).
It is defence in depth, not a claim that any allowed content is safe to execute.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

# Cap on the total text screened. A payload larger than this cannot be fully cleared, so it is DENIED
# (fail-closed) rather than partially scanned.
_MAX_SCREEN_BYTES = 1 << 20  # 1 MiB


@dataclass(frozen=True)
class ContentVerdict:
    """The screen's decision. ``allowed`` False means the content must be quarantined and never minted /
    replayed. ``category`` + ``matched`` name WHY (empty on allow)."""

    allowed: bool
    category: str = ""
    reason: str = ""
    matched: str = ""

    @property
    def denied(self) -> bool:
        return not self.allowed


# Category → ordered list of (label, compiled pattern). First match across all categories wins (the
# categories are checked in this dict's order). Patterns target genuinely malicious POST-exploitation
# behaviour, NOT the injection payloads a benign PoC uses to demonstrate a bug.
def _c(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE)


_CATEGORIES: "dict[str, list[tuple[str, re.Pattern[str]]]]" = {
    "detection_evasion": [
        ("disable_defender", _c(r"Set-MpPreference\s+.*-Disable(RealtimeMonitoring|IOAVProtection)")),
        ("amsi_bypass", _c(r"amsiInitFailed|AmsiScanBuffer|System\.Management\.Automation\.AmsiUtils")),
        ("clear_windows_eventlog", _c(r"\b(wevtutil\s+cl|Clear-EventLog|Clear-WinEvent)\b")),
        ("disable_audit", _c(r"\bauditpol\s+/(set|clear)\b|\bSet-MpPreference\s+-DisableScriptScanning")),
        ("clear_shell_history", _c(r"\bhistory\s+-c\b|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|rm\s+.*\.bash_history")),
        ("stop_security_service", _c(r"\b(systemctl\s+(stop|disable)\s+(auditd|falcon|osquery|crowdstrike)|net\s+stop\s+windefend)\b")),
        ("timestomp", _c(r"\btimestomp\b|touch\s+-[amt].*-r\s|\bSetFileTime\b")),
        ("secure_delete_traces", _c(r"\b(sdelete|shred\s+-u|wipe)\b.*\.(log|evtx|history)")),
    ],
    "persistence": [
        ("cron_install", _c(r"\bcrontab\s+-|>>?\s*/etc/cron|/etc/cron\.(d|daily|hourly)/")),
        ("systemd_unit", _c(r">\s*/etc/systemd/system/.*\.service|systemctl\s+enable\s+")),
        ("scheduled_task", _c(r"\bschtasks\s+/create\b|Register-ScheduledTask\b")),
        ("run_key", _c(r"CurrentVersion\\+Run|HKCU\\.*\\Run|HKLM\\.*\\Run")),
        ("rc_backdoor", _c(r">>?\s*/etc/rc\.local|>>?\s*~?/?\.(bashrc|bash_profile|profile|zshrc)\b.*(nc|bash\s+-i|/dev/tcp)")),
        ("launch_agent", _c(r"(LaunchAgents|LaunchDaemons)/.*\.plist")),
        ("ssh_authorized_keys", _c(r">>?\s*~?/?\.ssh/authorized_keys")),
        ("web_shell_drop", _c(r">\s*.*\.(php|jsp|aspx?)\b.*(system\(|eval\(|passthru\(|Runtime\.getRuntime)")),
    ],
    "destructive": [
        ("rm_rf_root", _c(r"\brm\s+-[rfRF]{1,3}\s+(/|/\*|~|/home|/etc|/var|--no-preserve-root)")),
        ("fork_bomb", _c(r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:")),
        ("disk_wipe", _c(r"\b(mkfs\.|wipefs|shred\s+/dev/|dd\s+if=/dev/(zero|urandom)\s+of=/dev/)")),
        ("overwrite_block_device", _c(r">\s*/dev/(sd[a-z]|nvme\d|vd[a-z]|xvd[a-z])\b")),
        ("windows_format", _c(r"\bformat\s+[a-z]:\s*/|cipher\s+/w:")),
        ("mass_drop_db", _c(r"\bDROP\s+DATABASE\b|\bTRUNCATE\s+TABLE\b.*;\s*DROP")),
        ("recursive_delete_all", _c(r"\b(Remove-Item|del)\b.*-Recurse.*-Force.*(C:\\|/)|find\s+/\s+-delete")),
    ],
    "self_propagating": [
        ("ssh_spread_loop", _c(r"for\s+\w+\s+in\s+.*(hosts|subnet|range).*;\s*do\s+.*ssh")),
        ("copy_self_remote", _c(r"(scp|rsync)\s+.*\$0\b|curl\s+.*-T\s+\$0|wget\s+.*\$0")),
        ("worm_replicate", _c(r"\b(psexec|wmic\s+/node:.*process\s+call\s+create)\b|paramiko.*for\s+.*connect")),
        ("mass_infect", _c(r"cp\s+\$0\s+.*&&.*(ssh|scp)|self[_-]?replicat")),
        ("spray_and_exec", _c(r"masscan.*\|\s*.*(curl|wget|sh)\b|nmap.*-oG\s+-\s*\|.*(sh|bash)\b")),
    ],
    "credential_exfil": [
        ("mimikatz", _c(r"\bmimikatz\b|sekurlsa::logonpasswords|lsadump::")),
        ("lsass_dump", _c(r"\bprocdump\b.*lsass|MiniDumpWriteDump|comsvcs\.dll,\s*MiniDump")),
        ("shadow_exfil", _c(r"(cat|cp|tar)\s+.*/etc/shadow.*\|\s*(nc|curl|wget|ncat|socat)")),
        ("ssh_key_exfil", _c(r"(cat|tar)\s+.*\.ssh/(id_(rsa|ed25519)|.*key).*\|\s*(nc|curl|wget|ncat)")),
        ("cloud_cred_exfil", _c(r"(cat|cp)\s+.*(\.aws/credentials|\.azure|gcloud.*credentials).*\|\s*(nc|curl|wget)")),
        ("browser_cred_theft", _c(r"Login\s*Data\b.*(select|sqlite3).*password|nss3.*PK11SDR_Decrypt")),
        ("env_secret_exfil", _c(r"\b(env|printenv|Get-ChildItem\s+Env:)\b.*\|\s*(curl|wget|nc)\s+.*http")),
        ("post_passwd_remote", _c(r"curl\s+.*(-d|--data)\s*@?/etc/(passwd|shadow)")),
    ],
}


def screen_poc_content(
    code: object,
    *,
    extra_texts: Iterable[object] = (),
) -> ContentVerdict:
    """Screen ``code`` (and any ``extra_texts`` — e.g. the evidence / poc_description fields, since a
    payload could hide there) for the five dangerous payload classes. Fail-closed: returns a DENY verdict
    on a non-``str`` input, oversized content, any category match, or any internal error — it NEVER raises
    into the caller. An empty / whitespace ``code`` with clean extras is ALLOWED (there is no payload to
    screen; the oracle, not this gate, decides whether the finding is proven)."""
    try:
        parts: list[str] = []
        for value in (code, *tuple(extra_texts)):
            if value is None or value == "":
                continue
            if not isinstance(value, str):
                return ContentVerdict(
                    allowed=False, category="malformed",
                    reason="content to screen is not a string (fail-closed)",
                    matched=type(value).__name__,
                )
            parts.append(value)
        blob = "\n".join(parts)
        if len(blob.encode("utf-8", errors="replace")) > _MAX_SCREEN_BYTES:
            return ContentVerdict(
                allowed=False, category="oversized",
                reason=f"content exceeds the {_MAX_SCREEN_BYTES}-byte screen cap — cannot clear, refused",
            )
        for category, patterns in _CATEGORIES.items():
            for label, rx in patterns:
                m = rx.search(blob)
                if m is not None:
                    snippet = m.group(0)
                    if len(snippet) > 120:
                        snippet = snippet[:120] + "..."
                    return ContentVerdict(
                        allowed=False, category=category,
                        reason=f"poc content matched a {category} pattern ({label}) — quarantined, not minted",
                        matched=snippet,
                    )
        return ContentVerdict(allowed=True, reason="no dangerous payload class matched")
    except Exception as exc:  # noqa: BLE001 - the analyzer erroring is itself a fail-closed DENY
        return ContentVerdict(
            allowed=False, category="analyzer_error",
            reason=f"content screen errored — fail closed ({type(exc).__name__})",
        )
