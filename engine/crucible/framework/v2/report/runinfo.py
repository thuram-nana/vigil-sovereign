"""
report.runinfo — the plain facts about ONE engagement run, read from what the run actually wrote.

The case file has to answer a non-specialist's first questions — *what was examined, when did it
start, when did it finish, how long did it take, what settings were used, and what do those
settings mean I did NOT get* — and it has to answer them from recorded data or not at all.

This module reads the small set of files a run leaves behind (``meta.json``, ``reverifiable.json``,
``progress.jsonl``, the stored ``report.json``) and returns a :class:`RunInfo` of exactly what was
recorded. Every field that has no source is ``None``, and the renderers print "not recorded" for
it. Nothing here estimates, back-calculates or fills in a plausible value.

Times are rendered in UTC and labelled as such. UTC is used deliberately: the recipient of a
dossier is often in a different country from the machine that produced it, and a bare local time
is ambiguous evidence.

Pure apart from reading files under the run directory; deterministic given the same run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Month names, so a date reads as a date to a reader who is not a programmer.
_MONTHS = ("January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December")

# Scan options whose PRESENCE materially narrows what was tested. Each maps to a plain-English
# statement of the limit it imposed. This is the backbone of the scope-honesty section: the
# document states the limits from the command that actually ran, not from a generic template.
_OPTION_MEANING: dict[str, str] = {
    "--no-oob": (
        "Out-of-band checks were switched OFF. Some serious weaknesses only reveal themselves "
        "when the tested system makes a connection back out to a listener under the tester's "
        "control. Those checks were not performed, so weaknesses of that kind would not have "
        "been found."
    ),
    "--targeted": (
        "The run was targeted rather than exhaustive: checks were focused on the specific "
        "address supplied, rather than sweeping every possibility."
    ),
    "--safe": "Only checks classified as safe for a live system were run.",
    "--dry-run": "This was a rehearsal: no live testing traffic was sent.",
    "--passive": "Only passive observation was performed; no test input was sent to the system.",
    "--no-crawl": "The site was not explored automatically; only the address supplied was examined.",
}

# Options that carry a value, with a template for the plain-English limit they impose.
_OPTION_VALUE_MEANING: dict[str, str] = {
    "--max-pages": (
        "At most {value} page(s) of the site were explored. Anything beyond that limit was not "
        "examined."
    ),
    "--max-requests": "At most {value} test request(s) were sent in total.",
    "--timeout": "Each request was given at most {value} second(s) to respond.",
    "--rate": "Requests were sent at no more than {value} per second, to avoid disturbing the system.",
}


def human_time(value: Any) -> Optional[str]:
    """A recorded time as a sentence a non-specialist can read, in UTC and labelled — e.g.
    ``"29 July 2026 at 15:20:10 UTC"``. Accepts a UNIX timestamp (int/float) or an ISO-8601
    string. Returns ``None`` when the value is missing or unreadable, so the caller prints
    "not recorded" rather than inventing a time."""
    dt = _to_datetime(value)
    if dt is None:
        return None
    return f"{dt.day} {_MONTHS[dt.month - 1]} {dt.year} at {dt:%H:%M:%S} UTC"


def _to_datetime(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    # a numeric string is a UNIX timestamp
    try:
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def human_duration(seconds: Any) -> Optional[str]:
    """A measured duration in words: ``"0.23 seconds"``, ``"4 minutes 12 seconds"``. ``None``
    when nothing was recorded."""
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return None
    if s < 0:
        return None
    if s < 1:
        return f"{s:.2f} seconds"
    if s < 60:
        return f"{s:.1f} seconds"
    minutes, rest = divmod(int(round(s)), 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} {rest} second{'s' if rest != 1 else ''}"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} hour{'s' if hours != 1 else ''} {minutes} minute{'s' if minutes != 1 else ''}"


@dataclass
class ScopeLimit:
    """One recorded limit on what was tested, with the option that imposed it."""

    option: str
    meaning: str


# --------------------------------------------------------------------------------------------------
# operation types
#
# A dossier is not always a web test. The console launches seven kinds of operation, each recording a
# different subject and a different set of artefacts, and a case file that assumed the web shape would
# describe a cloud assessment as "Target: http://…" — wrong on its face to anyone who knows the
# domain, and a straightforward misrepresentation to anyone who does not.
#
# ``records_*`` below states which artefact families each operation type is known to write TODAY,
# established by reading the launch paths in ``console/actions.py``:
#
#   launch_scan / launch_assessment(mode="url", loopback)
#       spawns `framework.v2 scan … --reverifiable-out …` with capture_report=True
#       → meta.json, progress.jsonl, report.json, reverifiable.json.  findings + proofs.
#   launch_assessment(mode="codebase")
#       spawns Strix with VIGIL_PROOF_RUN_DIR set, capture_report=False
#       → meta.json + proofs/ + evidence/ when the proof studio mints one.  proofs, NO findings file.
#   launch_cloud(mode in {cloud, k8s, infra})
#       spawns `engage <slug> --fuse-only --spine`, no report capture
#       → meta.json + progress.jsonl only.  neither.
#   launch_assessment(mode in {aegis, suite, tool}) and the blackboard `engage` path
#       → meta.json (+ progress.jsonl).  neither.
#
# The distinction this table buys is the one that matters: an absent section can be reported as "this
# operation type does not record that" rather than as "nothing was found". Those are opposite claims,
# and only the first is true. When a type that SHOULD record something has not, that is reported too —
# as an incomplete record, which is a defect worth surfacing rather than silently rendering as empty.
# --------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class OperationType:
    """One kind of engagement, and what its records can support."""

    key: str
    name: str                      # what to call it in a sentence
    subject_label: str             # what its subject IS ("Codebase examined", "Cloud account …")
    subject_kind: str              # how to describe the subject's form, for a reader
    records_findings: bool         # writes a structured findings record (report.json)
    records_proofs: bool           # can write retained proofs (reverifiable.json / proofs/)
    records_coverage: bool = False  # writes which checks it attempted (nothing does, today)
    note: str = ""                 # anything a reader needs to know about this type's records


_OPERATION_TYPES: dict[str, OperationType] = {
    "url": OperationType(
        key="url", name="web application test",
        subject_label="Web address examined", subject_kind="a web address",
        records_findings=True, records_proofs=True),
    "codebase": OperationType(
        key="codebase", name="source-code review",
        subject_label="Codebase examined", subject_kind="a folder of source code",
        records_findings=False, records_proofs=True,
        note="A source-code review records the proofs it establishes, but it does not write a "
             "structured list of findings the way a web test does. Its narrative output is the "
             "reviewing tool's own log."),
    "cloud": OperationType(
        key="cloud", name="cloud posture assessment",
        subject_label="Cloud account examined", subject_kind="an account or subscription label",
        records_findings=False, records_proofs=False,
        note="A cloud posture assessment currently records only that it ran, and its own summary "
             "text. It does not yet write a structured findings record or retained proofs."),
    "k8s": OperationType(
        key="k8s", name="Kubernetes posture assessment",
        subject_label="Cluster examined", subject_kind="a cluster label",
        records_findings=False, records_proofs=False,
        note="A Kubernetes posture assessment currently records only that it ran, and its own "
             "summary text. It does not yet write a structured findings record or retained proofs."),
    "infra": OperationType(
        key="infra", name="infrastructure posture assessment",
        subject_label="Infrastructure examined", subject_kind="a host or service label",
        records_findings=False, records_proofs=False,
        note="An infrastructure posture assessment currently records only that it ran, and its own "
             "summary text. It does not yet write a structured findings record or retained proofs."),
    "aegis": OperationType(
        key="aegis", name="defensive monitoring run",
        subject_label="Log sources examined", subject_kind="a set of log files",
        records_findings=False, records_proofs=False,
        note="A defensive monitoring run watches the organisation's own logs. It currently records "
             "only that it ran; it does not write a structured findings record."),
    "suite": OperationType(
        key="suite", name="tool suite run",
        subject_label="Subject examined", subject_kind="whatever the chosen tools accept",
        records_findings=False, records_proofs=False,
        note="A tool suite run currently records only that it ran and which tools were chosen. It "
             "does not write a structured findings record."),
    "tool": OperationType(
        key="tool", name="single tool run",
        subject_label="Subject examined", subject_kind="whatever the chosen tool accepts",
        records_findings=False, records_proofs=False,
        note="A single tool run currently records only that it ran and which tool was chosen. It "
             "does not write a structured findings record."),
}

UNKNOWN_OPERATION = OperationType(
    key="unknown", name="engagement",
    subject_label="Subject examined", subject_kind="not recorded",
    records_findings=False, records_proofs=False,
    note="The run record does not say what kind of operation this was, and it could not be "
         "determined from the command either. Everything below is therefore reported from whatever "
         "the run left behind, without assuming what it should have contained.")


def operation_type(key: str) -> OperationType:
    return _OPERATION_TYPES.get((key or "").strip().lower(), UNKNOWN_OPERATION)


def _infer_mode(cmd: list[str], meta: dict) -> tuple[str, str]:
    """``(mode key, how it was determined)`` — from the recorded ``mode`` when the launcher wrote
    one, otherwise from the command it recorded. ``launch_scan`` writes no ``mode`` at all, so a
    plain scan run has to be recognised by its command; that inference is reported as an inference,
    never as a recorded fact."""
    recorded = str(meta.get("mode") or "").strip().lower()
    if recorded in _OPERATION_TYPES:
        return (recorded, "recorded by the launcher")
    joined = " ".join(str(c) for c in cmd)
    if "framework.v2" in joined and " scan " in f" {joined} ":
        return ("url", "inferred from the recorded command (a web scan)")
    if "strix" in joined:
        return ("codebase", "inferred from the recorded command (a source-code review)")
    if "--fuse-only" in joined:
        # cloud / k8s / infra all spawn the same fused engage; without a recorded mode they cannot
        # be told apart, so the sensor name is consulted and otherwise the type stays unknown.
        sensor = str(meta.get("sensor") or "").lower()
        if "kube" in sensor:
            return ("k8s", "inferred from the recorded sensor")
        if "cloud" in sensor:
            return ("cloud", "inferred from the recorded sensor")
        return ("infra", "inferred from the recorded command (a posture assessment)")
    if "aegis" in joined:
        return ("aegis", "inferred from the recorded command")
    if recorded:
        return (recorded, "recorded by the launcher, but not a type this document knows")
    return ("unknown", "not recorded, and not determinable from the command")


@dataclass
class Subject:
    """What was examined, in the vocabulary of THIS kind of operation."""

    label: str = "Subject examined"
    value: str = "not recorded"
    detail: list[tuple[str, str]] = field(default_factory=list)
    unrecorded: list[str] = field(default_factory=list)   # aspects this type does not record


@dataclass
class RunInfo:
    """What the run recorded about itself. Every optional field is ``None`` when the run did
    not record it — the documents then say "not recorded" rather than guessing."""

    run_id: str = ""
    target: Optional[str] = None
    status: Optional[str] = None
    started: Optional[str] = None            # human, UTC
    finished: Optional[str] = None           # human, UTC
    duration: Optional[str] = None           # human
    command: list[str] = field(default_factory=list)
    limits: list[ScopeLimit] = field(default_factory=list)
    pages_examined: Optional[int] = None
    requests_examined: Optional[int] = None
    test_requests_sent: Optional[int] = None
    endpoints_discovered: Optional[int] = None
    finding_times: dict[str, str] = field(default_factory=dict)   # bug class -> human time
    notes: list[str] = field(default_factory=list)
    # what kind of operation this was, how that was determined, and what it examined
    operation: OperationType = UNKNOWN_OPERATION
    mode_source: str = ""
    subject: Subject = field(default_factory=Subject)
    # which artefact families this run's directory ACTUALLY contains (observed, not assumed)
    has_findings_record: bool = False
    has_retained_proofs: bool = False

    @property
    def started_text(self) -> str:
        return self.started or "not recorded"

    @property
    def finished_text(self) -> str:
        return self.finished or "not recorded"

    @property
    def duration_text(self) -> str:
        return self.duration or "not recorded"

    def artefact_gap(self, family: str) -> Optional[str]:
        """A sentence explaining why a section cannot be produced, or ``None`` when the material is
        present. ``family`` is ``"findings"`` or ``"proofs"``.

        Three outcomes, and keeping them apart is the whole point of this method:

          * present            → ``None``; render the section normally.
          * this type does not record it → say exactly that, so an empty section is never read as
            an examination that found nothing.
          * this type DOES record it, but this run has not → say that too. A missing artefact from
            a type that writes one is an incomplete record, which is a defect worth surfacing."""
        present = self.has_findings_record if family == "findings" else self.has_retained_proofs
        if present:
            return None
        expected = (self.operation.records_findings if family == "findings"
                    else self.operation.records_proofs)
        what = ("a structured list of findings" if family == "findings"
                else "saved evidence that proofs can be re-run from")
        if not expected:
            return (
                f"This engagement was {_article(self.operation.name)} {self.operation.name}, and "
                f"that kind of operation does not currently record {what}. This section therefore "
                f"cannot be produced for this engagement. **Read that as a gap in what was "
                f"recorded, not as a finding that nothing is wrong** — no conclusion about the "
                f"subject follows from it."
            )
        return (
            f"{_article(self.operation.name).capitalize()} {self.operation.name} normally records "
            f"{what}, but this run's record does not contain it. The record is incomplete. This "
            f"section cannot be produced, and again that says nothing about the subject — it says "
            f"something went wrong with the run or with what it saved."
        )


def _article(word: str) -> str:
    return "an" if (word or "")[:1].lower() in "aeiou" else "a"


def _build_subject(op: OperationType, meta: dict, target: Optional[str]) -> Subject:
    """What was examined, described in the vocabulary of this operation type. Only fields the
    launcher actually recorded are shown; every aspect a reader might expect but that is NOT
    recorded is listed in ``unrecorded`` so the document can say so out loud."""
    value = (target or "").strip() or "not recorded"
    s = Subject(label=op.subject_label, value=value)

    def add(key: str, label: str) -> None:
        v = meta.get(key)
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v if str(x).strip())
        v = str(v or "").strip()
        if v:
            s.detail.append((label, v))

    if op.key == "codebase":
        name = Path(value).name if value != "not recorded" else ""
        if name:
            s.detail.append(("Repository or folder name", name))
        add("objective", "What the reviewer was asked to look at")
        s.unrecorded += [
            "which files were read, and how many",
            "which functions or components were examined",
            "the commit or version of the code that was reviewed",
        ]
    elif op.key == "cloud":
        add("provider", "Cloud provider")
        add("sensor", "How the account was read")
        add("fusion_json", "The plan file that defined what to collect")
        s.unrecorded += [
            "which regions were covered",
            "which individual resources were examined",
            "which accounts or subscriptions beyond the one named above",
        ]
    elif op.key == "k8s":
        add("sensor", "How the cluster was read")
        add("fusion_json", "The plan file that defined what to collect")
        s.unrecorded += [
            "which namespaces were covered",
            "which workloads, roles or bindings were examined",
        ]
    elif op.key == "infra":
        add("sensor", "How the estate was read")
        s.unrecorded += ["which hosts and services were reached", "which ports were examined"]
    elif op.key == "aegis":
        add("scan_mode", "Monitoring mode")
        s.unrecorded += ["which log files were read", "the period the logs covered"]
    elif op.key in ("suite", "tool"):
        add("tools", "Tools chosen")
        add("objective", "What was asked for")
        s.unrecorded += ["what each tool examined", "what each tool reported"]
    elif op.key == "url":
        add("scan_mode", "Depth setting")
        add("objective", "What was asked for")

    scope = meta.get("scope")
    if isinstance(scope, (list, tuple)) and scope:
        s.detail.append(("Scope recorded at launch", ", ".join(str(x) for x in scope)))
    return s


def _read_json(path: Path) -> Any:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _parse_limits(cmd: list[str]) -> list[ScopeLimit]:
    """Turn the recorded command line into the plain-English limits it imposed. Only options
    this module has a written meaning for are reported — an unrecognised option is left out
    rather than described with a guess."""
    limits: list[ScopeLimit] = []
    seen: set[str] = set()
    for i, tok in enumerate(cmd):
        opt = str(tok)
        if opt in _OPTION_MEANING and opt not in seen:
            seen.add(opt)
            limits.append(ScopeLimit(option=opt, meaning=_OPTION_MEANING[opt]))
            continue
        base, _, inline = opt.partition("=")
        if base in _OPTION_VALUE_MEANING and base not in seen:
            value = inline or (cmd[i + 1] if i + 1 < len(cmd) else "")
            if value and not str(value).startswith("-"):
                seen.add(base)
                limits.append(ScopeLimit(
                    option=f"{base} {value}",
                    meaning=_OPTION_VALUE_MEANING[base].format(value=value)))
    return limits


_TS_KEYS = ("ts", "time", "timestamp", "at")


def _progress_finding_times(run_dir: Path) -> dict[str, str]:
    """Per-finding confirmation times, IF the progress log recorded any. The scan progress log
    is a JSON-lines stream; a ``scan.finding`` line carries a timestamp only when the producer
    wrote one. When it did not, this returns ``{}`` and the documents say the time was not
    recorded for individual findings."""
    p = run_dir / "progress.jsonl"
    if p.is_symlink() or not p.is_file():
        return {}
    out: dict[str, str] = {}
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict) or obj.get("event") != "scan.finding":
            continue
        for key in _TS_KEYS:
            if key in obj:
                human = human_time(obj[key])
                if human:
                    out[str(obj.get("bug_class") or "")] = human
                break
    return out


def read_run_info(run_dir: Path | str, export_doc: Any = None) -> RunInfo:
    """Read everything the run recorded about itself. ``export_doc`` is the already-parsed
    stored ``report.json`` when the caller has it (its ``summary`` carries the coverage
    counts). Never raises: an absent or malformed file simply leaves fields unrecorded."""
    run = Path(run_dir)
    info = RunInfo(run_id=run.name)

    meta = _read_json(run / "meta.json")
    if not isinstance(meta, dict):
        meta = {}
    if meta:
        info.target = str(meta.get("target") or "").strip() or None
        info.status = str(meta.get("status") or "").strip() or None
        info.started = human_time(meta.get("started"))
        info.finished = human_time(meta.get("finished"))
        cmd = meta.get("cmd")
        if isinstance(cmd, list):
            info.command = [str(c) for c in cmd]
            info.limits = _parse_limits(info.command)

    # The measured duration lives with the re-verifiable material the scanner wrote.
    rv = _read_json(run / "reverifiable.json")
    if isinstance(rv, dict):
        info.duration = human_duration(rv.get("elapsed_s"))
        for attr, key in (("pages_examined", "pages_crawled"),
                          ("requests_examined", "requests_audited"),
                          ("test_requests_sent", "audit_requests_sent")):
            v = rv.get(key)
            if isinstance(v, int):
                setattr(info, attr, v)
        if info.target is None:
            info.target = str(rv.get("target") or "").strip() or None

    if isinstance(export_doc, dict):
        if info.target is None:
            info.target = str(export_doc.get("target") or "").strip() or None
        summary = export_doc.get("summary")
        if isinstance(summary, dict):
            for attr, key in (("pages_examined", "pages_crawled"),
                              ("requests_examined", "requests_audited"),
                              ("endpoints_discovered", "discovered_endpoints")):
                v = summary.get(key)
                if isinstance(v, int) and getattr(info, attr) is None:
                    setattr(info, attr, v)

    info.finding_times = _progress_finding_times(run)

    # ---- what KIND of operation this was, and what it examined ---------------------------------
    mode_key, how = _infer_mode(info.command, meta)
    info.operation = operation_type(mode_key)
    info.mode_source = how
    info.subject = _build_subject(info.operation, meta, info.target)

    # What the run directory ACTUALLY holds — observed, never assumed from the operation type.
    info.has_findings_record = (run / "report.json").is_file() and not (run / "report.json").is_symlink()
    info.has_retained_proofs = any(
        (run / rel).is_file() and not (run / rel).is_symlink()
        for rel in ("reverifiable.json", "proofs/reverifiable.json")
    )

    if info.operation is UNKNOWN_OPERATION:
        info.notes.append(
            "The run record does not say what kind of operation this was. Everything in this pack "
            "is therefore reported from what the run actually left behind, with no assumption "
            "about what it should have contained."
        )
    elif how.startswith("inferred"):
        info.notes.append(
            f"The kind of operation was not written down by the launcher; it was {how}. If that is "
            f"wrong, the descriptions of the subject and of what was recorded will be wrong with it."
        )

    if info.started is None and info.finished is not None:
        info.notes.append(
            "The run recorded when it finished but not when it started, so no start time is "
            "stated. The measured duration is reported separately where it was recorded."
        )
    if not info.finding_times:
        info.notes.append(
            "The engine did not record a separate time for each individual finding. All "
            "findings were produced within the single engagement window stated above."
        )
    return info


# --------------------------------------------------------------------------------------------------
# a redaction pass for anything read out of a command line into a hand-to-anyone document
# --------------------------------------------------------------------------------------------------

_URL_USERINFO_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s:@]+(?::[^/\s@]*)?@")


def safe_command_token(token: str) -> str:
    """Strip credentials embedded in a URL argument before a command line is printed into a
    document that will be handed to a third party. Display-only."""
    return _URL_USERINFO_RE.sub(lambda m: m.group(1) + "[redacted]@", str(token or ""))
