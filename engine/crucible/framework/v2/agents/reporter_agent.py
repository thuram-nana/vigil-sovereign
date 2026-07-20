"""
reporter_agent — synthesises confirmed Findings into the technical report.

Reads `findings` with `critique_status='confirmed'` and writes (or
updates) `targets/<slug>/reports/technical.md`. The reporter is
deliberately conservative: it does NOT promote findings whose
critique-agent flagged objections, and it never modifies the
executive or remediation reports — those are human-written from the
technical one in this session.

A single step regenerates the technical report from scratch, so the
output is always consistent with the current blackboard state. It
runs only when the set of confirmed findings has changed since last
emission.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ..common import paths
from typing import Iterator

from .base import Agent
from .blackboard import Blackboard, BlackboardEventRow
from .models import FindingPayload


class ReporterAgent(Agent):
    name = "reporter"

    def __init__(self, bb: Blackboard, engagement_slug: str) -> None:
        super().__init__(bb, engagement_slug)
        self._last_emitted_count = 0

    def should_run(self) -> bool:
        n = self._count_reportable_findings()
        return n > self._last_emitted_count

    def step(self) -> int:
        confirmed = list(self._reportable_findings())
        if not confirmed:
            return 0
        body = self._render(confirmed)
        out = paths.target_dir(self.slug) / "reports" / "technical.md"
        paths.secure_write(out, body)   # X2: findings report (PoCs/confirmed vulns) is owner-only
        self._last_emitted_count = len(confirmed)
        self._advance_cursor()
        return 1

    # ---- helpers ----

    def _confirmed_findings(self) -> Iterator[BlackboardEventRow]:
        """ORACLE-confirmed findings only (the sole authority's verdict)."""
        rows = self.bb.read(engagement=self.engagement_id, kinds=["finding"])
        for r in rows:
            if r.payload.get("critique_status") == "confirmed":
                yield r

    def _reportable_findings(self) -> Iterator[BlackboardEventRow]:
        """Findings the report renders: oracle-confirmed (as fact) AND llm_advisory
        (shown, but clearly labelled unconfirmed — label-don't-drop). An advisory
        finding is NEVER presented as a confirmed fact; the per-finding verification
        block distinguishes them."""
        rows = self.bb.read(engagement=self.engagement_id, kinds=["finding"])
        for r in rows:
            if r.payload.get("critique_status") in ("confirmed", "llm_advisory"):
                yield r

    def _count_confirmed_findings(self) -> int:
        return sum(1 for _ in self._confirmed_findings())

    def _count_reportable_findings(self) -> int:
        return sum(1 for _ in self._reportable_findings())

    def _admit(self, f: FindingPayload):
        """Re-execute the finding's OWN retained oracle_context at report time, rather than
        trusting the stored ``verified_by_oracle`` flag. Returns the AdmittedClaim (or None
        on error). A genuinely-confirmed finding whose proof still re-fires admits as a fact
        (identical to today); a finding recorded as confirmed whose proof no longer
        reproduces — tampered, or a dry-run stub — is demoted here and never asserted as a
        fact in the report. Pure and read-only; sends no traffic (the oracle re-runs over
        retained evidence).

        Delegates to ``report.grounding.admit_for_report`` — the single shared grounding
        authority the Wave-6 report layer reuses — so the reporter-agent and a rendered
        report grade a finding by the SAME re-execution. ``match_confidence=False`` there:
        the blackboard finding's confidence is CALIBRATED, not the raw oracle value, so the
        gate checks re-firing + bug_class binding without falsely demoting on the legitimate
        calibration delta. ``critique_dryrun`` is deliberately NOT propagated into the ORACLE
        token — that flag marks the LLM critique as a dry-run; the oracle ground is a
        deterministic re-fire of retained evidence, independent of the LLM, and the dry-run
        label is surfaced in the advisory (non-fact) branch below, not here."""
        try:
            from ..report.grounding import admit_for_report
            return admit_for_report(f, source="report:reporter")
        except Exception:
            return None

    def _render(self, confirmed_events: list[BlackboardEventRow]) -> str:
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings: list[tuple[int, FindingPayload, int]] = []
        for ev in confirmed_events:
            try:
                f = FindingPayload.model_validate(ev.payload)
                findings.append((sev_order.get(f.severity, 5), f, ev.id))
            except Exception:
                continue
        findings.sort(key=lambda x: (x[0], x[1].finding_slug))

        # Re-execute each finding's oracle ONCE, up front — the header counts and the
        # per-finding verification block both key on the LIVE verdict, so a finding whose
        # proof no longer re-fires is counted (and rendered) as a lead, not a fact.
        admitted = {eid: self._admit(f) for _s, f, eid in findings}

        def _is_fact(f: FindingPayload, eid: int) -> bool:
            a = admitted.get(eid)
            return a is not None and a.is_fact

        n_oracle = sum(1 for _s, f, eid in findings if _is_fact(f, eid))
        # a finding recorded oracle-confirmed whose proof did NOT re-verify at report time is
        # its own category — never lumped in with true LLM-advisory (no-oracle-signal) leads.
        n_demoted = sum(1 for _s, f, eid in findings
                        if not _is_fact(f, eid) and f.verified_by_oracle)
        n_advisory = len(findings) - n_oracle - n_demoted
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        lines: list[str] = [
            f"# Technical report — `{self.slug}`",
            "",
            f"Generated by reporter-agent at {ts} from blackboard state.",
            f"**{n_oracle}** oracle-confirmed finding(s)"
            + (f" · **{n_advisory}** LLM-advisory (unconfirmed) finding(s)" if n_advisory else "")
            + (f" · **{n_demoted}** demoted (recorded oracle, failed re-verification)" if n_demoted else "")
            + ".",
            "",
            "Grounding is per-finding and explicit:",
            "- An **oracle-confirmed** finding was verified by a deterministic oracle and carries "
            "a re-runnable certificate — it is a proven fact.",
            "- An **LLM-advisory** finding was flagged by reasoning but has NO deterministic oracle "
            "signal — it is a lead to verify, NOT a confirmed fact. See each finding's Verification section.",
            "- A **demoted** finding was recorded as oracle-confirmed but its retained proof did "
            "NOT re-verify when this report was generated — treat it as a lead, not a fact, and "
            "investigate why the evidence no longer reproduces.",
            "",
            "## Index",
            "",
        ]
        for _sev, f, _eid in findings:
            lines.append(f"- [{f.finding_slug} — {f.title}](#{f.finding_slug.lower()})  `{f.severity}`")
        lines.append("")

        for _sev, f, eid in findings:
            lines += [
                f"## {f.finding_slug}",
                "",
                f"**Title:** {f.title}",
                f"**Severity:** {f.severity}",
                f"**Bug class:** `{f.bug_class}`",
                f"**Surface:** `{f.surface}`",
                f"**Derived from hypothesis:** `{f.derived_from_hypothesis or '(none)'}`",
                f"**Blackboard event id:** {eid}",
                "",
                "### Summary",
                "",
                f.summary,
                "",
                "### Impact",
                "",
                f.impact or "_(unspecified)_",
                "",
            ]
            # Prove-don't-guess: surface HOW the finding was confirmed, gating the
            # assurance on a LIVE re-execution of the finding's oracle at report time — not
            # on the stored flag. An oracle-verified finding shows which oracle fired, the
            # RE-EXECUTED (never-1.0) confidence, and the oracle's rationale, so the report
            # carries the proof rather than merely asserting it.
            a = admitted.get(eid)
            if a is not None and a.is_fact:
                # the gate re-executed the oracle; show the stored CALIBRATED confidence
                # (byte-identical to before for a genuine finding — the re-execution is a
                # gate, not the value source).
                conf = f"{f.confidence:.3f}" if f.confidence is not None else "n/a"
                lines += [
                    "### Verification (deterministic oracle)",
                    "",
                    f"**Confirmed by oracle:** `{f.oracle_kind or 'unknown'}`  ",
                    f"**Calibrated confidence:** {conf}  ",
                    "",
                    f.oracle_rationale or "_(no rationale recorded)_",
                    "",
                ]
            elif f.verified_by_oracle:
                # recorded as oracle-confirmed at scan time, but the retained proof does
                # NOT re-verify now (altered evidence / a dry-run stub) — demote it rather
                # than assert a fact on a stale flag. This is the firewall catching a
                # "confirmed" that is no longer true.
                why = a.reason if a is not None else "no admissible ground at report time"
                lines += [
                    "### Verification (unverified at report time)",
                    "",
                    "_Recorded as oracle-confirmed, but its retained proof did NOT "
                    f"re-verify when this report was generated ({why}). Shown as a lead, "
                    "NOT a confirmed fact._",
                    "",
                ]
            else:
                dryrun = getattr(f, "critique_dryrun", False)
                note = ("_LLM-advisory confirmation — no deterministic oracle signal; "
                        "and produced by a DRY-RUN (canned) model call, NOT a live "
                        "inference. Treat as a placeholder lead only._" if dryrun else
                        "_LLM-advisory confirmation — no deterministic oracle signal. "
                        "A lead to verify, NOT a confirmed fact._")
                lines += ["### Verification", "", note, ""]
            if f.cvss_vector:
                lines += [f"**CVSS 3.1 vector:** `{f.cvss_vector}`  ", ""]
            if f.cvss_base is not None:
                lines += [f"**CVSS base score:** {f.cvss_base}", ""]
            lines += ["---", ""]

        lines += [
            "## Notes",
            "",
            "This file is regenerated by the reporter-agent on every "
            "engagement tick that changes the confirmed-findings set. "
            "Hand-edits will be overwritten.  For the executive summary "
            "and remediation roadmap, copy this content into "
            "`reports/executive.md` and `reports/remediation-roadmap.md` "
            "and adapt the framing per `framework/templates/`.",
            "",
        ]
        return "\n".join(lines)
