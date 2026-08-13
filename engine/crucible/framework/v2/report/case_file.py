"""
report.case_file — the plain-English case file that makes a dossier readable end to end.

A dossier already proves things. Until now it did not *explain* them: the archive held a
machine-readable export and a cryptographic proof bundle, which is exactly the right evidence
and exactly the wrong reading material for the people a dossier is usually handed to — a
regulator, an auditor, a government official, a client executive. This module writes the part
they read.

It produces nine numbered documents, so the reading order is obvious from the file names::

    00-START-HERE.html        the one page to open; explains every other file in the archive
    01-executive-summary.md   what was done, what was found, what it means, what to do first
    02-approach-and-scope.md  how the work was done — and what was NOT examined
    03-findings.md            every proven finding, in plain language
    04-leads.md               what was observed or suspected but NOT proven
    05-what-was-looked-for.md every category the engine can confirm, and this run's position
    06-what-to-do.md          the prioritised remediation order
    07-verify-it-yourself.md  the exact commands, and what a pass and a failure look like
    08-glossary.md            every technical term used anywhere in the dossier

Three rules run through all of it:

  * **Meaning before mechanism.** Every section opens with what something means for the
    organisation and only then describes how it works.
  * **Say the limits out loud.** A proven finding states what it proves *and* what it does not.
    A section on what was tested is followed immediately by what was not. Absence of a finding
    is never allowed to read as evidence of safety.
  * **Never assert what was not measured.** Timestamps, counts and settings come from what the
    run recorded. Where a value was not recorded, the documents say "not recorded". The
    plain-language descriptions of weakness categories are generic, well-established knowledge
    (the same standing as the class-level remediation table in :mod:`report.generate`); where
    no such description is on file, the document says so and reproduces the engine's own words
    instead of inventing a friendlier version.

Pure and deterministic: a pure function of the graded findings, the adapter's extras, the run
facts and the archive listing. No wallclock (the build time is injected), no RNG, no I/O.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .adapt import AdaptResult, FindingExtras
from .grounding import GRADE_DEMOTED, GradedFinding
from .howto import finding_specific_remediation
from .catalogue import COVERAGE_GAP_NOTE, Catalogue, build_catalogue
from .plainspeak import oracle_plain as _oracle_plain
from .plainspeak import (category_title, oracle_establishes, oracle_plain_map,
                         plain_for as _plain_for, short_plain)
from .priority import effort_size, prioritize
from .runinfo import RunInfo, human_time, safe_command_token

# The documents this module always writes, in reading order. Every one is emitted on every
# build, even when it has nothing to report — a document that says "none" is information; a
# missing document is a gap the reader has to wonder about.
START_HERE = "00-START-HERE.html"
DOC_EXECUTIVE = "01-executive-summary.md"
DOC_APPROACH = "02-approach-and-scope.md"
DOC_FINDINGS = "03-findings.md"
DOC_LEADS = "04-leads.md"
DOC_CATALOGUE = "05-what-was-looked-for.md"
DOC_WHAT_TO_DO = "06-what-to-do.md"
DOC_VERIFY = "07-verify-it-yourself.md"
DOC_GLOSSARY = "08-glossary.md"

CASE_FILE_NAMES: tuple[str, ...] = (
    START_HERE, DOC_EXECUTIVE, DOC_APPROACH, DOC_FINDINGS,
    DOC_LEADS, DOC_CATALOGUE, DOC_WHAT_TO_DO, DOC_VERIFY, DOC_GLOSSARY,
)

_EFFORT_WORDS = {
    "S": "small — hours of engineering work",
    "M": "moderate — days of engineering work",
    "L": "large — weeks of engineering work",
    "XL": "very large — a quarter or more of engineering work",
}

_SEVERITY_WORDS = {
    "Critical": "Critical — treat as an emergency",
    "High": "High — schedule before other work",
    "Medium": "Medium — schedule in the normal cycle",
    "Low": "Low — worth fixing, not urgent",
    "Info": "Informational — no direct harm identified",
}



@dataclass
class _Item:
    """One finding as the case file presents it: the graded finding plus everything the export
    carried that the grader's model has no field for."""

    graded: GradedFinding
    extras: FindingExtras
    what: str
    why: str
    generic: bool          # True when no plain-language description was on file for the category

    @property
    def title(self) -> str:
        """A readable title.

        The engine records titles in its own shorthand ("boolean_sqli confirmed at q"), which is
        jargon in a document written for someone with no technical background. Where a readable
        name for the category is on file, the title is composed from that name and the finding's
        OWN recorded parameter — both fields the finding already carries, so this derives rather
        than invents. Where no readable name is on file, the engine's title is used unchanged, and
        the recorded title is shown alongside in every case so nothing is replaced silently."""
        name = category_title(self.graded.finding.bug_class)
        if not name:
            return _md_inline(self.graded.finding.title)
        param = self.extras.parameter or ""
        if param:
            return f"{name} in the '{_md_inline(param)}' parameter"
        return name

    @property
    def recorded_title(self) -> Optional[str]:
        """The engine's own title, when it differs from the readable one."""
        raw = _md_inline(self.graded.finding.title)
        return raw if raw and raw != self.title else None

    @property
    def where(self) -> str:
        """Where the finding is, without the engine's internal position token."""
        loc = self.extras.endpoint or self.extras.location or self.graded.finding.surface or ""
        return _md_inline(loc) or "not recorded"


# --------------------------------------------------------------------------------------------------
# small shared helpers
# --------------------------------------------------------------------------------------------------


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _plain(s: Any) -> str:
    """Drop Markdown emphasis from a sentence written for the .md documents before it is put
    into the HTML page, where `**` would render literally."""
    return str(s if s is not None else "").replace("**", "")


def _md_inline(s: Any) -> str:
    """Neutralise Markdown control characters in text taken from a finding, so an odd title
    cannot break the document's structure. Display-only."""
    return str(s if s is not None else "").replace("`", "'").replace("\n", " ").replace("\r", " ").strip()


def _count_word(n: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _header(title: str, label: str, run_id: str, built: Optional[str]) -> list[str]:
    return [
        f"# {title}",
        "",
        f"**Engagement:** {_md_inline(label)}  ",
        f"**Reference number:** `{_md_inline(run_id)}`  ",
        f"**This document was produced:** {built or 'not recorded'}  ",
        "",
    ]


# The boundaries inherent in each KIND of examination — the things that were out of reach for
# reasons no setting could change. Written per operation type, because the honest limits of a
# source-code review (no running system, so nothing about deployment or configuration) are not the
# limits of a cloud posture assessment (configuration only, so nothing about the applications
# running on it). A type with no entry gets the conservative default.
_INHERENT_LIMITS: dict[str, tuple[str, ...]] = {
    "url": (
        "- **Only the address named above, and what could be reached from it.** Other systems, "
        "other addresses, other environments and internal networks were not examined.",
        "- **Only what was reachable without credentials that were not supplied.** Areas behind a "
        "login, a payment step, or a role that was not provided remained unvisited, and therefore "
        "unexamined.",
    ),
    "codebase": (
        "- **Only the source code, as written.** A review of code cannot observe how the running "
        "service is configured, what it is connected to, or what data it holds. A weakness that "
        "exists only in deployment or configuration is invisible to it.",
        "- **Only the code that was present.** Dependencies pulled in at build time, generated "
        "code, and anything held in a different repository were not examined unless they were in "
        "the folder named above.",
        "- **The version of the code is not recorded**, so this pack cannot state which commit was "
        "reviewed. Treat it as describing the code as it stood when the review ran.",
    ),
    "cloud": (
        "- **Only the account named above, and only its configuration.** A posture assessment "
        "reads how the account is set up. It does not test the applications running inside it, and "
        "a weakness in an application would not appear here.",
        "- **Only what the collection step returned.** Regions, services and resources the "
        "collection did not cover are not covered by this pack, and which those were is not "
        "recorded.",
    ),
    "k8s": (
        "- **Only the cluster named above, and only its configuration.** This reads how the "
        "cluster is set up. It does not test the applications running in it.",
        "- **Only what the collection step returned.** Namespaces and workloads the collection did "
        "not cover are not covered here, and which those were is not recorded.",
    ),
    "infra": (
        "- **Only the hosts and services declared in the plan.** Anything not declared was not "
        "examined, and the declaration is a statement of intent rather than a discovery.",
    ),
    "aegis": (
        "- **Only the logs that were supplied, for the period they cover.** An attack that left no "
        "trace in those logs, or that happened outside the period, cannot appear here.",
    ),
}

_INHERENT_LIMITS_DEFAULT: tuple[str, ...] = (
    "- **Only what this kind of operation reaches.** The boundaries of this operation type are not "
    "written down anywhere this pack can read, so they cannot be listed precisely. Ask the team "
    "that ran it what it did and did not cover before relying on the result.",
)


def _subject_block(info: RunInfo) -> list[str]:
    """The subject, in this operation type's own vocabulary. A source-code review names a
    repository; a cloud assessment names an account and its provider; a web test names an address.
    Forcing all of them into a single "Target" line would misdescribe most engagements."""
    L = [f"- **{info.subject.label}:** `{_md_inline(info.subject.value)}`"]
    for key, value in info.subject.detail:
        L.append(f"- **{_md_inline(key)}:** {_md_inline(value)}")
    L.append(f"- **Kind of work:** {info.operation.name}")
    return L


def _subject_unrecorded_block(info: RunInfo) -> list[str]:
    """The aspects of the subject that this kind of operation does NOT record. Stating them is what
    stops a reader assuming the examination covered ground it never recorded covering."""
    if not info.subject.unrecorded:
        return []
    L = [f"The record of {_article(info.operation.name)} {info.operation.name} does not capture "
         "everything a reader might reasonably expect. In particular it does not record:", ""]
    for item in info.subject.unrecorded:
        L.append(f"- {item}")
    L += ["",
          "Those are gaps in what was written down. They are not statements that the work did not "
          "happen, and they are not statements that anything is fine.", ""]
    return L


def _article(word: str) -> str:
    return "an" if (word or "")[:1].lower() in "aeiou" else "a"


def _extra_proofs_note(n_certs: int, n_facts: int) -> Optional[str]:
    """A reconciliation sentence when the evidence bundle carries MORE proofs than there are proven
    findings in the findings record.

    The two numbers come from different places and can legitimately differ: the findings record is
    written by one kind of run, while proofs accumulate in the run directory from any tool that
    minted one. A reader who sees "2 proven findings" here and "3 certificates" in the evidence
    bundle would otherwise be left to guess which is wrong — and would be right to distrust both.
    Saying so plainly costs a sentence and keeps the archive internally consistent."""
    extra = n_certs - n_facts
    if extra <= 0:
        return None
    return (
        f"The evidence bundle in this pack carries {_count_word(n_certs, 'proof')}, which is "
        f"{extra} more than the {_count_word(n_facts, 'proven finding')} described "
        f"here. That is not a contradiction. The findings above come from the examination's own "
        f"findings record; the additional {_count_word(extra, 'proof')} were saved into this "
        f"engagement's working directory by other tooling and were not matched to any entry in "
        f"that record. They are included because they are part of the evidence, and they can be "
        f"re-checked with everything else — but no finding in this pack rests on them, and no "
        f"claim is made about what they show."
    )


def _remediation_text(item: _Item) -> str:
    """The fix to recommend. The scanner's own finding-specific text is preferred when the export
    carried one; otherwise the class-level rule, woven with this finding's parameter."""
    if item.extras.scanner_remediation:
        return item.extras.scanner_remediation
    return finding_specific_remediation(item.graded.finding)


def _where(item: _Item) -> str:
    """Where the finding is, in a form a person can read. The engine's location carries an internal
    position token (``[query_value:0]``) that means nothing outside the engine; the readable form
    names the address and the affected parameter separately."""
    return item.where


def _confirmed_time(item: _Item, info: RunInfo) -> str:
    t = info.finding_times.get(item.graded.finding.bug_class)
    if t:
        return t
    if info.finished:
        return (f"not recorded individually; produced during the engagement that finished on "
                f"{info.finished}")
    return "not recorded"


def _standards_line(item: _Item) -> Optional[str]:
    refs = item.extras.references
    if not refs:
        return None
    return ("**Recognised category:** " + ", ".join(f"`{_md_inline(r)}`" for r in refs) +
            ". These are identifiers in public catalogues of weakness categories (see the "
            "glossary), included so the finding can be cross-referenced against other reports "
            "and standards.")


# --------------------------------------------------------------------------------------------------
# 01 — executive summary
# --------------------------------------------------------------------------------------------------


def render_executive(*, label: str, info: RunInfo, facts: list[_Item], observed: list[_Item],
                     unproven: list[_Item], built: Optional[str], signed: bool,
                     proof_ok: bool, n_certs: int = 0) -> str:
    n_f, n_o, n_u = len(facts), len(observed), len(unproven)
    L = _header("Executive summary", label, info.run_id, built)
    L += [
        "## What this is",
        "",
        f"This is the summary of an authorised {info.operation.name} carried out on something this "
        "organisation owns. It was done with permission, against the organisation's own property. "
        "Nothing in it was obtained from anybody else's systems.",
        "",
        "It is written to be read without a technical background. Every technical term used "
        "anywhere in this pack is explained in `08-glossary.md`.",
        "",
        "## What was examined",
        "",
    ]
    L += _subject_block(info)
    L += [
        f"- **Examination started:** {info.started_text}",
        f"- **Examination finished:** {info.finished_text}",
        f"- **Time taken:** {info.duration_text}",
        f"- **This pack was produced:** {built or 'not recorded'}",
        "",
    ]
    L += _subject_unrecorded_block(info)
    if info.notes:
        L += ["Where something reads *not recorded*, the run genuinely did not record it. Nothing "
              "in this pack has been estimated or reconstructed to fill such a gap.", ""]

    L += ["## What was found", "",
          "Findings are separated by how strongly they are established. That distinction is the "
          "most important thing on this page, so it is stated before any numbers:", "",
          "- **Proven.** The examination performed the action and the result was confirmed by an "
          "automatic check. The evidence was saved, and the check was run again from that saved "
          "evidence while this pack was being assembled, with the same result. Anyone can repeat "
          "that themselves — see `07-verify-it-yourself.md`.",
          "- **Observed but not exploited.** Something was directly seen to be missing or "
          "misconfigured. The observation is reliable, but no attack was performed to demonstrate "
          "consequences, so no consequence is claimed here.",
          "- **Suspected, not proven.** Flagged for attention, with no confirmation. It is a lead "
          "to check, not a statement about what an attacker can do.",
          "",
          "| Category | Count |",
          "|----------|------:|",
          f"| Proven | {n_f} |",
          f"| Observed but not exploited | {n_o} |",
          f"| Suspected, not proven | {n_u} |",
          f"| **Total recorded** | **{n_f + n_o + n_u}** |",
          ""]
    extra = _extra_proofs_note(n_certs, n_f)
    if extra:
        L += [extra, ""]

    L += ["## What it means for this organisation", ""]
    if facts:
        worst = facts[0]
        L += [
            f"{_count_word(n_f, 'weakness', 'weaknesses')} in this {info.operation.subject_noun} "
            f"{'was' if n_f == 1 else 'were'} demonstrated, not merely suspected. In plain terms:",
            "",
        ]
        for it in facts:
            L.append(f"- **{it.title}** — {it.what}")
        L += ["",
              f"The most serious of these is **{_md_inline(worst.graded.finding.title)}**, rated "
              f"{_SEVERITY_WORDS.get(worst.graded.finding.severity, worst.graded.finding.severity)}.",
              ""]
    else:
        L += [
            f"No weakness in this {info.operation.subject_noun} was proven during this examination.",
            "",
            f"**That is not the same as this {info.operation.subject_noun} being secure.** It "
            "means that within the "
            "boundaries described in `02-approach-and-scope.md`, and within the time this "
            "examination ran, nothing was demonstrated. Anything outside those boundaries was not "
            "looked at. `02` states the boundaries plainly, and it should be read before this "
            "result is relied upon.",
            "",
        ]
    if observed:
        L += [
            f"In addition, {_count_word(n_o, 'protective setting', 'protective settings')} "
            f"{'was' if n_o == 1 else 'were'} found to be missing or weak. These were seen "
            f"directly rather than demonstrated by attack. Individually they cause no harm; "
            f"together they remove the safety margins that limit the damage when something else "
            f"goes wrong. They are listed in `04-leads.md`.",
            "",
        ]
    if unproven:
        L += [f"A further {_count_word(n_u, 'item')} {'is' if n_u == 1 else 'are'} recorded as "
              f"suspected but unproven, also in `04-leads.md`. Nothing should be concluded from "
              f"them until they are checked.", ""]

    L += ["## What to do first", ""]
    if facts:
        rows = prioritize([it.graded for it in facts])
        L += ["In this order:", ""]
        for r in rows:
            match = next((it for it in facts if it.graded.finding.finding_slug ==
                          r.graded.finding.finding_slug), None)
            fix = _remediation_text(match) if match else ""
            L.append(f"{r.rank}. **{_md_inline(r.graded.finding.title)}** "
                     f"({_SEVERITY_WORDS.get(r.graded.finding.severity, r.graded.finding.severity)}; "
                     f"estimated effort: {_EFFORT_WORDS.get(r.effort, r.effort)}).  ")
            L.append(f"   {_md_inline(fix)}")
        L += ["", "The full ordering, with the reasoning behind it, is in `06-what-to-do.md`.", ""]
    elif observed:
        L += ["Nothing was proven, so nothing here is urgent. The missing protective settings "
              "listed in `04-leads.md` are inexpensive to add and are the sensible next step. "
              "`06-what-to-do.md` gives the order.", ""]
    else:
        L += ["Nothing requiring action was recorded. `02-approach-and-scope.md` states what was "
              "examined, which is what determines how much weight this result carries.", ""]

    L += ["## What this pack does not tell you", "",
          "It is worth being explicit about the limits, because a security report is easy to "
          "over-read:", "",
          f"- It does not say this {info.operation.subject_noun} is secure. It says what was "
          "examined and what was found.",
          "- It does not cover anything outside the boundaries in `02-approach-and-scope.md`. "
          "Anything not examined is simply unknown, not safe.",
          "- A proven finding shows that a weakness exists. It does not show that anybody has "
          "used it, and it is not evidence that data has been taken.",
          f"- It describes this {info.operation.subject_noun} as it was during the examination "
          "window above. Anything that changes afterwards has not been examined in its changed form.",
          ""]

    L += ["## How much you can trust this document", "",
          "Two independent things support it, and they are worth distinguishing:", "", ]
    if proof_ok:
        L.append("- **The proven findings can be re-checked by you, without trusting us.** The "
                 "saved evidence travels with this pack, together with an independent program "
                 "that re-runs the checks over it. `07-verify-it-yourself.md` gives the exact "
                 "command. It does not contact anything that was examined and it does not need the "
                 "internet.")
    else:
        L.append("- **No re-checkable evidence bundle is included**, because nothing in this "
                 "examination was proven to the standard that produces one. That is the honest "
                 "outcome for this run, not an omission.")
    if signed:
        L.append("- **The pack has been digitally signed**, so alteration after the fact is "
                 "detectable. `07-verify-it-yourself.md` explains how to check this, including "
                 "the one step that must be done through a separate channel.")
    else:
        L.append("- **The pack is not digitally signed.** No signing key was available when it "
                 "was produced. Its contents can still be checked for internal consistency, but "
                 "that check cannot prove who produced it. This is stated rather than hidden.")
    L += ["", "---", "",
          "Continue with `02-approach-and-scope.md`, which describes how the work was done and — "
          "importantly — what was not examined.", ""]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# 02 — approach and scope
# --------------------------------------------------------------------------------------------------


def render_approach(*, label: str, info: RunInfo, built: Optional[str],
                    adapted: AdaptResult, n_facts: int, notes: Iterable[str]) -> str:
    L = _header("How the work was done, and what was not examined", label, info.run_id, built)
    L += [
        "## The short version",
        "",
        "An automated examination engine was pointed at one address belonging to this "
        "organisation. It explored what it could reach from there, sent test requests, and "
        "recorded what came back. Where a result met a strict standard of proof, the evidence was "
        "saved so that the result can be re-established later by anyone, without trusting the "
        "engine that produced it.",
        "",
        "## The standard of proof used",
        "",
        "This is the part that distinguishes this pack from an ordinary scan report, so it is "
        "worth reading even if nothing else is.",
        "",
        "A finding is only called **proven** when all of the following hold:",
        "",
        "1. A test request was actually sent and a reply actually received.",
        "2. An automatic check — a small, fixed program with no judgement and no discretion — "
        "examined the reply and confirmed the specific condition that defines the weakness.",
        "3. The request and the reply were saved.",
        "4. When this pack was assembled, that same check was run again over the saved copies and "
        "reached the same conclusion.",
        "",
        "Step 4 matters more than it may appear. It means a finding cannot survive in this pack "
        "merely because it was once written down as confirmed. Anything whose saved evidence no "
        "longer supports it is moved out of the proven list and into `04-leads.md`, with the "
        "reason recorded. Nothing here is proven by assertion.",
        "",
        "Everything that does not meet that standard is reported as an observation or a lead, and "
        "is never described as something an attacker can do.",
        "",
        "## Exactly what was examined",
        "",
    ]
    L += _subject_block(info)
    if info.pages_examined is not None:
        L.append(f"- **Pages explored:** {info.pages_examined}")
    if info.requests_examined is not None:
        L.append(f"- **Request patterns examined for weaknesses:** {info.requests_examined}")
    if info.test_requests_sent is not None:
        L.append(f"- **Test requests sent in total:** {info.test_requests_sent}")
    if info.endpoints_discovered is not None:
        L.append(f"- **Additional addresses discovered while exploring:** {info.endpoints_discovered}")
    L += [
        f"- **Started:** {info.started_text}",
        f"- **Finished:** {info.finished_text}",
        f"- **Time taken:** {info.duration_text}",
        "",
    ]
    L += _subject_unrecorded_block(info)
    for n in info.notes:
        L += [f"> {n}", ""]

    if info.command:
        L += ["## The exact instruction that was run", "",
              "Recorded verbatim, so that the examination can be repeated exactly:", "",
              "```", " ".join(safe_command_token(c) for c in info.command), "```", ""]
        if info.limits:
            L += ["The settings in that instruction limited what could be found. In plain terms:", ""]
            for lim in info.limits:
                L.append(f"- **`{_md_inline(lim.option)}`** — {lim.meaning}")
            L.append("")
    else:
        L += ["## The exact instruction that was run", "",
              "The run did not record the instruction that produced it, so it cannot be shown "
              "here. This is a gap in the record, stated rather than filled in.", ""]

    L += [
        "## What was NOT examined",
        "",
        "This section exists because a security report is most often misread in one particular "
        "way: as saying that everything not mentioned is fine. It does not say that. The "
        "following were outside this examination.",
        "",
    ]
    if info.limits:
        L += ["**Limits imposed by the settings above:**", ""]
        for lim in info.limits:
            L.append(f"- {lim.meaning}")
        L.append("")
    noun = info.operation.subject_noun
    L += ["**Limits inherent in this kind of examination:**", ""]
    L += list(_INHERENT_LIMITS.get(info.operation.key, _INHERENT_LIMITS_DEFAULT))
    L += [
        f"- **Only the state of the {noun} during the window above.** Any change made afterwards "
        "has not been examined.",
        "- **Only automated examination.** A person working by hand finds categories of problem "
        "that automation does not — in particular business-logic flaws, where every individual "
        "step works correctly but the sequence produces a wrong outcome. Nothing of that kind was "
        "looked for here.",
        "- **No third-party services.** Payment providers, identity providers, hosting platforms "
        "and similar were not tested, and must not be tested without their own authorisation.",
        "",
        "The correct reading of a clean result in any of these areas is *not examined*, not "
        "*found to be safe*.",
        "",
        "## How the record was assembled",
        "",
    ]
    if info.has_findings_record:
        L += ["The findings in this pack were read from the machine-readable record the "
              "examination wrote (`appendix/report.json`), translated into the form the written "
              "reports use, and joined back to the saved evidence so that each proof could be "
              "re-run. That translation copies values; it does not add any.", ""]
    else:
        L += ["No structured findings record was available to build this pack from.", "",
              info.artefact_gap("findings") or "", ""]
    trans = list(adapted.notes) + [n for n in notes if n]
    if trans:
        L += ["What happened during that assembly, recorded plainly:", ""]
        for n in trans:
            L.append(f"- {n}")
        L.append("")
    L += [
        f"Of the findings in the record, {_count_word(n_facts, 'one', 'were')} confirmed by "
        f"re-running the saved proof at assembly time."
        if n_facts != 1 else
        "Of the findings in the record, one was confirmed by re-running its saved proof at "
        "assembly time.",
        "",
        "---",
        "",
        "Continue with `03-findings.md`.",
        "",
    ]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# per-finding block, shared by 03 and 04
# --------------------------------------------------------------------------------------------------


def _category_line(item: _Item) -> str:
    """The engine's own name for the weakness category, with its short meaning. Naming the
    category matters: it is the word that appears in the machine records, in the catalogue, and in
    any other tool's report, and a reader who cannot connect this entry to that word cannot
    cross-check the finding anywhere else."""
    bc = (item.graded.finding.bug_class or "").strip()
    if not bc or bc.lower() == "passive":
        return ""
    meaning = short_plain(bc)
    if meaning:
        return f"**Category:** `{_md_inline(bc)}` — {meaning}  "
    return (f"**Category:** `{_md_inline(bc)}` — no short description of this category is held on "
            f"file.  ")


def _finding_block(item: _Item, info: RunInfo, *, proven: bool, index: int) -> list[str]:
    f = item.graded.finding
    L = [f"### {index}. {item.title}", "",
         f"**Reference:** `{_md_inline(f.finding_slug)}`  "]
    if item.recorded_title:
        L.append(f"**Recorded by the engine as:** `{item.recorded_title}`  ")
    cat = _category_line(item)
    if cat:
        L.append(cat)
    L += [f"**Rating:** {_SEVERITY_WORDS.get(f.severity, f.severity)}  ",
          f"**Where:** `{_where(item)}`  "]
    if item.extras.parameter:
        L.append(f"**Affected input:** the `{_md_inline(item.extras.parameter)}` parameter  ")
    L += [
          f"**When it was recorded:** {_confirmed_time(item, info)}  ",
          "",
          "**What this kind of weakness is.** " + item.what,
          "",
          "**What this kind of weakness can lead to, in general.** " + item.why,
          "",
          "> The paragraph above describes the CATEGORY. It is general knowledge about this kind "
          "of weakness, and it is the reason the category is taken seriously — not a description "
          f"of what happened to this {info.operation.subject_noun}. What was actually established "
          "here is stated next, "
          "and it is narrower.",
          ""]

    if proven:
        L += [f"**What was established on this {info.operation.subject_noun}.** The examination "
              "sent test input to "
              f"`{_where(item)}` and an automatic check confirmed "
              + oracle_establishes(item.graded.oracle_kind) + ".", ""]
        L += ["**How that was proved.** " + _oracle_plain(item.graded.oracle_kind), ""]
        if item.extras.evidence:
            L += ["The engine recorded this observation at the time:", "",
                  "> " + _md_inline(item.extras.evidence), ""]
        L += ["The saved request and reply travel with this pack, and the same check was run over "
              "them again while the pack was assembled — it reached the same conclusion. "
              "`07-verify-it-yourself.md` shows how to repeat that yourself.", ""]
        if item.graded.certificate_digest:
            L += [f"**Evidence reference:** `sha256:{item.graded.certificate_digest}` — the "
                  f"fingerprint of the saved evidence for this finding, so that this entry and "
                  f"that evidence can be tied together unambiguously.", ""]
        L += ["**What this does NOT prove.** Only the specific behaviour described above was "
              "demonstrated. The examination did not go on to find out how far the weakness could "
              "be pushed: no data was extracted, no account was taken over, and no attempt was "
              "made to reach the general consequences described earlier. So the general "
              "description is the reason to fix this promptly — it is not a record of what "
              "happened here. Equally, this finding is not evidence that anybody has used the "
              "weakness or that data has been taken, and it says nothing about parts of the system "
              "that were not examined.", ""]
    else:
        if item.graded.grade == GRADE_DEMOTED:
            L += ["**Why it is not proven.** The record says an automatic check confirmed this "
                  "during the examination, but when that check was run again over the saved "
                  "evidence while this pack was assembled, it did not reach the same conclusion. "
                  "It is therefore reported as unproven. This is worth investigating in its own "
                  "right: it means either that the evidence is incomplete or that something about "
                  "the original confirmation was wrong.", ""]
        elif item.extras.kind == "passive":
            L += ["**How this was established.** It was observed directly in the system's own "
                  "replies — no attack was performed. The observation itself is reliable.", ""]
            if item.extras.evidence:
                L += ["The engine recorded:", "", "> " + _md_inline(item.extras.evidence), ""]
            L += ["**Why it is not listed as proven.** Nothing was demonstrated. A missing "
                  "protective setting is a weakened safety margin, not by itself an action an "
                  "attacker performed. It is reported here so that it is not overstated.", ""]
        else:
            L += ["**Why it is not proven.** No automatic check confirmed it. It was flagged for "
                  "attention on the basis of what was visible, and no test established that it "
                  "can be used. Treat it as something to check, not as a statement about what an "
                  "attacker can do.", ""]
            if item.extras.evidence:
                L += ["The engine recorded:", "", "> " + _md_inline(item.extras.evidence), ""]
        L += [f"**What was established on this {info.operation.subject_noun}.** Nothing beyond "
              "the observation above. In "
              "particular, none of the general consequences described earlier was demonstrated "
              "here — they are what this category of weakness is capable of, which is why the item "
              f"is worth resolving, and they are not a description of this "
              f"{info.operation.subject_noun}.", ""]

    L += ["**What to do about it.** " + _md_inline(_remediation_text(item)), ""]

    if proven:
        L += ["**How to check the fix worked.** Deploy the change, then run the examination again "
              "against the fixed system — the exact instruction is in `02-approach-and-scope.md`. "
              "The fix has worked when this finding no longer appears in the new result.",
              "",
              "> A caution worth understanding: the verification command in "
              "`07-verify-it-yourself.md` will keep passing after the fix is deployed. That "
              "command re-checks the *saved evidence from this examination*, which proves the "
              "evidence is genuine and unaltered. It does not, and cannot, tell you anything "
              "about the system's condition today. Only a fresh examination does that.",
              ""]
    else:
        L += ["**How to check it is resolved.** Run the examination again against the changed "
              "system, using the instruction in `02-approach-and-scope.md`. This item is resolved "
              "when it no longer appears.", ""]

    std = _standards_line(item)
    if std:
        L += [std, ""]
    if item.generic:
        L += ["> No plain-language description of this category is held on file, so the engine's "
              "own wording above is the authoritative description of what was seen.", ""]
    L += ["---", ""]
    return L


# --------------------------------------------------------------------------------------------------
# 03 — findings   /   04 — leads
# --------------------------------------------------------------------------------------------------


def render_findings(*, label: str, info: RunInfo, facts: list[_Item], built: Optional[str]) -> str:
    L = _header("What was found — proven findings", label, info.run_id, built)
    L += [
        "Everything in this document was demonstrated and then confirmed again from saved "
        "evidence while this pack was assembled. Nothing here rests on judgement or opinion.",
        "",
        "Things that were *not* proven are in `04-leads.md`. Keeping them apart is deliberate: "
        "mixing proven and unproven findings is the most common way a security report misleads "
        "the person reading it.",
        "",
        "Each entry answers the same six questions: what it is, why it matters here, how we "
        "proved it, what it does *not* prove, what to do, and how to check the fix worked.",
        "",
    ]
    if not facts:
        gap = info.artefact_gap("findings")
        if gap is not None:
            L += ["## This section could not be produced", "", gap, "",
                  "Nothing should be inferred from the absence of findings below. The examination "
                  "may or may not have encountered something; what is certain is only that its "
                  "record does not say. `02-approach-and-scope.md` sets out what this kind of "
                  "operation does and does not record.", ""]
            return "\n".join(L) + "\n"
        L += ["## Nothing was proven in this examination", "",
              "A structured record of findings WAS produced, and nothing in it met the standard of "
              "proof described in `02-approach-and-scope.md`. So this is a real result, not a "
              "missing one.",
              "",
              "It is still a statement about what was demonstrated, not a clean bill of health. "
              "`02-approach-and-scope.md` sets out what was and was not examined, "
              "`04-leads.md` lists what was observed or suspected without being proven, and "
              "`05-what-was-looked-for.md` shows how much of what the engine can look for this "
              "engagement actually recorded. All three should be read before concluding anything.",
              ""]
        return "\n".join(L) + "\n"

    L += [f"## Summary — {_count_word(len(facts), 'proven finding')}", "",
          "| # | Finding | Rating | Where |",
          "|--:|---------|--------|-------|"]
    for i, it in enumerate(facts, start=1):
        L.append(f"| {i} | {it.title} | {it.graded.finding.severity} | "
                 f"`{_where(it)}` |")
    L += ["", "## The findings in detail", ""]
    for i, it in enumerate(facts, start=1):
        L += _finding_block(it, info, proven=True, index=i)
    L += ["Continue with `04-leads.md`, then `06-what-to-do.md`.", ""]
    return "\n".join(L) + "\n"


def render_leads(*, label: str, info: RunInfo, observed: list[_Item], unproven: list[_Item],
                 built: Optional[str]) -> str:
    L = _header("What was observed or suspected, but not proven", label, info.run_id, built)
    L += [
        "Nothing in this document was demonstrated. It is recorded because leaving it out would "
        "hide information, and shown separately because presenting it alongside proven findings "
        "would overstate it.",
        "",
        "There are two kinds of item here, and the difference matters:",
        "",
        "- **Observed but not exploited** — something was directly seen to be missing or "
        "misconfigured in the system's own replies. The observation is reliable. What an attacker "
        "could do with it was not tested, so nothing of that kind is claimed.",
        "- **Suspected, not proven** — flagged for attention, with nothing confirming it. These "
        "are leads for the engineering team, not conclusions.",
        "",
    ]
    if not observed and not unproven:
        gap = info.artefact_gap("findings")
        if gap is not None:
            L += ["## This section could not be produced", "", gap, ""]
            return "\n".join(L) + "\n"
        L += ["## Nothing to report", "",
              "A structured record of findings was produced, and it contained no unproven "
              "observations or leads. Everything it recorded is in `03-findings.md`.", ""]
        return "\n".join(L) + "\n"

    L += [f"## Observed but not exploited — {_count_word(len(observed), 'item')}", ""]
    if observed:
        L += ["These are weakened safety margins rather than demonstrated attacks. Individually "
              "each is minor; the reason to fix them is that they are what limits the damage when "
              "something else goes wrong, and they are usually cheap to put right.",
              "",
              "| # | Item | Rating |", "|--:|------|--------|"]
        for i, it in enumerate(observed, start=1):
            L.append(f"| {i} | {it.title} | {it.graded.finding.severity} |")
        L += ["", "### In detail", ""]
        for i, it in enumerate(observed, start=1):
            L += _finding_block(it, info, proven=False, index=i)
    else:
        L += ["_None._", ""]

    start = len(observed)
    L += [f"## Suspected, not proven — {_count_word(len(unproven), 'item')}", ""]
    if unproven:
        L += ["Nothing should be concluded from these until they have been checked. They are "
              "listed so that the record is complete.", ""]
        for i, it in enumerate(unproven, start=start + 1):
            L += _finding_block(it, info, proven=False, index=i)
    else:
        L += ["_None._", ""]
    L += ["Continue with `06-what-to-do.md`.", ""]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# 05 — what was looked for (the catalogue)
# --------------------------------------------------------------------------------------------------


def render_catalogue(*, label: str, info: RunInfo, cat: Catalogue, built: Optional[str]) -> str:
    n_conf, n_rep, n_unk, n_all = (len(cat.confirmed), len(cat.reported),
                                   len(cat.not_recorded), len(cat.rows))
    L = _header("What the examination is able to look for", label, info.run_id, built)
    L += [
        "## Why this document exists",
        "",
        "A list of findings tells you what was found. It cannot tell you what the silence means. "
        "Three findings out of three categories examined would be a very different result from "
        "three out of ninety, and the findings alone do not distinguish them.",
        "",
        f"This document lists every one of the {n_all} categories of weakness the examination "
        "engine is capable of confirming, and states this engagement's position against each. It "
        "is generated from the engine's own internal register when the pack is assembled, not "
        "written by hand, so it cannot quietly overstate what the engine can do.",
        "",
        "## The three states, and the one that is missing",
        "",
        "| State | Meaning |",
        "|-------|---------|",
        "| **Confirmed** | A weakness of this category was proven in this engagement. The finding "
        "is named, and it appears in `03-findings.md`. |",
        "| **Reported, not confirmed** | Something of this category was recorded but not proven. "
        "It appears in `04-leads.md`. |",
        "| **Not recorded** | The engagement record does not say whether this category was "
        "examined. |",
        "",
        "**There is deliberately no state meaning \"examined and found clean\", and its absence "
        "is the most important thing on this page.**",
        "",
        COVERAGE_GAP_NOTE,
        "",
        "So a row reading *not recorded* must be read as *unknown*. It is not a clean result, it "
        "is not a pass, and it should not be presented to anyone as either. If assurance is needed "
        "over a particular category, that assurance has to come from work that recorded it — not "
        "from this row.",
        "",
        "## Which of these categories even apply here",
        "",
        f"This engagement was {_article(info.operation.name)} {info.operation.name}. Not every "
        "category below is relevant to that kind of work — the categories that matter to a review "
        "of source code are not the categories that matter to a cloud account, and neither set "
        "matches a web application.",
        "",
        "**The engine does not record which categories apply to which kind of operation**, so this "
        "document cannot mark the irrelevant ones, and it does not guess. Every category is listed, "
        "and a reader who knows the domain should discount the ones that plainly do not apply. "
        "Marking rows relevant on a hunch would be inventing information, which is worse than "
        "listing a few rows that obviously do not apply.",
        "",
        "## This engagement at a glance",
        "",
        "| | Categories |",
        "|--|-----------:|",
        f"| Confirmed | {n_conf} |",
        f"| Reported, not confirmed | {n_rep} |",
        f"| Not recorded whether examined | {n_unk} |",
        f"| **Total the engine can confirm** | **{n_all}** |",
        "",
    ]
    if n_conf or n_rep:
        L += ["### The categories this engagement did record", "",
              "| Category | Status | Findings |", "|----------|--------|----------|"]
        for r in cat.confirmed + cat.reported:
            refs = ", ".join(f"`{_md_inline(s)}`" for s in r.findings) or "—"
            L.append(f"| `{_md_inline(r.bug_class)}` | {r.status_text} | {refs} |")
        L.append("")

    L += ["## The full catalogue", "",
          "Grouped by family for readability. The **Confirmed by** column names the deterministic "
          "checks the engine would use to establish a weakness of that category — these are the "
          "same check names that appear on findings and in the saved evidence, so a category here "
          "can be traced to a finding elsewhere in this pack.",
          "",
          "The **Standards** column shows what a weakness of that category *would* implicate under "
          "the common frameworks. It is a property of the category, not a statement about this "
          "organisation: only a confirmed row asserts anything about the system examined.",
          ""]
    for family, rows in cat.by_family():
        L += [f"### {family}", "",
              "| Category | What it means | Status | Confirmed by | Standards |",
              "|----------|---------------|--------|--------------|-----------|"]
        for r in rows:
            meaning = r.meaning or "_no short description on file_"
            oracles = ", ".join(f"`{_md_inline(o)}`" for o in r.oracles) or "—"
            std = r.standards or {}
            bits: list[str] = []
            if std.get("owasp"):
                bits.append(str(std["owasp"]))
            for key in ("cwe", "attack"):
                vals = std.get(key) or []
                if vals:
                    bits.append(", ".join(str(v) for v in vals[:3]))
            L.append(f"| `{_md_inline(r.bug_class)}` | {meaning} | {r.status_text} | {oracles} | "
                     f"{_md_inline('; '.join(bits)) or '—'} |")
        L.append("")

    if cat.notes:
        L += ["## Notes on this catalogue", ""]
        for n in cat.notes:
            L.append(f"- {n}")
        L.append("")
    L += ["The machine-readable form of this catalogue, including the full standards mapping for "
          "every category, is `appendix/catalogue.json`.",
          "",
          "---",
          "",
          "Continue with `06-what-to-do.md`.",
          ""]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# 06 — what to do
# --------------------------------------------------------------------------------------------------


def render_what_to_do(*, label: str, info: RunInfo, facts: list[_Item], observed: list[_Item],
                      unproven: list[_Item], built: Optional[str]) -> str:
    L = _header("What to do, and in what order", label, info.run_id, built)
    L += [
        "## How this order was decided",
        "",
        "Two things decide the order, and both are stated so the reasoning can be checked or "
        "overruled:",
        "",
        "- **How much harm it could cause**, taken from the rating on each finding.",
        "- **How much work it is likely to take to fix properly**, estimated from the category of "
        "weakness. This is an estimate based on the kind of problem, not a measurement of this "
        "organisation's code. Treat it as a starting point for planning, not as a quotation.",
        "",
        "Work that prevents a lot of harm for a little effort comes first. Only proven findings "
        "are placed in this order — scheduling engineering effort against something unproven is "
        "how security work loses credibility.",
        "",
        "## Stage 1 — fix what was proven",
        "",
    ]
    if facts:
        rows = prioritize([it.graded for it in facts])
        by_slug = {it.graded.finding.finding_slug: it for it in facts}
        L += ["| Order | Finding | Rating | Effort to fix |",
              "|------:|---------|--------|---------------|"]
        for r in rows:
            L.append(f"| {r.rank} | {_md_inline(r.graded.finding.title)} | "
                     f"{r.graded.finding.severity} | {_EFFORT_WORDS.get(r.effort, r.effort)} |")
        L += ["", "### What each one requires", ""]
        for r in rows:
            it = by_slug.get(r.graded.finding.finding_slug)
            if it is None:
                continue
            L += [f"**{r.rank}. {_md_inline(r.graded.finding.title)}**  ",
                  f"_Reference `{_md_inline(r.graded.finding.finding_slug)}`; "
                  f"{_SEVERITY_WORDS.get(r.graded.finding.severity, r.graded.finding.severity)}; "
                  f"estimated effort {_EFFORT_WORDS.get(r.effort, r.effort)}._",
                  "",
                  _md_inline(_remediation_text(it)),
                  "",
                  f"Confirm the fix by re-running the examination (see "
                  f"`02-approach-and-scope.md`) and checking that `{_md_inline(r.graded.finding.finding_slug)}` "
                  f"no longer appears.",
                  ""]
        quick = [r for r in rows if r.tier == 0]
        if quick:
            L += ["### Do these first if capacity is limited", "",
                  "Serious, and inexpensive to fix — the best return on a constrained week:", ""]
            for r in quick:
                L.append(f"- **{_md_inline(r.graded.finding.title)}** "
                         f"({r.graded.finding.severity}, "
                         f"{_EFFORT_WORDS.get(r.effort, r.effort)}).")
            L.append("")
    else:
        L += ["Nothing was proven, so there is nothing in this stage.", "",
              "Before reading that as good news, read `02-approach-and-scope.md`: what was not "
              "examined is not the same as what is safe.", ""]

    L += ["## Stage 2 — close the observed gaps", ""]
    if observed:
        L += ["These were observed directly but not exploited. They are normally configuration "
              "changes rather than code changes, and are usually completed quickly. Ordered by "
              "rating:", "",
              "| Item | Rating | What is needed |", "|------|--------|----------------|"]
        for it in observed:
            L.append(f"| {it.title} | {it.graded.finding.severity} | "
                     f"{_md_inline(_remediation_text(it))} |")
        L.append("")
    else:
        L += ["Nothing was recorded in this category.", ""]

    L += ["## Stage 3 — resolve what is unproven", ""]
    if unproven:
        L += ["Each of these should be checked so that it can be either confirmed and fixed, or "
              "dismissed with a reason. Leaving them permanently unresolved is the outcome to "
              "avoid: an unresolved lead accumulates into a backlog nobody trusts.", ""]
        for it in unproven:
            L.append(f"- **{it.title}** "
                     f"({it.graded.finding.severity}) — see `04-leads.md`.")
        L.append("")
    else:
        L += ["Nothing was recorded in this category.", ""]

    L += ["## Stage 4 — confirm and re-examine", "",
          "1. Deploy the changes from the stages above.",
          "2. Run the examination again, using the instruction recorded in "
          "`02-approach-and-scope.md`, and check that the findings above no longer appear.",
          "3. Keep this pack. It is the record of the position before the changes, and it can be "
          "checked independently at any time in the future — see `07-verify-it-yourself.md`.",
          "",
          "One thing to plan for: the areas listed as not examined in `02-approach-and-scope.md` "
          "remain unexamined after all of the above is done. If assurance is needed over those, "
          "it takes a further piece of work, not a re-run of this one.",
          ""]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# 06 — verify it yourself
# --------------------------------------------------------------------------------------------------


_MANIFEST_CHECK = """python3 - <<'PYTHON'
import hashlib, json, pathlib
manifest = json.load(open("MANIFEST.json"))
bad = []
for entry in manifest["entries"]:
    data = pathlib.Path(entry["path"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        bad.append(entry["path"])
print("ALTERED FILES:", bad) if bad else print("OK -", len(manifest["entries"]), "files all match")
PYTHON"""

_SIGNATURE_CHECK = """python3 - <<'PYTHON'
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

manifest = open("MANIFEST.json", "rb").read()
sig = json.load(open("MANIFEST.sig.json"))

# 1. the signature covers exactly this MANIFEST.json
assert sig["manifest_sha256"] == hashlib.sha256(manifest).hexdigest(), "signature is for a DIFFERENT manifest"

# 2. recompute the fingerprint of the signing authority from the signed document itself
canonical = json.dumps(sig["trust_root"], sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
print("fingerprint of the signing authority:", "sha256:" + hashlib.sha256(canonical).hexdigest())

# 3. count how many authorised signers produced a valid signature
keys = {a["key_id"]: a["public_key_b64"] for a in sig["trust_root"]["authorizers"]}
valid = set()
for s in sig["signatures"]:
    pub = keys.get(s["key_id"])
    if not pub:
        continue
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(
            base64.b64decode(s["sig_b64"]), manifest)
        valid.add(s["key_id"])
    except (InvalidSignature, ValueError):
        pass
print("valid signatures:", len(valid), "of", sig["threshold"], "required")
print("RESULT:", "PASS" if len(valid) >= sig["threshold"] else "FAIL")
PYTHON"""


def render_verify(*, label: str, info: RunInfo, built: Optional[str], signed: bool,
                  fingerprint: str, proof: dict, n_facts: int) -> str:
    verify_cmd = str(proof.get("verify_cmd") or "")
    proof_fp = str(proof.get("trust_root_fingerprint") or fingerprint or "")
    L = _header("How to check all of this for yourself", label, info.run_id, built)
    L += [
        "You do not have to take this pack on trust. There are three separate checks, and they "
        "answer three different questions. They are independent: one can pass while another "
        "fails, and each failure means something different.",
        "",
        "| Check | The question it answers |",
        "|-------|-------------------------|",
        "| 1. Contents | Has anything in this pack been altered since it was produced? |",
        "| 2. Signature | Was it produced by the organisation that claims to have produced it? |",
        "| 3. Proof | Do the findings actually follow from the saved evidence? |",
        "",
        "You need a computer with Python 3 installed. None of these checks contacts the examined "
        "system, and none of them requires an internet connection. Nothing below sends any data "
        "anywhere.",
        "",
        "Start by unpacking the archive and opening a terminal in the unpacked folder.",
        "",
        "---",
        "",
        "## Check 1 — has anything been altered?",
        "",
        "`MANIFEST.json` lists every file in this pack together with its fingerprint: a short "
        "value computed from the file's contents, which changes if even one character changes. "
        "This check recomputes every fingerprint and compares.",
        "",
        "Run, from the unpacked folder:",
        "",
        "```",
        _MANIFEST_CHECK,
        "```",
        "",
        "**A pass looks like:** `OK - <number> files all match`.",
        "",
        "**A failure looks like:** `ALTERED FILES: [...]` followed by one or more file names. "
        "That means those files are not the ones that were packed. Do not rely on them, and ask "
        "the sender for a fresh copy.",
        "",
        "**What a pass does not mean.** It proves the pack is internally consistent — the files "
        "match the list. It does not prove who produced it, because somebody who altered a file "
        "could have rewritten the list to match. That is what check 2 is for.",
        "",
        "---",
        "",
        "## Check 2 — was it produced by whom it claims?",
        "",
    ]
    if signed:
        L += [
            "`MANIFEST.sig.json` holds a digital signature over `MANIFEST.json` — the electronic "
            "equivalent of a seal that can only be applied by the holder of a particular private "
            "key, and that breaks if the sealed document is altered afterwards.",
            "",
            "This check needs one widely used Python package. If it is not already present, "
            "install it with `pip install cryptography`.",
            "",
            "```",
            _SIGNATURE_CHECK,
            "```",
            "",
            "**A pass looks like:** `RESULT: PASS`, preceded by a line beginning "
            "`fingerprint of the signing authority:`.",
            "",
            "**A failure looks like:** `RESULT: FAIL`, or an error stating the signature is for a "
            "different manifest.",
            "",
            "### The step that must not be skipped",
            "",
            f"The fingerprint printed by that check is `{_md_inline(proof_fp or 'not recorded')}`. "
            f"It also appears in the file `TRUST-ROOT-FINGERPRINT.txt` inside this pack.",
            "",
            "**Obtain that same fingerprint from the sender through a different channel** — a "
            "phone call, a letter, a published page, an in-person meeting — and compare it "
            "character by character with the value the check printed. Anyone who could replace "
            "this pack could also replace the copy of the fingerprint inside it, so comparing the "
            "pack against itself proves nothing. The comparison is only meaningful when one side "
            "of it came from somewhere else.",
            "",
            "If the two fingerprints differ, this pack was signed by somebody other than the "
            "party you obtained the fingerprint from. Treat it as untrustworthy.",
            "",
        ]
    else:
        L += [
            "**This pack is not signed.** No signing key was available when it was produced, so "
            "there is no signature to check and nothing here can establish who produced it.",
            "",
            "Check 1 still works and still detects alteration relative to the list inside the "
            "pack. But if you need assurance about the origin of this document, ask the sender "
            "for a signed copy.",
            "",
        ]

    L += ["---", "", "## Check 3 — do the findings follow from the evidence?", ""]
    if proof.get("ok") and verify_cmd:
        L += [
            "This is the strongest check in the pack, and the one that is unusual. The saved "
            "request and reply for each proven finding travel inside `proof-bundle/`, together "
            "with the checking program itself. Running it re-derives every proven finding from "
            "the saved evidence, on your machine.",
            "",
            "It does not ask this pack whether the findings are true. It works them out again "
            "from scratch.",
            "",
            "```",
            "cd proof-bundle",
            verify_cmd,
            "```",
            "",
            "**A pass looks like:** the command finishes and exits with status `0`. On most "
            "systems you can confirm that by running `echo $?` immediately afterwards and seeing "
            "`0`. Every finding it re-derived is listed as it goes.",
            "",
            "**A failure looks like:** a non-zero exit status, and a message naming what did not "
            "check out. A single altered character anywhere in the evidence causes this. There is "
            "no partial pass.",
            "",
            "**What a pass means.** Each of the "
            f"{_count_word(n_facts, 'proven finding')} in `03-findings.md` genuinely follows from "
            "the saved evidence, that the evidence has not been altered, and that it was sealed "
            "by the signing authority whose fingerprint you compared in check 2.",
            "",
            (_extra_proofs_note(int(proof.get("certificates") or 0), n_facts) or ""),
            "",
            "**What a pass does not mean.** It says nothing about the system's condition today. "
            "It re-checks evidence captured during the examination window, so it will keep "
            "passing after the weaknesses are fixed. To find out whether the system is still "
            "affected, the examination itself has to be run again — see `02-approach-and-scope.md`.",
            "",
        ]
    else:
        L += [
            "**No evidence bundle is included in this pack.** Nothing in this examination was "
            "proven to the standard that produces one, so there is nothing to re-derive.",
            "",
        ]
        note = str(proof.get("note") or "").strip()
        if note:
            L += [f"The reason recorded when the pack was assembled: {_md_inline(note)}.", ""]
        L += ["This is the honest outcome for an examination that proved nothing, not a missing "
              "piece. `04-leads.md` lists what was observed and suspected instead.", ""]

    L += ["---", "", "## If you would rather someone else did this", "",
          "Every check above can be handed to any competent technical person, including one with "
          "no connection to this organisation and no access to its systems. That is the point of "
          "packaging the evidence this way: the conclusions do not depend on trusting the party "
          "that produced them.",
          "", "Continue with `08-glossary.md` if any term in this pack was unfamiliar.", ""]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# 07 — glossary
# --------------------------------------------------------------------------------------------------

_GLOSSARY: tuple[tuple[str, str], ...] = (
    ("Archive / pack", "The single compressed file this document arrived in, and everything "
                       "inside it. Also called a dossier."),
    ("Automatic check (also: oracle)",
     "A small fixed program that inspects a saved request and reply and answers one narrow "
     "question — for example, did these two replies differ in the way that only a genuine "
     "database-injection weakness produces. It has no judgement and no discretion, which is what "
     "makes its answer repeatable by anyone. The machine-readable files in this pack use the word "
     "'oracle' for it."),
    ("CAPEC", "A public catalogue of attack patterns, maintained by MITRE, a not-for-profit "
              "organisation. A reference such as `CAPEC-7` identifies a recognised pattern so that "
              "findings can be compared across reports and tools."),
    ("CWE", "The Common Weakness Enumeration: a public catalogue of categories of software "
            "weakness, also maintained by MITRE. `CWE-89`, for example, is the standard identifier "
            "for database injection."),
    ("Confirmed / proven", "In this pack these mean one specific thing: the action was performed, "
                           "an automatic check confirmed the result, the evidence was saved, and "
                           "the check was run again over that saved evidence when the pack was "
                           "assembled, with the same outcome."),
    ("Digital signature", "An electronic seal produced with a private key held by the signer. "
                          "Anyone can check it using the matching public key, but only the holder "
                          "of the private key can produce it, and it breaks if the sealed document "
                          "is altered afterwards."),
    ("Endpoint", "One specific address on a system that accepts requests — for example the search "
                 "page, or the login form."),
    ("Evidence bundle / proof bundle",
     "The folder named `proof-bundle` inside this pack. It holds the saved requests and replies "
     "for each proven finding, the sealed record of each proof, and the program that re-derives "
     "them. It works offline and does not contact anything that was examined."),
    ("Fact", "The word the machine-readable files use for a proven finding, as defined above. "
             "The written documents say 'proven' instead."),
    ("Fingerprint (of a file)",
     "A short value computed from a file's contents — technically a SHA-256 hash. Any change to "
     "the file, however small, produces a completely different value, which is what makes it "
     "useful for detecting alteration."),
    ("Fingerprint (of a signing authority)",
     "The same idea applied to the set of public keys entitled to sign. Comparing it against a "
     "copy obtained through a separate channel is what establishes that the signature came from "
     "the expected party rather than from somebody who substituted their own keys."),
    ("Header (HTTP header)",
     "A short instruction a web system sends alongside every page, telling the browser how to "
     "treat it. Several findings in this pack concern protective headers that were absent."),
    ("Lead", "Something flagged for attention that was not confirmed. A lead is a question, not "
             "a conclusion."),
    ("m-of-n signature",
     "A signature scheme requiring at least a set number of authorised people (m) out of a larger "
     "group (n) to sign before the result counts as valid. It removes the single point of failure "
     "of one person's key."),
    ("MANIFEST.json", "The list, inside this pack, of every file it contains together with each "
                      "file's fingerprint. Check 1 in `07-verify-it-yourself.md` uses it."),
    ("Out-of-band", "Communication through a separate channel from the one carrying the thing "
                    "being checked — for example, confirming a fingerprint by telephone rather "
                    "than reading it out of the same file you are trying to verify."),
    ("Parameter", "A named piece of information sent with a request — for example the `q` in a "
                  "web address ending `?q=chairs` is the search parameter."),
    ("Passive observation", "Something noticed in the system's ordinary replies without sending "
                            "anything unusual to it. Reliable as an observation, but it "
                            "demonstrates nothing about what an attacker could do."),
    ("Payload / test input", "The specially chosen text sent to a system to find out how it "
                             "handles input it did not expect."),
    ("SARIF", "A standard file format for security results, used so that findings can be loaded "
              "into other tools automatically. `appendix/report.sarif` is that format."),
    ("Severity rating", "How much harm a finding could cause: Critical, High, Medium, Low or "
                        "Informational. It reflects potential consequence, not how likely the "
                        "problem is to be found or used."),
    ("SHA-256", "The specific method used throughout this pack to compute fingerprints of files "
                "and of evidence. It is a published international standard."),
    ("Spine / event log", "A tamper-evident record in which each entry is linked to the one "
                          "before it, so that removing or altering an entry after the fact is "
                          "detectable. Where present it appears in the `spine/` folder."),
    ("Surface / attack surface", "The set of places on a system where input can be supplied, and "
                                 "therefore where weaknesses can exist."),
    ("Tamper-evident", "Built so that alteration is detectable. It does not mean alteration is "
                       "impossible — it means it cannot be done without leaving a trace."),
    ("Target", "The system that was examined."),
    ("Trust root", "The set of public keys entitled to sign on behalf of the producing "
                   "organisation, together with how many of them must sign. It is included in "
                   "this pack, which is why its fingerprint must be confirmed separately."),
    ("XSS (cross-site scripting)",
     "A weakness where text supplied by a visitor is placed into a web page as working code "
     "rather than as ordinary text, so the browser runs it."),
    ("SQL injection", "A weakness where text supplied by a visitor changes the question the "
                      "system asks its database, rather than merely supplying an answer to it. "
                      "'SQL' is the language used to ask databases questions."),
)


def render_glossary(*, label: str, info: RunInfo, built: Optional[str],
                    extra_terms: Iterable[tuple[str, str]] = ()) -> str:
    L = _header("Glossary", label, info.run_id, built)
    L += ["Every technical term used anywhere in this pack, in alphabetical order, explained "
          "without assuming a technical background.", ""]
    terms = list(_GLOSSARY) + [t for t in extra_terms if t]
    for term, meaning in sorted(terms, key=lambda t: t[0].lower()):
        L += [f"**{term}**", "", meaning, ""]
    L += ["---", "",
          "If a term used in this pack is missing from this list, that is a defect in the pack. "
          "Please report it to whoever supplied it.", ""]
    return "\n".join(L) + "\n"


def _extra_glossary_terms(items: Iterable[_Item]) -> list[tuple[str, str]]:
    """Glossary entries for the specific weakness categories and checks this run produced, so the
    promise that every term is explained holds for THIS pack, not merely in general."""
    known = oracle_plain_map()
    out: dict[str, str] = {}
    for it in items:
        kind = (it.graded.oracle_kind or "").strip()
        if not kind:
            continue
        out[f"{kind} (an automatic check)"] = known.get(kind) or (
            "One of the automatic checks used in this examination. The record does not carry "
            "a plain-language description of how it works; it is named here so it can be "
            "looked up by that name.")
    return sorted(out.items())


# --------------------------------------------------------------------------------------------------
# 00 — START HERE, and the archive inventory it is built around
# --------------------------------------------------------------------------------------------------

# What each file in the archive is, in one sentence, for a reader with no technical background.
# Exact names first, then prefixes, then a general fallback — so EVERY entry gets an explanation
# and nothing in the archive is left unaccounted for.
_EXACT_EXPLAIN: dict[str, str] = {
    START_HERE: "This page.",
    "index.html": "The same case summarised on one technical page, written for a security "
                  "engineer. You do not need it; it contains nothing that is not in the numbered "
                  "documents.",
    DOC_EXECUTIVE: "What was done, what was found, what it means, and what to do first. Start here "
                   "after this page.",
    DOC_APPROACH: "How the examination was carried out — and, importantly, what was not examined.",
    DOC_FINDINGS: "Every proven finding, in plain language.",
    DOC_LEADS: "What was observed or suspected but not proven, kept separate so it is not "
               "overstated.",
    DOC_CATALOGUE: "Every category of weakness the examination is able to look for, with this "
                   "engagement's position against each — so you can judge what the absence of a "
                   "finding does and does not mean.",
    DOC_WHAT_TO_DO: "The recommended order of work, with the reasoning behind it.",
    DOC_VERIFY: "The exact commands to check all of this yourself, and what a pass and a failure "
                "look like.",
    DOC_GLOSSARY: "Every technical term used anywhere in this pack, explained.",
    "README.md": "A short technical description of the archive, for whoever receives the file "
                 "itself.",
    "MANIFEST.json": "The list of every file in this pack with its fingerprint. Used by check 1 in "
                     "`07-verify-it-yourself.md` to detect alteration.",
    "MANIFEST.sig.json": "The digital signature over that list. Used by check 2 in "
                         "`07-verify-it-yourself.md` to establish who produced the pack.",
    "TRUST-ROOT-FINGERPRINT.txt": "The fingerprint of the signing authority. Confirm this value "
                                  "through a separate channel — see check 2 in "
                                  "`07-verify-it-yourself.md`.",
    "appendix/report.json": "The examination's own machine-readable record of every finding. It is "
                            "the source the written documents were produced from.",
    "appendix/report.sarif": "The same findings in SARIF, a standard format that security tooling "
                             "can load automatically.",
    "appendix/catalogue.json": "The machine-readable form of the category catalogue in "
                               "`05-what-was-looked-for.md`, with the full standards mapping for "
                               "every category.",
    "proof-bundle/README.md": "Technical notes accompanying the evidence bundle.",
    "proof-bundle/HOW-TO-VERIFY.md": "The engineer-facing version of check 3 in "
                                     "`07-verify-it-yourself.md`.",
    "proof-bundle/reverifiable.json": "The saved evidence for each proven finding, in the form the "
                                      "checking program reads.",
    "proof-bundle/evidence-bundle.json": "The sealed record of each proof, with its digital "
                                         "signature.",
    "proof-bundle/trust-root.json": "The public keys entitled to sign, and how many must sign.",
    "proof-bundle/TRUST-ROOT-FINGERPRINT.txt": "The fingerprint of those keys, for the separate-"
                                               "channel comparison described in check 2.",
    "logs/engagement-log.jsonl": "The engine's own activity log for this examination, with "
                                 "passwords and keys removed.",
    "logs/terminal-transcript.jsonl": "A signed record of the commands the operator ran by hand "
                                      "during this engagement, with passwords and keys removed.",
    "drift/drift.json": "A record of changes detected in the examined system between examinations.",
}

_PREFIX_EXPLAIN: tuple[tuple[str, str], ...] = (
    ("proof-bundle/evidence/", "A saved request or reply captured during the examination. These "
                               "are the raw bytes the automatic checks re-examine, kept exactly as "
                               "they were recorded."),
    ("proof-bundle/", "Part of the evidence bundle used by check 3 in `07-verify-it-yourself.md`."),
    ("reports/", "The detailed engineering report, written for the technical team that will make "
                 "the changes. The numbered documents cover the same ground in plain language."),
    ("appendix/", "A machine-readable record, included so that other tools and future reviewers "
                  "can read this examination without depending on the written documents."),
    ("logs/", "A record of activity during the examination, with passwords and keys removed."),
    ("spine/", "A tamper-evident event record in which each entry is cryptographically linked to "
               "the one before it, so that later alteration is detectable."),
    ("drift/", "A record of changes detected in the examined system between examinations."),
)


def explain_entry(name: str) -> str:
    """A one-sentence, non-technical explanation of one file in the archive. Every possible name
    gets an answer — the fallback names the folder rather than leaving a file unexplained."""
    if name in _EXACT_EXPLAIN:
        return _EXACT_EXPLAIN[name]
    for prefix, text in _PREFIX_EXPLAIN:
        if name.startswith(prefix):
            return text
    if name.endswith(".spine"):
        return ("A tamper-evident event record in which each entry is cryptographically linked to "
                "the one before it, so that later alteration is detectable.")
    if "/" in name:
        folder = name.split("/", 1)[0]
        return (f"A supporting file in the `{folder}/` folder, included so that the record of this "
                f"examination is complete.")
    return "A supporting file included so that the record of this examination is complete."


_START_CSS = """
:root { color-scheme: light dark; --bg:#fbfbfa; --fg:#1c1c1c; --muted:#5c5c5c; --line:#dcdcd8;
        --panel:#ffffff; --accent:#1d3f6e; --warn-bg:#fdf4e3; --warn-line:#d9b871; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#15171a; --fg:#e8e8e6; --muted:#9aa0a8; --line:#2c3037; --panel:#1c1f24;
          --accent:#9dc0f0; --warn-bg:#33290f; --warn-line:#7b6421; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:16px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
main { max-width: 46rem; margin: 0 auto; padding: 2.5rem 1.25rem 5rem; }
h1 { font-size: 1.75rem; line-height:1.25; margin: 0 0 .35rem; }
h2 { font-size: 1.2rem; margin: 2.4rem 0 .6rem; padding-bottom:.35rem; border-bottom:1px solid var(--line); }
h3 { font-size: 1rem; margin: 1.6rem 0 .4rem; }
p, li { margin: .55rem 0; }
.lede { color: var(--muted); font-size: 1.02rem; margin: 0 0 1.6rem; }
.panel { background: var(--panel); border:1px solid var(--line); border-radius:10px;
         padding: .9rem 1.1rem; margin: 1.1rem 0; }
.panel.caution { background: var(--warn-bg); border-color: var(--warn-line); }
table { border-collapse: collapse; width:100%; margin: .8rem 0; font-size: .95rem; }
th, td { text-align:left; padding:.5rem .65rem; border-bottom:1px solid var(--line); vertical-align:top; }
th { font-size:.78rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); font-weight:600; }
td.num { text-align:right; white-space:nowrap; }
code { font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.9em;
       background: rgba(127,127,127,.14); padding:.06rem .34rem; border-radius:4px; }
.filelist { overflow-x:auto; }
.step { display:flex; gap:.85rem; margin:.9rem 0; }
.step .n { flex:0 0 1.75rem; height:1.75rem; border-radius:50%; background:var(--accent); color:#fff;
           display:flex; align-items:center; justify-content:center; font-weight:700; font-size:.85rem; }
.step .b { flex:1 1 auto; }
.meta { font-size:.92rem; }
.meta td:first-child { color:var(--muted); width:38%; }
a { color: var(--accent); }
""".strip()


def render_start_here(*, label: str, info: RunInfo, built: Optional[str], facts: list[_Item],
                      observed: list[_Item], unproven: list[_Item], signed: bool,
                      fingerprint: str, proof: dict, inventory: list[str]) -> str:
    n_f, n_o, n_u = len(facts), len(observed), len(unproven)
    proof_ok = bool(proof.get("ok"))
    L: list[str] = ["<main>"]
    L.append(f"<h1>{_e(label)}</h1>")
    L.append(f"<p class='lede'>An authorised {_e(info.operation.name)}, carried out with "
             "permission on something this organisation owns. This page explains what is in this "
             "pack, what it found, and how to check any of it for yourself. No technical "
             "background is needed.</p>")

    # --- the facts of the engagement -------------------------------------------------------------
    L.append("<h2>The essentials</h2>")
    L.append("<table class='meta'><tbody>")
    rows: list[tuple[str, str]] = [
        ("Engagement", label),
        ("Kind of work", info.operation.name),
        (info.subject.label, info.subject.value),
    ]
    rows += [(k, v) for k, v in info.subject.detail]
    for k, v in tuple(rows) + (
        ("Examination started", info.started_text),
        ("Examination finished", info.finished_text),
        ("Time taken", info.duration_text),
        ("This pack was produced", built or "not recorded"),
        ("Internal reference number", info.run_id or "not recorded"),
    ):
        L.append(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>")
    L.append(f"<tr><td>Signed</td><td>{'Yes — see check 2 below' if signed else 'No — see below'}</td></tr>")
    L.append("</tbody></table>")
    if info.started is None:
        L.append("<p class='meta'>Where a value reads <em>not recorded</em>, the run genuinely "
                 "did not record it. Nothing in this pack has been estimated to fill such a "
                 "gap.</p>")

    if info.subject.unrecorded:
        L.append("<div class='panel'><p><strong>What the record does not capture.</strong> "
                 f"{_e(_article(info.operation.name).capitalize())} {_e(info.operation.name)} "
                 "records less than a reader might expect. This engagement has no record of:</p><ul>")
        for u in info.subject.unrecorded:
            L.append(f"<li>{_e(u)}</li>")
        L.append("</ul><p>Those are gaps in what was written down — not statements that the work "
                 "did not happen, and not statements that anything is fine.</p></div>")

    # --- the result -------------------------------------------------------------------------------
    L.append("<h2>What was found</h2>")
    L.append("<table><thead><tr><th>Category</th><th class='num'>Count</th><th>What it means</th>"
             "</tr></thead><tbody>")
    L.append(f"<tr><td><strong>Proven</strong></td><td class='num'>{n_f}</td>"
             "<td>Demonstrated, and confirmed again from saved evidence while this pack was "
             "assembled. You can repeat that check yourself.</td></tr>")
    L.append(f"<tr><td>Observed but not exploited</td><td class='num'>{n_o}</td>"
             "<td>Seen directly to be missing or misconfigured. Reliable as an observation; no "
             "consequence was demonstrated.</td></tr>")
    L.append(f"<tr><td>Suspected, not proven</td><td class='num'>{n_u}</td>"
             "<td>Flagged for attention, with nothing confirming it. A question, not a "
             "conclusion.</td></tr>")
    L.append("</tbody></table>")

    if facts:
        L.append("<p>In plain terms, what was demonstrated is:</p><ul>")
        for it in facts:
            L.append(f"<li><strong>{_e(it.title)}</strong> — {_e(it.what)}</li>")
        L.append("</ul>")
        L.append("<p>Each of those is set out in full in <code>03-findings.md</code>, which "
                 "states separately what was demonstrated here and what that kind of weakness can "
                 "lead to in general — the two are different, and the difference matters. What to "
                 "do about them, in order, is in <code>06-what-to-do.md</code>.</p>")
    elif info.artefact_gap("findings") is not None:
        L.append("<div class='panel caution'><p><strong>This engagement produced no findings "
                 "record, so the counts above are not a result.</strong> "
                 f"{_e(_plain(info.artefact_gap('findings')))}</p></div>")
    else:
        L.append("<div class='panel caution'><p><strong>Nothing was proven in this "
                 f"examination.</strong> That is not the same as this {_e(info.operation.subject_noun)} "
                 "being secure. It means that within the boundaries described in "
                 "<code>02-approach-and-scope.md</code>, nothing was demonstrated. Anything outside "
                 "those boundaries was not looked at. Please read "
                 "<code>02-approach-and-scope.md</code> before relying on this result.</p></div>")

    L.append("<div class='panel caution'><p><strong>What this pack does not say.</strong> It does "
             f"not say this {_e(info.operation.subject_noun)} is secure. It says what was examined "
             "and what was found. "
             "<code>02-approach-and-scope.md</code> sets out plainly what was <em>not</em> "
             "examined — anything in that list is unknown, not safe. A proven finding shows that "
             "a weakness exists; it is not evidence that anybody has used it or that data has "
             "been taken.</p></div>")

    # --- reading order -----------------------------------------------------------------------------
    L.append("<h2>What to read, in order</h2>")
    for i, (name, what) in enumerate((
        (DOC_EXECUTIVE, "What was done, what was found, what it means, and what to do first. "
                        "If you read only one document, read this one."),
        (DOC_APPROACH, "How the work was done — and what was not examined. Read this before "
                       "drawing any conclusion from the result."),
        (DOC_FINDINGS, "Every proven finding: what kind of weakness it is, what was actually "
                       "demonstrated here, how it was proved, what it does not prove, "
                       "what to do, and how to check the fix worked."),
        (DOC_LEADS, "What was observed or suspected but not proven, kept separate so that it is "
                    "not overstated."),
        (DOC_CATALOGUE, "Every category of weakness the examination can look for, and this "
                        "engagement's position against each. Read it to judge what the silence "
                        "means: a category with no finding is recorded as unknown, not as clean."),
        (DOC_WHAT_TO_DO, "The recommended order of work, with the reasoning behind it."),
        (DOC_VERIFY, "How to check everything above yourself, with the exact commands and what a "
                     "pass and a failure look like."),
        (DOC_GLOSSARY, "Every technical term used anywhere in this pack."),
    ), start=1):
        L.append(f"<div class='step'><div class='n'>{i}</div><div class='b'>"
                 f"<strong><code>{_e(name)}</code></strong><br>{_e(what)}</div></div>")

    # --- verification ------------------------------------------------------------------------------
    L.append("<h2>How to check this pack yourself</h2>")
    L.append("<p>Three separate checks, answering three different questions. Full instructions, "
             "with what a pass and a failure look like, are in "
             f"<code>{_e(DOC_VERIFY)}</code>.</p>")
    L.append("<ol>")
    L.append("<li><strong>Has anything been altered?</strong> Every file's fingerprint is "
             "recorded in <code>MANIFEST.json</code> and can be recomputed.</li>")
    if signed:
        L.append("<li><strong>Who produced it?</strong> The pack carries a digital signature. "
                 "Confirming it requires one value — the fingerprint below — obtained from the "
                 "sender through a <em>separate</em> channel, because a copy taken from inside "
                 "this pack proves nothing.</li>")
    else:
        L.append("<li><strong>Who produced it?</strong> This pack is <strong>not signed</strong> — "
                 "no signing key was available when it was produced. Its contents can still be "
                 "checked for alteration, but nothing here establishes who produced it.</li>")
    if proof_ok:
        L.append("<li><strong>Do the findings follow from the evidence?</strong> The saved "
                 "evidence and an independent checking program travel inside "
                 "<code>proof-bundle/</code>. Running it re-derives every proven finding on your "
                 "own machine, offline, without trusting this pack.</li>")
    else:
        L.append("<li><strong>Do the findings follow from the evidence?</strong> No evidence "
                 "bundle is included, because nothing was proven to the standard that produces "
                 "one. That is the honest outcome for this examination, not an omission.</li>")
    L.append("</ol>")
    if signed and (proof.get("trust_root_fingerprint") or fingerprint):
        fp = proof.get("trust_root_fingerprint") or fingerprint
        L.append("<div class='panel'><p><strong>Fingerprint of the signing authority</strong></p>"
                 f"<p><code>{_e(fp)}</code></p>"
                 "<p>Obtain this same value from the sender by telephone, letter, or another "
                 "channel that did not carry this file, and compare it character by character. If "
                 "the two differ, do not trust this pack.</p></div>")

    # --- complete inventory -------------------------------------------------------------------------
    L.append("<h2>Everything in this pack</h2>")
    L.append("<p>Every file in the archive is listed below with what it is, so that nothing here "
             "is unexplained.</p>")
    L.append("<div class='filelist'><table><thead><tr><th>File</th><th>What it is</th></tr>"
             "</thead><tbody>")
    for name in inventory:
        L.append(f"<tr><td><code>{_e(name)}</code></td><td>{_e(explain_entry(name))}</td></tr>")
    L.append("</tbody></table></div>")
    L.append(f"<p class='meta'>{_count_word(len(inventory), 'file')} in total.</p>")

    L.append("<h2>Questions</h2>")
    L.append("<p>Anything in this pack can be handed to any competent technical person, including "
             "one with no connection to this organisation, and checked independently. The "
             "conclusions do not depend on trusting the party that produced them — which is the "
             "reason the evidence is packaged this way.</p>")
    L.append("</main>")

    body = "\n".join(L)
    return ("<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_e(label)} — security examination</title>"
            f"<style>{_START_CSS}</style></head><body>\n{body}\n</body></html>\n")


# --------------------------------------------------------------------------------------------------
# the public entry point
# --------------------------------------------------------------------------------------------------


def _classify(graded: list[GradedFinding], adapted: AdaptResult) -> tuple[list[_Item], list[_Item], list[_Item]]:
    """Split the graded findings into proven / observed-not-exploited / suspected-not-proven, each
    carrying the extras the export held. A passive observation is separated from a genuine lead
    because calling a directly-observed missing header a "suspicion" understates it, and calling
    it a proven attack overstates it."""
    facts: list[_Item] = []
    observed: list[_Item] = []
    unproven: list[_Item] = []
    for g in graded:
        extras = adapted.extras.get(g.finding.finding_slug) or FindingExtras(slug=g.finding.finding_slug)
        what, why, generic = _plain_for(g.finding.bug_class, g.finding.title)
        item = _Item(graded=g, extras=extras, what=what, why=why, generic=generic)
        if g.is_fact:
            facts.append(item)
        elif extras.kind == "passive" and g.grade != GRADE_DEMOTED:
            observed.append(item)
        else:
            unproven.append(item)

    from .priority import SEVERITY_RANK

    def _key(it: _Item) -> tuple[int, str]:
        return (SEVERITY_RANK.get(it.graded.finding.severity, 5), it.graded.finding.finding_slug)

    facts.sort(key=_key)
    observed.sort(key=_key)
    unproven.sort(key=_key)
    return (facts, observed, unproven)


def build_case_file(
    *,
    label: str,
    run_info: RunInfo,
    graded: list[GradedFinding],
    adapted: AdaptResult,
    proof: dict,
    signed: bool,
    fingerprint: str,
    generated_at: Optional[str],
    inventory: list[str],
    notes: Iterable[str] = (),
    catalogue: Optional[Catalogue] = None,
) -> dict[str, bytes]:
    """Render the case-file documents. Returns ``{arcname: bytes}``.

    ``inventory`` is the FULL list of archive entry names the finished dossier will contain,
    including the documents this function returns and the signature envelope — that is what lets
    the START-HERE page account for every file. ``label`` is presentation only: it names the
    engagement for a human reader and never reaches a certificate or a signed claim.

    Pure and deterministic given its inputs (``generated_at`` is the only injected clock)."""
    facts, observed, unproven = _classify(graded, adapted)
    # The build stamp is injected as an ISO string; render it the way every other time in the pack
    # is rendered, falling back to the raw value if it cannot be parsed (never dropping it).
    built = human_time(generated_at) or generated_at
    cat = catalogue if catalogue is not None else build_catalogue(graded)

    out: dict[str, bytes] = {}
    out[START_HERE] = render_start_here(
        label=label, info=run_info, built=built, facts=facts, observed=observed,
        unproven=unproven, signed=signed, fingerprint=fingerprint, proof=proof,
        inventory=sorted(inventory)).encode("utf-8")
    out[DOC_EXECUTIVE] = render_executive(
        label=label, info=run_info, facts=facts, observed=observed, unproven=unproven,
        built=built, signed=signed, proof_ok=bool(proof.get("ok")),
        n_certs=int(proof.get("certificates") or 0)).encode("utf-8")
    out[DOC_APPROACH] = render_approach(
        label=label, info=run_info, built=built, adapted=adapted, n_facts=len(facts),
        notes=notes).encode("utf-8")
    out[DOC_FINDINGS] = render_findings(
        label=label, info=run_info, facts=facts, built=built).encode("utf-8")
    out[DOC_LEADS] = render_leads(
        label=label, info=run_info, observed=observed, unproven=unproven, built=built).encode("utf-8")
    out[DOC_CATALOGUE] = render_catalogue(
        label=label, info=run_info, cat=cat, built=built).encode("utf-8")
    out[DOC_WHAT_TO_DO] = render_what_to_do(
        label=label, info=run_info, facts=facts, observed=observed, unproven=unproven,
        built=built).encode("utf-8")
    out[DOC_VERIFY] = render_verify(
        label=label, info=run_info, built=built, signed=signed, fingerprint=fingerprint,
        proof=proof, n_facts=len(facts)).encode("utf-8")
    out[DOC_GLOSSARY] = render_glossary(
        label=label, info=run_info, built=built,
        extra_terms=_extra_glossary_terms(facts)).encode("utf-8")
    return out
