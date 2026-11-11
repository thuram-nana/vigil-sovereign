"""live.ci_annotate — the FACT/LEAD-typed PR annotation layer (W4).

Pins:
  * HONEST typing: a finding is a FACT only when static_oracle_confirmed is True — a DAA match the oracle
    did not confirm (incl. one codescan labels grounding="fact"/verified_by_oracle=True on the DAA tier)
    is a LEAD (::warning), never ::error. This is the W4 guarantee that CI never over-claims a lead.
  * GitHub workflow-command escaping on attacker-influenceable fields (no %/CR/LF/comma/colon break-out).
  * counts() + summary_markdown() shape; markdown table metacharacters neutralized.
"""

from __future__ import annotations

from vigil_integration.live.ci_annotate import (
    annotation_lines,
    counts,
    is_fact,
    summary_markdown,
    warning_annotation,
)

# An oracle-CONFIRMED FACT.
_FACT = {"title": "weak hash", "bug_class": "broken-crypto-invocation", "severity": "High",
         "location": "pkg/a.py:12", "static_oracle_confirmed": True,
         "grounding": "fact", "verified_by_oracle": True}
# A DAA match codescan labels grounding="fact"/verified_by_oracle=True on the DAA tier, but which the
# oracle did NOT confirm (a LEAD-only class). The annotate layer MUST type this a LEAD.
_LEAD_DAA = {"title": "shell true", "bug_class": "os-command", "severity": "High",
             "location": "pkg/b.py:3", "grounding": "fact", "verified_by_oracle": True}
# A FACT-capable class the oracle REFUSED.
_LEAD_REFUSED = {"title": "tls off", "bug_class": "insecure-flag", "severity": "Medium",
                 "location": "pkg/c.py:7", "static_oracle_confirmed": False,
                 "grounding": "fact", "verified_by_oracle": True}


def test_fact_typing_keys_off_the_oracle_verdict_not_the_daa_tier() -> None:
    assert is_fact(_FACT) is True
    assert is_fact(_LEAD_DAA) is False       # DAA grounding="fact" must NOT make it a FACT
    assert is_fact(_LEAD_REFUSED) is False   # an oracle refusal is a LEAD


def test_annotation_lines_error_for_fact_warning_for_leads() -> None:
    lines = annotation_lines([_FACT, _LEAD_DAA, _LEAD_REFUSED])
    assert lines[0].startswith("::error file=pkg/a.py,line=12,") and "VIGIL FACT" in lines[0]
    assert lines[1].startswith("::warning file=pkg/b.py,line=3,") and "VIGIL LEAD" in lines[1]
    assert lines[2].startswith("::warning file=pkg/c.py,line=7,") and "VIGIL LEAD" in lines[2]


def test_annotation_escapes_workflow_command_metacharacters() -> None:
    evil = {"title": "x\n::error::INJECTED, comma: colon %pct",
            "bug_class": "b", "severity": "High", "location": "p.py:1",
            "static_oracle_confirmed": True}
    lines = annotation_lines([evil])
    assert len(lines) == 1                    # one finding -> one command
    line = lines[0]
    # the load-bearing safety property: NO raw newline embedded in the command string, so GitHub cannot
    # parse the attacker's '::error::INJECTED' as a SECOND command line — it stays inert mid-line data.
    assert "\n" not in line and "\r" not in line
    assert line.startswith("::error file=p.py,line=1,")   # exactly one real command, at the line start
    assert "%25pct" in line                   # percent escaped per the workflow-command spec


def test_counts_and_summary_markdown_shape() -> None:
    c = counts([_FACT, _LEAD_DAA, _LEAD_REFUSED])
    assert c == {"facts": 1, "leads": 2, "total": 3, "by_severity": {"high": 2, "medium": 1}}
    md = summary_markdown([_FACT, _LEAD_DAA], repo="github.com/o/r", commit="abc")
    assert "VIGIL code security scan" in md
    assert "1 oracle-confirmed FACT(s)" in md and "1 LEAD(s)" in md
    assert "Oracle-confirmed FACTs" in md and "Leads (unconfirmed" in md


def test_markdown_neutralizes_table_breakout() -> None:
    nasty = {"title": "a | b `c` [x](y)", "bug_class": "x", "severity": "Low", "location": "p.py:1",
             "static_oracle_confirmed": False}
    md = summary_markdown([nasty])
    # pipe escaped, backtick neutralized, inline-link brackets escaped — no table break-out / link injection
    assert "a \\| b 'c' \\[x\\](y)" in md


def test_summary_banner_surfaces_a_not_scanned_status() -> None:
    md = summary_markdown([], repo="github.com/o/r", banner="NOT SCANNED — the scan was REFUSED (no-authority).")
    assert "[!WARNING]" in md and "NOT SCANNED" in md and "REFUSED" in md
    # without a banner, no warning block
    assert "[!WARNING]" not in summary_markdown([], repo="github.com/o/r")


def test_warning_annotation_is_an_escaped_standalone_command() -> None:
    line = warning_annotation("x\n::error::INJECTED % danger")
    assert line.startswith("::warning title=VIGIL::")
    assert "\n" not in line and "%25" in line        # no raw newline (no injected 2nd command); % escaped
