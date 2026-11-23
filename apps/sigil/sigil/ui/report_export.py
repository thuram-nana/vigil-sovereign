"""PR-G (Area 6) — the shareable ASSESSMENT REPORT: one workspace's PROVEN findings as a deterministic,
self-contained HTML document a customer can hand to an auditor or their own customer (and, through the
owner-provisioned renderer in ``ui/report_pdf``, the same document as a PDF).

WHAT IS IN IT. An executive summary (the posture score with how it is computed, the severity breakdown, what to fix
first), every proven finding worst-first in plain language (the SIGNED plain-language impact and fix when the
certificate carries them — never improvised), the remediation roadmap by tier, the OWASP / PCI DSS / SOC 2 controls
those findings implicate (``ui/compliance_view`` — never a claim that a control is met), and "verify it yourself":
each finding's offline re-verification command and proof fingerprint.

REDACTION (an allowlist, never a cert dump). Per finding the report carries only: its reference, title, severity (and
whether that severity is the certificate's own or an estimate), class, host, surface, confidence, summary, the signed
plain-language impact + fix, the standards it implicates, its remediation tier, its retest verdict, the offline
``how_to_verify`` command and the ``oracle_context_digest`` fingerprint. No proof bytes beyond ``how_to_verify``: the
report claims, the artifact manifest, the internal engagement slug and any other certificate field never reach it.

DETERMINISTIC + INERT. The same spine and the same ``now`` give byte-identical HTML (no wallclock or randomness of its
own; ordering is total). Every value is HTML-escaped; the document has no script, no form, no external reference
(the wordmark is an inline ``data:`` image of the app's own SVG) and pins itself with a ``default-src 'none'`` CSP, so
opening it from disk runs nothing.

TENANT ISOLATION + PROVEN ONLY are inherited from :func:`compliance_view.proven_rows` (the org's own server-derived
slug set; a FACT-bearing certificate per row). The trial preview lock is the PROVISIONER's: a locked org is refused
before this module runs (the full report is what a purchase unlocks).

FATAL-2: sovereign-side — stdlib + vigil_core + ui-local only; ``assert_no_offense`` at import. A pure read.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from ..reuse import assert_no_offense

assert_no_offense()

from vigil_core import standards_mirror as _sm  # noqa: E402

from . import compliance_view as _cv  # noqa: E402
from . import finding_presentation as _fpres  # noqa: E402
from . import finding_preview as _fp  # noqa: E402

REPORT_SCHEMA = "vigil.customer-report/v1"
HTML_CONTENT_TYPE = "text/html; charset=utf-8"
# The finding fields the report may carry (the redaction allowlist; see the module docstring).
REPORT_FIELDS = ("finding_ref", "title", "severity", "severity_basis", "bug_class", "host", "surface", "confidence",
                 "summary", "plain_impact", "remediation", "standards_chips", "tier", "tier_label", "retest",
                 "how_to_verify", "oracle_context_digest")
_PLAIN_IMPACT_FIELDS = ("what", "category_consequence", "established")
_TOP_N = 3
_WORDMARK = Path(__file__).resolve().parent / "customer_app" / "brand" / "vigil-wordmark.svg"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_-]+")
_SEVERITY_LABELS = {"critical": "Critical", "high": "High", "unrated": "Unrated", "medium": "Medium", "low": "Low",
                    "info": "Info"}
_STATUS_LABELS = {_cv.STATUS_PROVEN: "Proven weakness", _cv.STATUS_FIXED: "Fixed (retest)",
                  _cv.STATUS_NONE: "No proven weakness", _cv.STATUS_NOT_MAPPED: "Not mapped by VIGIL checks"}


def _e(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


@lru_cache(maxsize=1)
def _wordmark_uri() -> str:
    """The app's own wordmark as an inline data: URI (so the document stays self-contained), or "" if unreadable."""
    try:
        return "data:image/svg+xml;base64," + base64.b64encode(_WORDMARK.read_bytes()).decode("ascii")
    except OSError:
        return ""


def _redact(row: dict) -> "dict[str, Any]":
    """One finding projected through the REPORT_FIELDS allowlist (the signed plain-language impact through its own)."""
    out: "dict[str, Any]" = {}
    for k in REPORT_FIELDS:
        v = row.get(k)
        if v is None or v == "" or v == []:
            continue
        if k == "plain_impact":
            if not isinstance(v, dict):
                continue
            v = {f: str(v[f]) for f in _PLAIN_IMPACT_FIELDS if isinstance(v.get(f), str) and v[f].strip()}
            if not v:
                continue
        out[k] = v
    return out


def _stamp(now: float) -> "tuple[str, str]":
    t = time.gmtime(float(now))
    return time.strftime("%Y-%m-%d %H:%M UTC", t), time.strftime("%Y%m%d", t)


def report_model(store, org_id: str, *, now: float, org_name: str = "", retests: bool = False) -> "dict[str, Any]":
    """The report's DATA (what the HTML renders), from the org's OWN proven findings. PURE + deterministic."""
    rows = _cv.proven_rows(store, org_id, now=now, retests=retests)
    findings = [_redact(r) for r in rows]
    counts = {s: 0 for s in _fp.SEVERITIES}
    for r in rows:
        counts[r["severity"] if r["severity"] in counts else "unrated"] += 1
    open_rows = [r for r in rows if r.get("retest") != "fixed"]
    stamp, _day = _stamp(now)
    compliance = _cv.rollup(rows)
    model: "dict[str, Any]" = {
        "schema": REPORT_SCHEMA,
        "org_id": org_id,
        "org_name": org_name or org_id,
        "generated_at": stamp,
        "posture_score": _fpres.posture_score(rows),
        "posture_basis": "100 × 100 ÷ (100 + the sum of each proven finding's severity weight); an honest "
                         "prioritisation heuristic, not a measured or certified rating",
        "findings_total": len(rows),
        "hosts": sorted({r["host"] for r in rows if r.get("host")}),
        "severity_counts": counts,
        "fix_first": [{"finding_ref": r["finding_ref"], "title": r["title"], "severity": r["severity"],
                       "host": r.get("host", "")} for r in open_rows[:_TOP_N]],
        "findings": findings,
        "compliance": {"frameworks": [
            {"framework": fw["framework"], "label": fw["label"], "version": fw["version"], "summary": fw["summary"],
             "controls": [c for c in fw["controls"] if c["status"] in (_cv.STATUS_PROVEN, _cv.STATUS_FIXED)]}
            for fw in compliance["frameworks"]], "statement": compliance["statement"]},
    }
    canon = json.dumps(model, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    model["fingerprint"] = "sha256:" + hashlib.sha256(canon).hexdigest()
    return model


_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #10141c;
       background: #ffffff; margin: 0; }
main { max-width: 920px; margin: 0 auto; padding: 32px 24px 48px; }
header { border-bottom: 2px solid #10141c; padding-bottom: 16px; margin-bottom: 24px; }
header img { height: 28px; width: auto; display: block; margin-bottom: 12px; }
h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 32px 0 12px; }
h3 { font-size: 15px; margin: 0 0 6px; }
.meta { color: #4a5263; font-size: 12px; } .muted { color: #4a5263; }
table { border-collapse: collapse; width: 100%; } th, td { text-align: left; padding: 6px 8px;
  border-bottom: 1px solid #d9dde5; vertical-align: top; }
.finding { border: 1px solid #d9dde5; border-radius: 8px; padding: 14px 16px; margin: 12px 0;
  page-break-inside: avoid; }
.sev { display: inline-block; font-size: 11px; font-weight: 600; text-transform: uppercase; padding: 1px 8px;
  border-radius: 10px; border: 1px solid #10141c; }
.sev-critical { background: #7f1d1d; color: #ffffff; } .sev-high { background: #c2410c; color: #ffffff; }
.sev-medium { background: #facc15; } .sev-low { background: #dbeafe; } .sev-info, .sev-unrated { background: #eef0f4; }
.score { font-size: 40px; font-weight: 700; } dl { margin: 8px 0; } dt { font-weight: 600; }
dd { margin: 0 0 8px; } code { font: 12px/1.4 ui-monospace, Menlo, Consolas, monospace; background: #f3f4f7;
  padding: 1px 4px; border-radius: 4px; word-break: break-all; }
.chips span { display: inline-block; border: 1px solid #b8bfcc; border-radius: 10px; padding: 0 8px;
  font-size: 12px; margin: 2px 4px 2px 0; }
footer { margin-top: 40px; border-top: 1px solid #d9dde5; padding-top: 12px; font-size: 12px; color: #4a5263; }
""".strip()


def _sev(sev: str) -> str:
    key = sev if sev in _SEVERITY_LABELS else "unrated"
    return f'<span class="sev sev-{key}">{_e(_SEVERITY_LABELS[key])}</span>'


def _chips(chips: "Optional[list]") -> str:
    out = []
    for c in chips or ():
        if isinstance(c, dict) and c.get("framework") in _cv.FRAMEWORKS:
            out.append(f"<span>{_e(c.get('label'))} {_e(', '.join(str(i) for i in c.get('ids') or ()))}</span>")
    return f'<p class="chips">{"".join(out)}</p>' if out else ""


def _finding_html(f: dict, n: int) -> str:
    sev = str(f.get("severity") or "unrated")
    basis = "the certificate's own rating" if f.get("severity_basis") == "certificate" else \
        "an estimate for this class of weakness"
    meta = (f'<p class="meta">Severity: {_e(_SEVERITY_LABELS.get(sev, sev))} ({_e(basis)}) · Host: '
            f"{_e(f.get('host') or '—')} · Class: {_e(f.get('bug_class'))} · Reference: "
            f"<code>{_e(f.get('finding_ref'))}</code></p>")
    parts = [f'<section class="finding" id="f{n}">', f"<h3>{n}. {_e(f.get('title'))} {_sev(sev)}</h3>", meta]
    if f.get("retest") == "fixed":
        parts.append("<p><strong>Retested: the proof no longer works on this host.</strong></p>")
    elif f.get("retest") == "still_vulnerable":
        parts.append("<p><strong>Retested: the proof still works on this host.</strong></p>")
    parts.append("<dl>")
    if f.get("surface"):
        parts.append(f"<dt>Where</dt><dd><code>{_e(f['surface'])}</code></dd>")
    if f.get("summary"):
        parts.append(f"<dt>Summary</dt><dd>{_e(f['summary'])}</dd>")
    pi = f.get("plain_impact") or {}
    if pi.get("what"):
        parts.append(f"<dt>What this is</dt><dd>{_e(pi['what'])}</dd>")
    if pi.get("category_consequence"):
        parts.append(f"<dt>What this kind of weakness can lead to</dt><dd>{_e(pi['category_consequence'])}</dd>")
    if pi.get("established"):
        parts.append(f"<dt>What the proof established</dt><dd>{_e(pi['established'])}</dd>")
    if f.get("remediation"):
        parts.append(f"<dt>How to fix it</dt><dd>{_e(f['remediation'])}</dd>")
    else:
        parts.append("<dt>How to fix it</dt><dd class=\"muted\">This finding's certificate carries no signed fix "
                     "guidance, so none is shown here (VIGIL never improvises one).</dd>")
    if f.get("tier_label"):
        parts.append(f"<dt>Roadmap tier</dt><dd>{_e(f['tier_label'])}</dd>")
    if f.get("confidence") not in (None, ""):
        parts.append(f"<dt>Proof strength</dt><dd>{_e(f['confidence'])}</dd>")
    if f.get("how_to_verify"):
        parts.append(f"<dt>Verify it yourself</dt><dd><code>{_e(f['how_to_verify'])}</code></dd>")
    if f.get("oracle_context_digest"):
        parts.append(f"<dt>Proof fingerprint</dt><dd><code>{_e(f['oracle_context_digest'])}</code></dd>")
    parts.append("</dl>")
    parts.append(_chips(f.get("standards_chips")))
    parts.append("</section>")
    return "\n".join(p for p in parts if p)


def render_html(model: "dict[str, Any]") -> str:
    """The report document for ``model`` (from :func:`report_model`). Deterministic; every value escaped."""
    m = model
    logo = _wordmark_uri()
    sev_rows = "".join(f"<tr><td>{_sev(s)}</td><td>{int(n)}</td></tr>"
                       for s, n in m["severity_counts"].items() if n)
    fix_first = "".join(f"<li>{_sev(x['severity'])} {_e(x['title'])}"
                        f"{(' — ' + _e(x['host'])) if x.get('host') else ''}</li>" for x in m["fix_first"])
    findings = "\n".join(_finding_html(f, i) for i, f in enumerate(m["findings"], 1))
    tiers: "dict[int, list[dict]]" = {}
    for f in m["findings"]:
        if f.get("retest") != "fixed":
            tiers.setdefault(int(f.get("tier", 3)), []).append(f)
    roadmap = "".join(
        f"<h3>{_e(_sm.tier_label(t) or ('Tier ' + str(t)))}</h3><ul>"
        + "".join(f"<li>{_sev(str(f.get('severity')))} {_e(f.get('title'))}</li>" for f in fs) + "</ul>"
        for t, fs in sorted(tiers.items()))
    comp = []
    for fw in m["compliance"]["frameworks"]:
        s = fw["summary"]
        hit = s.get(_cv.STATUS_PROVEN, 0) + s.get(_cv.STATUS_FIXED, 0)
        comp.append(f"<h3>{_e(fw['label'])} <span class=\"meta\">{_e(fw['version'])}</span></h3>")
        if not fw["controls"]:
            comp.append("<p class=\"muted\">No proven weakness in this workspace implicates a control of this "
                        "framework.</p>")
            continue
        comp.append(f"<p class=\"muted\">{hit} control(s) implicated by a proven weakness.</p><table><thead><tr>"
                    "<th>Control</th><th>Status</th><th>Findings</th></tr></thead><tbody>")
        for c in fw["controls"]:
            name = f" — {_e(c['name'])}" if c.get("name") else ""
            refs = "; ".join(f"{_e(x['title'])}{' (fixed)' if x.get('retest') == 'fixed' else ''}"
                             for x in c["findings"])
            comp.append(f"<tr><td><code>{_e(c['id'])}</code>{name}</td>"
                        f"<td>{_e(_STATUS_LABELS.get(c['status'], c['status']))}</td><td>{refs}</td></tr>")
        comp.append("</tbody></table>")
    empty = "" if m["findings"] else ("<p>No proven findings in this workspace. That is not a statement that its "
                                      "hosts are free of weaknesses: VIGIL lists only what it proved.</p>")
    head_logo = f'<img src="{logo}" alt="VIGIL" />' if logo else "<strong>VIGIL</strong>"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:" />
<meta name="robots" content="noindex" />
<title>VIGIL security report — {_e(m['org_name'])}</title>
<style>
{_CSS}
</style>
</head>
<body>
<main>
<header>
{head_logo}
<h1>Security assessment report</h1>
<p class="meta">Workspace: {_e(m['org_name'])} ({_e(m['org_id'])}) · Generated {_e(m['generated_at'])} ·
Report fingerprint: <code>{_e(m['fingerprint'])}</code></p>
</header>
<section id="summary">
<h2>At a glance</h2>
<p><span class="score">{int(m['posture_score'])}</span> / 100 posture score</p>
<p class="muted">How it is computed: {_e(m['posture_basis'])}.</p>
<p>{int(m['findings_total'])} proven finding(s) across {len(m['hosts'])} host(s).</p>
{('<table><thead><tr><th>Severity</th><th>Findings</th></tr></thead><tbody>' + sev_rows + '</tbody></table>')
 if sev_rows else ''}
{('<h3>Fix first</h3><ol>' + fix_first + '</ol>') if fix_first else ''}
{empty}
</section>
<section id="findings">
<h2>Proven findings, worst first</h2>
<p class="muted">Every finding below was confirmed by a deterministic check on evidence the host produced. Anything
VIGIL could not prove is not in this report.</p>
{findings}
</section>
<section id="roadmap">
<h2>Remediation roadmap</h2>
{roadmap or '<p class="muted">Nothing open to fix.</p>'}
</section>
<section id="standards">
<h2>Standards mapping</h2>
<p>{_e(m['compliance']['statement'])}</p>
{''.join(comp)}
</section>
<section id="verify">
<h2>Verify it yourself</h2>
<p>Each finding lists the command that re-runs its proof offline, without VIGIL, and the fingerprint of the proof it
re-runs. Run the command to confirm the finding independently of this report.</p>
</section>
<footer>
<p>Generated by VIGIL from oracle-confirmed findings only ({_e(m['schema'])}). This report carries no proof data
beyond each finding's offline verification command and proof fingerprint. The posture score is a prioritisation
heuristic, not a certified rating, and the standards mapping is not a compliance attestation.</p>
</footer>
</main>
</body>
</html>
"""


def safe_filename(org_id: str, now: float, ext: str) -> str:
    """``vigil-report-<org>-<YYYYMMDD>.<ext>``, the org reduced to [A-Za-z0-9_-]."""
    _stamp_s, day = _stamp(now)
    org = _SAFE_NAME.sub("-", str(org_id or "workspace")).strip("-")[:64] or "workspace"
    return f"vigil-report-{org}-{day}.{ext}"


def build_report(store, org_id: str, *, now: float, org_name: str = "", retests: bool = False) -> "dict[str, Any]":
    """The HTML report for ONE org, as the export action returns it: the document, its SHA-256, a safe file name and
    the counts. PURE read; assumes the caller already authorized ``org_id`` for ``view_assessments`` and refused a
    preview-locked org."""
    model = report_model(store, org_id, now=now, org_name=org_name, retests=retests)
    doc = render_html(model)
    raw = doc.encode("utf-8")
    return {"schema": REPORT_SCHEMA, "org_id": org_id, "format": "html", "content_type": HTML_CONTENT_TYPE,
            "filename": safe_filename(org_id, now, "html"), "generated_at": model["generated_at"],
            "fingerprint": model["fingerprint"], "findings_total": model["findings_total"],
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "html": doc}
