"""
report.dossier — the ONE-CLICK run dossier compiler (R2).

"Every operation downloadable with one click." ``build_dossier`` assembles EVERYTHING a run
produced — the three human reports, the machine exports, the offline-verifiable proof bundle,
the scrubbed engagement log, the governance-signed spine chain, any drift record, and a
readable ``index.html`` — into ONE self-contained, tamper-evident ``.zip`` the operator can
hand to anyone.

What makes it trustworthy (and honest):

  * **Tamper-evidence.** A ``MANIFEST.json`` lists every content entry with its sha256; a
    governance ``MANIFEST.sig.json`` (m-of-n Ed25519 over the manifest bytes) + a
    ``TRUST-ROOT-FINGERPRINT.txt`` anchor authenticity. Flip any byte in any entry and the
    manifest check fails; re-sign under another key and the fingerprint (pinned out-of-band)
    refuses. If no governance signer is resolvable, the dossier is still integrity-checkable
    (hashes) but is HONESTLY marked NOT authenticity-signed.
  * **Offline re-verification.** The embedded proof bundle re-verifies in a VIGIL-free venv with
    the exact ``framework.v2 evidence verify`` command the ``index.html`` prints — the same
    zero-trust check ``vigil proof-export`` ships. A run with no oracle-confirmed FACT carries no
    bundle and says so plainly (a LEAD is a lead).
  * **Path safety.** Every zip entry is confined to a safe relative path (no absolute, no ``..``);
    symlinks are never followed. This reuses the C1 ``action_id`` confinement discipline from
    ``proof/bundle.py`` so no entry can ever escape the archive.
  * **Determinism.** Sorted zip entries, a fixed entry timestamp, and NO wallclock in the hashed
    content: the MANIFEST is a pure function of the inputs (+ an OPTIONAL injected ``generated_at``
    stamp). Two builds over the same inputs → identical MANIFEST hashes.

FATAL-2: this module lives on the offense side (``framework``). It reuses the report renderers
(``report.generate`` / ``report.export``) and the log scrubber (``common.logging._scrub``) at
module scope (all import-clean framework), but imports the proof bundle
(``vigil_integration.proof.bundle``) and the governance provisioner LAZILY / function-local — that
keeps the heavy integration import off the module-load path.
"""

from __future__ import annotations

import hashlib
import html
import io
import json
import os
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..common.logging import _scrub  # reuse the engagement-log secret scrubber verbatim
from .export import export_json, export_sarif
from .generate import ReportMeta, generate_reports

# A fixed zip entry timestamp (the ZIP epoch) so the archive framing carries NO wallclock and two
# builds over the same inputs produce byte-identical entries. The MANIFEST hashes the entry CONTENT,
# not this framing, so determinism holds regardless — this only makes the raw .zip bytes stable too.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

# The three operator documents, in the order the report package names them.
_REPORT_MD = ("executive.md", "technical.md", "remediation-roadmap.md")

# Candidate directories, relative to the run dir, to discover pre-rendered artifacts in.
_REPORT_DIRS = ("", "reports")


# --------------------------------------------------------------------------------------------------
# path safety — every arcname is confined; no absolute / no `..`; symlinks never followed
# --------------------------------------------------------------------------------------------------


def _is_safe_rel(name: str) -> bool:
    """True iff ``name`` is a confined relative arcname — not absolute, no ``..`` segment, not a
    Windows drive/UNC. Mirrors the C1 ``action_id`` confinement in ``proof/bundle.py``: an unsafe
    path DROPS its artifact, it never escapes the archive."""
    if not name:
        return False
    p = Path(name)
    if p.is_absolute():
        return False
    parts = p.parts
    if not parts:
        return False
    return not any(seg in ("..", "") or (len(seg) == 2 and seg[1] == ":") for seg in parts)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------------------------------
# discovery helpers — read what a run produced, from a small set of known locations
# --------------------------------------------------------------------------------------------------


def _read_bytes(p: Path) -> Optional[bytes]:
    try:
        if p.is_symlink() or not p.is_file():
            return None
        return p.read_bytes()
    except OSError:
        return None


def _read_text(p: Path) -> Optional[str]:
    b = _read_bytes(p)
    return None if b is None else b.decode("utf-8", errors="replace")


def _find_in(run_dir: Path, name: str) -> Optional[Path]:
    """The first existing (non-symlink) ``name`` across the candidate report dirs under ``run_dir``."""
    for sub in _REPORT_DIRS:
        cand = (run_dir / sub / name) if sub else (run_dir / name)
        if not cand.is_symlink() and cand.is_file():
            return cand
    return None


def _load_findings_source(run_dir: Path) -> Optional[list[dict]]:
    """A RAW findings source (``findings.json``) to feed the renderers, if present. Accepts a bare
    list, ``{"findings": [...]}`` or ``{"active_findings": [...]}``. Returns ``None`` when absent /
    unusable — the compiler then just ships whatever pre-rendered docs it found."""
    p = _find_in(run_dir, "findings.json")
    if p is None:
        return None
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        for key in ("findings", "active_findings"):
            v = doc.get(key)
            if isinstance(v, list):
                return [f for f in v if isinstance(f, dict)]
    return None


def _read_reverifiable(run_dir: Path) -> list[dict]:
    """The run's oracle-confirmed FACT set (``active_findings``). Handles BOTH conventions: the proof
    studio's ``proofs/reverifiable.json`` and a scan/console run's top-level ``reverifiable.json``.
    Total on a missing/unreadable file."""
    for rel in ("proofs/reverifiable.json", "reverifiable.json"):
        p = run_dir / rel
        if p.is_symlink() or not p.is_file():
            continue
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        fs = doc.get("active_findings") if isinstance(doc, dict) else None
        if isinstance(fs, list):
            return [f for f in fs if isinstance(f, dict)]
    return []


def _scrub_log(run_dir: Path) -> tuple[Optional[str], int]:
    """Find an engagement log under ``run_dir`` (or ``run_dir/logs``) and return its SCRUBBED JSONL
    text + a count of lines dropped as unparseable. Every parseable line is run through the same
    ``common.logging._scrub`` secret masker the live logger uses, then re-dumped deterministically
    (``sort_keys``); an unparseable line is DROPPED rather than shipped in the clear (the scrubber
    is a structured-key masker, not a free-text scanner — dropping is the safe choice). Returns
    ``(None, 0)`` when no log is found."""
    candidates: list[Path] = []
    for d in (run_dir, run_dir / "logs"):
        if not d.is_dir():
            continue
        for pat in (".crucible-v2.log", "engagement-log.jsonl", "engagement.log", "*.log"):
            candidates += sorted(x for x in d.glob(pat) if x.is_file() and not x.is_symlink())
    # de-dup, preserve order
    seen: set[str] = set()
    picked: list[Path] = []
    for c in candidates:
        if str(c) not in seen:
            seen.add(str(c))
            picked.append(c)
    if not picked:
        return (None, 0)

    out_lines: list[str] = []
    dropped = 0
    for path in picked:
        text = _read_text(path)
        if text is None:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                dropped += 1
                continue
            if not isinstance(obj, dict):
                dropped += 1
                continue
            scrubbed = _scrub(None, "", obj)  # the live logger's secret masker, reused verbatim
            out_lines.append(json.dumps(scrubbed, sort_keys=True, default=str))
    if not out_lines and dropped == 0:
        return (None, 0)
    return ("\n".join(out_lines) + ("\n" if out_lines else ""), dropped)


def _find_spine(run_dir: Path, base_dir: Optional[str]) -> dict[str, bytes]:
    """Any hash-linked, governance-signed spine artifact present (already redacted at rest). Searches
    ``run_dir`` for the json head/chain forms and ``run_dir``/``base_dir`` for a ``<slug>.spine`` file.
    Verbatim — the dossier does not re-derive the chain (that needs the live blackboard)."""
    out: dict[str, bytes] = {}
    for name in ("spine-chain.json", "spine-head.json", "spine.json"):
        b = _read_bytes(run_dir / name)
        if b is not None:
            out[name] = b
    search_dirs = [run_dir]
    if base_dir:
        search_dirs.append(Path(base_dir))
    for d in search_dirs:
        if not d.is_dir():
            continue
        for sp in sorted(x for x in d.glob("*.spine") if x.is_file() and not x.is_symlink()):
            b = _read_bytes(sp)
            if b is not None:
                out[sp.name] = b
    return out


def _find_drift(run_dir: Path) -> Optional[bytes]:
    for name in ("drift.json", "drift-report.json"):
        b = _read_bytes(run_dir / name)
        if b is not None:
            return b
    return None


# --------------------------------------------------------------------------------------------------
# reports + exports — read pre-rendered, else render from a raw findings source with the renderers
# --------------------------------------------------------------------------------------------------


@dataclass
class _Reports:
    md: dict[str, bytes] = field(default_factory=dict)          # arc basename -> bytes
    report_json: Optional[bytes] = None
    report_sarif: Optional[bytes] = None
    export_doc: Optional[dict] = None                           # parsed report.json (report.export shape)
    notes: list[str] = field(default_factory=list)


def _gather_reports(run_dir: Path, meta: ReportMeta) -> _Reports:
    """Collect the three markdown docs + the JSON/SARIF exports. Pre-rendered files under the run dir
    win; any that are absent are rendered from a ``findings.json`` raw source via the SAME
    ``report.generate`` / ``report.export`` renderers (so a doc and an export grade a finding
    identically). Deterministic given ``meta`` (``generated_at`` is the only optional non-determinism)."""
    r = _Reports()

    # pre-rendered markdown
    for name in _REPORT_MD:
        p = _find_in(run_dir, name)
        if p is not None:
            b = _read_bytes(p)
            if b is not None:
                r.md[name] = b
    # pre-rendered exports
    pj = _find_in(run_dir, "report.json")
    if pj is not None:
        r.report_json = _read_bytes(pj)
    ps = _find_in(run_dir, "report.sarif")
    if ps is not None:
        r.report_sarif = _read_bytes(ps)

    # render whatever is missing, from a raw findings source, using the report renderers
    need_md = [n for n in _REPORT_MD if n not in r.md]
    if need_md or r.report_json is None or r.report_sarif is None:
        findings = _load_findings_source(run_dir)
        if findings is not None:
            try:
                docs = generate_reports(findings, meta)
                _name = {"executive": "executive.md", "technical": "technical.md",
                         "remediation-roadmap": "remediation-roadmap.md"}
                for key, fname in _name.items():
                    if fname in need_md and key in docs:
                        r.md[fname] = docs[key].encode("utf-8")
                if r.report_json is None:
                    r.report_json = export_json(findings, meta).encode("utf-8")
                if r.report_sarif is None:
                    r.report_sarif = export_sarif(findings, meta).encode("utf-8")
                r.notes.append(f"rendered reports/exports from findings.json ({len(findings)} finding(s)) "
                               "via report.generate/report.export")
            except Exception as e:  # noqa: BLE001 — a malformed findings source never aborts the dossier
                r.notes.append(f"could not render from findings.json: {e}")

    if r.report_json is not None:
        try:
            doc = json.loads(r.report_json.decode("utf-8"))
            if isinstance(doc, dict):
                r.export_doc = doc
        except ValueError:
            pass
    return r


# --------------------------------------------------------------------------------------------------
# the offline-verifiable proof bundle (lazy — reuses vigil_integration.proof.bundle.export_bundle)
# --------------------------------------------------------------------------------------------------


def _build_proof_bundle(run_dir: Path, engagement_slug: str, base_dir: Optional[str],
                        vault: Any) -> tuple[dict[str, bytes], dict]:
    """Export the client-verifiable proof bundle into a temp dir and read its tree into memory (arcname
    -> bytes, all confined under ``proof-bundle/``). Returns ``(entries, summary)``; ``summary`` carries
    ``ok`` / ``verify_cmd`` / ``trust_root_fingerprint`` / a ``note`` when there are no FACTs to bundle.
    Lazy import — FATAL-2: the heavy integration import stays off the module-load path."""
    from vigil_integration.proof.bundle import export_bundle  # lazy — touches framework + integration

    entries: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="vigil-dossier-proof-") as td:
        out = Path(td) / "proof-bundle"
        try:
            res = export_bundle(run_dir=str(run_dir), out_dir=str(out),
                                engagement_slug=engagement_slug, base_dir=base_dir, vault=vault)
        except Exception as e:  # noqa: BLE001 — a bundle failure never aborts the dossier
            return ({}, {"ok": False, "note": f"proof bundle skipped ({e})"})
        if not res.get("ok"):
            return ({}, {"ok": False, "note": res.get("error", "no proof bundle")})
        # read the bundle tree into memory, confining + never following symlinks
        for root, dirs, files in os.walk(out, followlinks=False):
            # prune symlinked dirs
            dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
            for fn in files:
                fp = Path(root, fn)
                if fp.is_symlink():
                    continue
                rel = fp.relative_to(out).as_posix()
                arc = f"proof-bundle/{rel}"
                if not _is_safe_rel(arc):
                    continue
                b = _read_bytes(fp)
                if b is not None:
                    entries[arc] = b
        return (entries, {"ok": True, "verify_cmd": res.get("verify_cmd", ""),
                          "certificates": res.get("certificates", 0),
                          "trust_root_fingerprint": res.get("trust_root_fingerprint", "")})


# --------------------------------------------------------------------------------------------------
# index.html — a readable, honest, self-contained dossier (inline CSS, no external assets)
# --------------------------------------------------------------------------------------------------


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def _facts_from_reverifiable(facts: list[dict]) -> list[dict]:
    """Normalise the reverifiable FACT set for display: bug_class, ref, the confirming oracle, channel."""
    out = []
    for f in facts:
        out.append({
            "ref": f.get("check_id") or f.get("finding_slug") or f.get("bug_class") or "finding",
            "bug_class": f.get("bug_class") or "",
            "confirmed_by": f.get("confirmed_by") or "",
            "channel": f.get("channel") or "",
        })
    return out


_INDEX_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       color: #1a1a1a; background: #fafafa; }
main { max-width: 900px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 .5rem; border-bottom: 1px solid #ddd; padding-bottom: .3rem; }
h3 { font-size: 1.02rem; margin: 1.2rem 0 .3rem; }
.sub { color: #666; margin: 0 0 1.25rem; }
.banner { border-radius: 8px; padding: .8rem 1rem; margin: 1rem 0; font-weight: 600; }
.banner.fact { background: #e7f6ec; border: 1px solid #67c98f; color: #145a32; }
.banner.lead { background: #fbeecf; border: 1px solid #e0b354; color: #6b4e0a; }
.banner.none { background: #f0f0f0; border: 1px solid #bbb; color: #333; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #e2e2e2; vertical-align: top; }
th { background: #f2f2f2; font-size: .82rem; text-transform: uppercase; letter-spacing: .03em; color: #555; }
code, pre { font-family: ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
pre { background: #1e1e1e; color: #eee; padding: .9rem 1rem; border-radius: 8px; overflow-x: auto;
      font-size: .86rem; }
code.inl { background: rgba(127,127,127,.16); padding: .05rem .35rem; border-radius: 4px; font-size: .88em; }
.badge { display: inline-block; font-size: .72rem; font-weight: 700; padding: .1rem .45rem; border-radius: 4px;
         text-transform: uppercase; letter-spacing: .03em; }
.badge.fact { background: #145a32; color: #fff; }
.badge.lead { background: #6b4e0a; color: #fff; }
.files a, .files span { display: inline-block; margin: .1rem .4rem .1rem 0; }
.muted { color: #777; font-size: .9rem; }
.note { border-left: 3px solid #bbb; padding: .4rem .8rem; margin: .6rem 0; background: rgba(127,127,127,.08); }
@media (prefers-color-scheme: dark) {
  body { color: #e6e6e6; background: #16181c; }
  h2 { border-bottom-color: #333; }
  th { background: #23262d; color: #aaa; }
  th, td { border-bottom-color: #2b2f36; }
  .sub, .muted { color: #9aa0a8; }
  .banner.fact { background: #123123; border-color: #2f7d52; color: #a7e8c2; }
  .banner.lead { background: #3a2f12; border-color: #7d6320; color: #f0d79a; }
  .banner.none { background: #24262b; border-color: #444; color: #ccc; }
  .note { background: rgba(255,255,255,.05); border-left-color: #555; }
}
""".strip()


def _render_index(*, engagement_slug: str, facts: list[dict], reports: _Reports,
                  proof: dict, spine_names: list[str], has_drift: bool, has_log: bool,
                  signed: bool, fingerprint: str, generated_at: Optional[str],
                  included: list[str]) -> str:
    """Build the self-contained index.html. Reflects EXACTLY what the run produced: FACTs from the
    reverifiable set, findings/remediation from the report export when present, and the REAL offline
    verify command for the embedded proof bundle. Never fabricates a fact, never overclaims a lead."""
    fact_rows = _facts_from_reverifiable(facts)
    n_facts = len(fact_rows)

    # lead count, best-effort, from the report export summary (honest "unknown" otherwise)
    lead_note = ""
    n_leads: Optional[int] = None
    if reports.export_doc is not None:
        summ = reports.export_doc.get("summary")
        if isinstance(summ, dict) and isinstance(summ.get("leads"), int):
            n_leads = summ["leads"]
    if n_leads is None:
        lead_note = " (leads not enumerated — no structured report.json in this run)"

    L: list[str] = []
    L.append("<main>")
    L.append(f"<h1>VIGIL engagement dossier — <code class='inl'>{_e(engagement_slug)}</code></h1>")
    sub = "A self-contained, tamper-evident record of one engagement."
    if generated_at:
        sub += f" Generated {_e(generated_at)}."
    L.append(f"<p class='sub'>{sub}</p>")

    # honest headline banner
    if n_facts > 0:
        lead_txt = f"{n_leads} lead(s)" if n_leads is not None else "leads (see reports)"
        L.append(f"<div class='banner fact'>{n_facts} oracle-confirmed FACT(s) — each re-verifiable "
                 f"OFFLINE from the embedded proof bundle. Plus {_e(lead_txt)}{_e(lead_note)}.</div>")
    else:
        if n_leads and n_leads > 0:
            L.append(f"<div class='banner lead'>This run produced NO oracle-confirmed FACT — {n_leads} "
                     f"LEAD(s) to verify. A lead is a lead, not a proven attacker capability. No offline "
                     f"proof bundle is included.</div>")
        else:
            L.append("<div class='banner none'>This run produced no oracle-confirmed FACT and no enumerated "
                     "lead. Nothing here asserts an attacker capability.</div>")

    # what was found — the FACT set
    L.append("<h2>What was found (oracle-confirmed facts)</h2>")
    if fact_rows:
        L.append("<table><thead><tr><th>Finding</th><th>Bug class</th><th>Confirmed by oracle</th>"
                 "<th>Channel</th><th>Grounding</th></tr></thead><tbody>")
        for fr in fact_rows:
            L.append("<tr>"
                     f"<td><code class='inl'>{_e(fr['ref'])}</code></td>"
                     f"<td>{_e(fr['bug_class'])}</td>"
                     f"<td>{_e(fr['confirmed_by'])}</td>"
                     f"<td>{_e(fr['channel'])}</td>"
                     "<td><span class='badge fact'>fact</span></td>"
                     "</tr>")
        L.append("</tbody></table>")
        L.append("<p class='muted'>Each fact above was minted by a deterministic oracle re-firing over "
                 "executor-captured (non-LLM) bytes, then signed. Reproduce them yourself below.</p>")
    else:
        L.append("<p class='muted'>No finding in this run was confirmed by a deterministic oracle. "
                 "See the reports for unproven leads.</p>")

    # findings + remediation from the structured export (if present)
    if reports.export_doc is not None and isinstance(reports.export_doc.get("findings"), list):
        L.append("<h2>How to patch (per finding)</h2>")
        L.append("<table><thead><tr><th>Finding</th><th>Severity</th><th>Grounding</th>"
                 "<th>Remediation (class-level)</th></tr></thead><tbody>")
        for f in reports.export_doc["findings"][:500]:
            if not isinstance(f, dict):
                continue
            g = str(f.get("grounding", "")).lower()
            badge = "fact" if g == "fact" else "lead"
            L.append("<tr>"
                     f"<td><b>{_e(f.get('title', ''))}</b><br><span class='muted'>"
                     f"<code class='inl'>{_e(f.get('slug', ''))}</code> · {_e(f.get('bug_class', ''))}</span></td>"
                     f"<td>{_e(f.get('severity', ''))}</td>"
                     f"<td><span class='badge {badge}'>{_e(g or 'lead')}</span></td>"
                     f"<td>{_e(f.get('remediation', ''))}</td>"
                     "</tr>")
        L.append("</tbody></table>")
        L.append("<p class='muted'>Full remediation ordering (impact ÷ effort) is in "
                 "<code class='inl'>reports/remediation-roadmap.md</code>; per-finding proof/verification "
                 "blocks are in <code class='inl'>reports/technical.md</code>.</p>")
    elif "reports/remediation-roadmap.md" in included or "reports/technical.md" in included:
        L.append("<h2>How to patch</h2>")
        L.append("<p>Remediation guidance is in <code class='inl'>reports/remediation-roadmap.md</code>; "
                 "per-finding verification is in <code class='inl'>reports/technical.md</code>.</p>")

    # how to verify — the REAL offline command
    L.append("<h2>How to verify each (offline, zero-trust)</h2>")
    if proof.get("ok"):
        cmd = proof.get("verify_cmd") or ""
        fp = proof.get("trust_root_fingerprint") or fingerprint
        L.append("<p>The embedded proof bundle re-verifies with the open-source deterministic verifier — "
                 "no target, no network, none of VIGIL's offense engine. From the unzipped dossier:</p>")
        L.append(f"<pre>cd proof-bundle\n{_e(cmd)}</pre>")
        L.append("<p class='muted'>Exit 0 iff every certificate is authentic (m-of-n signature), bound, "
                 "REPRODUCED (the same deterministic oracle re-fires), artifact-hashed, and chained. A single "
                 "flipped byte anywhere fails it closed.</p>")
        if fp:
            L.append(f"<p class='muted'>Pin the governance trust root out-of-band: the fingerprint is "
                     f"<code class='inl'>{_e(fp)}</code> (also in "
                     f"<code class='inl'>proof-bundle/TRUST-ROOT-FINGERPRINT.txt</code>). Obtain it from the "
                     f"operator through an INDEPENDENT channel before trusting authenticity.</p>")
    else:
        L.append(f"<p class='note'>No offline proof bundle is included: {_e(proof.get('note', 'no facts'))}. "
                 "That is the honest outcome for a run with no oracle-confirmed FACT — there is nothing to "
                 "re-prove. The reports and (scrubbed) logs are still here.</p>")

    # dossier integrity
    L.append("<h2>Is this dossier intact?</h2>")
    L.append("<p><code class='inl'>MANIFEST.json</code> lists every content entry with its sha256. "
             "Recompute a file's hash and compare — any mismatch means the dossier was altered.</p>")
    if signed:
        L.append(f"<p><code class='inl'>MANIFEST.sig.json</code> carries an m-of-n governance Ed25519 "
                 f"signature over <code class='inl'>MANIFEST.json</code>; the trust-root fingerprint is "
                 f"<code class='inl'>{_e(fingerprint)}</code> (also in "
                 f"<code class='inl'>TRUST-ROOT-FINGERPRINT.txt</code>). Verify that signature to confirm "
                 f"this dossier was produced under the operator's governance key.</p>")
    else:
        L.append("<p class='note'>This dossier is <b>integrity-checkable but NOT authenticity-signed</b>: no "
                 "governance signer was resolvable at build time, so there is a MANIFEST of hashes but no "
                 "signature over it. The hashes prove the entries were not altered relative to this MANIFEST; "
                 "they do NOT prove who produced it.</p>")

    # contents
    L.append("<h2>What is in this archive</h2>")
    L.append("<div class='files'>")
    for name in included:
        L.append(f"<span><code class='inl'>{_e(name)}</code></span>")
    L.append("</div>")
    extras = []
    if has_log:
        extras.append("a secret-scrubbed engagement log")
    if spine_names:
        extras.append("the hash-linked, governance-signed spine chain")
    if has_drift:
        extras.append("a drift record")
    if extras:
        L.append(f"<p class='muted'>Also included: {_e(', '.join(extras))}.</p>")
    L.append("</main>")

    body = "\n".join(L)
    return (f"<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>VIGIL dossier — {_e(engagement_slug)}</title>"
            f"<style>{_INDEX_CSS}</style></head><body>\n{body}\n</body></html>\n")


def _render_readme(*, engagement_slug: str, n_facts: int, proof: dict, signed: bool,
                   fingerprint: str, included: list[str], notes: list[str]) -> str:
    L = [f"# VIGIL engagement dossier — {engagement_slug}", "",
         "One self-contained, tamper-evident record of a single engagement. Open `index.html` for the "
         "readable view.", "", "## Integrity", "",
         "`MANIFEST.json` lists every content entry with its sha256. Recompute any entry's hash and compare."]
    if signed:
        L += ["", f"`MANIFEST.sig.json` is an m-of-n governance Ed25519 signature over `MANIFEST.json`. "
                  f"The trust-root fingerprint (`TRUST-ROOT-FINGERPRINT.txt`) is `{fingerprint}` — pin it "
                  f"OUT-OF-BAND to anchor authenticity."]
    else:
        L += ["", "This dossier is integrity-checkable (hashes) but NOT authenticity-signed: no governance "
                  "signer was resolvable at build time."]
    L += ["", "## Offline verification", ""]
    if proof.get("ok"):
        L += [f"The embedded proof bundle re-verifies with zero trust in VIGIL ({n_facts} FACT(s)). From the "
              "unzipped dossier:", "", "```", "cd proof-bundle", proof.get("verify_cmd", ""), "```", "",
              "Exit 0 iff every certificate is authentic, bound, reproduced, artifact-hashed and chained."]
    else:
        L += [f"No proof bundle is included: {proof.get('note', 'no oracle-confirmed FACT')}. A run with only "
              "leads has nothing to re-prove — this is the honest outcome, not an omission."]
    L += ["", "## Contents", ""]
    L += [f"- `{n}`" for n in included]
    if notes:
        L += ["", "## Build notes", ""]
        L += [f"- {n}" for n in notes]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------------------
# manifest + governance signature (m-of-n over the manifest bytes)
# --------------------------------------------------------------------------------------------------


def _build_manifest(entries: dict[str, bytes], engagement_slug: str) -> bytes:
    """The tamper-evidence manifest: every content entry + its sha256, sorted by path. Pure function of
    the entry CONTENT — no wallclock — so two builds over the same inputs produce identical bytes."""
    manifest = {
        "dossier": "vigil-run-dossier/v1",
        "engagement_slug": engagement_slug,
        "entry_count": len(entries),
        "entries": [{"path": name, "sha256": _sha256(entries[name])}
                    for name in sorted(entries)],
    }
    return json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")


def _sign_manifest(manifest_bytes: bytes, engagement_slug: str, base_dir: Optional[str],
                   run_dir: Path, vault: Any) -> tuple[Optional[bytes], Optional[str], list[str]]:
    """Sign the manifest bytes with the run's STABLE governance authority (same key ``export_bundle``
    uses, given the same ``base_dir``), returning ``(sig_bytes, fingerprint, notes)``. A self-describing
    m-of-n Ed25519 signature over the exact manifest bytes: a verifier recomputes sha256(MANIFEST.json)
    and checks ``verify_one`` for each signer against the embedded PUBLIC trust root. Returns
    ``(None, None, notes)`` when no signer is resolvable (the dossier is then honestly UNSIGNED)."""
    notes: list[str] = []
    try:
        from vigil_core import sign

        from ..evidence.certify import trust_root_fingerprint
        from vigil_integration.live.wiring import provision_authority
    except Exception as e:  # noqa: BLE001
        notes.append(f"unsigned: governance signer not importable ({e})")
        return (None, None, notes)

    try:
        prov = provision_authority(slug=engagement_slug, scope=["127.0.0.1"],
                                   base_dir=(base_dir or str(run_dir)), vault=vault)
    except Exception as e:  # noqa: BLE001
        notes.append(f"unsigned: could not provision a governance authority ({e})")
        return (None, None, notes)

    try:
        fingerprint = trust_root_fingerprint(prov.trust_root)
        sigs = [{"key_id": kid, "sig_b64": sign(priv, manifest_bytes)} for kid, priv in prov.signers]
        sig_doc = {
            "algo": "ed25519",
            "signs": "MANIFEST.json (raw bytes)",
            "engagement_slug": engagement_slug,
            "manifest_sha256": _sha256(manifest_bytes),
            "threshold": int(getattr(prov.trust_root, "threshold", len(sigs)) or len(sigs)),
            "trust_root": prov.trust_root.model_dump(mode="json"),
            "trust_root_fingerprint": fingerprint,
            "signatures": sigs,
        }
        return (json.dumps(sig_doc, indent=2, sort_keys=True).encode("utf-8"), fingerprint, notes)
    except Exception as e:  # noqa: BLE001
        notes.append(f"unsigned: signing failed ({e})")
        return (None, None, notes)


# --------------------------------------------------------------------------------------------------
# the public API
# --------------------------------------------------------------------------------------------------


def _write_zip(out_zip: Path, entries: dict[str, bytes]) -> None:
    """Write a DETERMINISTIC zip: entries in sorted arcname order, each with a fixed epoch timestamp and
    stored external attrs. The archive bytes are stable given stable content (the MANIFEST already
    guarantees determinism at the content layer regardless of framing)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(entries):
            zi = zipfile.ZipInfo(filename=name, date_time=_ZIP_EPOCH)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, entries[name])
    data = buf.getvalue()
    fd = os.open(str(out_zip), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def build_dossier(
    *,
    run_dir: str | os.PathLike,
    out_zip: str | os.PathLike,
    engagement_slug: str = "engagement",
    base_dir: Optional[str] = None,
    vault: Any = None,
    generated_at: Optional[str] = None,
) -> dict:
    """Assemble EVERYTHING a run produced into one self-contained, tamper-evident ``.zip`` at ``out_zip``.

    Gathers (whatever is present): the three human reports + the JSON/SARIF exports (pre-rendered under
    ``run_dir`` or rendered from a ``findings.json`` via the report renderers); the offline-verifiable
    proof bundle (``vigil_integration.proof.bundle.export_bundle`` — skipped with an honest note when a
    run has no oracle-confirmed FACT); the secret-scrubbed engagement log; any governance-signed spine
    chain; any drift record; a readable ``index.html`` + ``README.md``; a ``MANIFEST.json`` of sha256s;
    and (if a governance signer is resolvable) a ``MANIFEST.sig.json`` + ``TRUST-ROOT-FINGERPRINT.txt``.

    Deterministic: sorted entries, no wallclock in the hashed content (``generated_at`` is the only,
    OPTIONAL, injected stamp and it defaults to none). Path-safe: every entry is confined; symlinks are
    never followed. Returns a summary ``{ok, dossier, entries, facts, leads, signed, verify_cmd,
    trust_root_fingerprint, manifest_sha256, notes}``."""
    run = Path(run_dir)
    if not run.is_dir():
        return {"ok": False, "error": f"run dir not found: {run}"}

    meta = ReportMeta(target=engagement_slug, generated_at=generated_at)
    notes: list[str] = []

    # 1) reports + exports (pre-rendered, else rendered from findings.json via the renderers)
    reports = _gather_reports(run, meta)
    notes += reports.notes

    # 2) the oracle-confirmed FACT set (for the index + the lead/fact honesty)
    facts = _read_reverifiable(run)

    # content entries: arcname -> bytes (everything EXCEPT the manifest/signature envelope)
    entries: dict[str, bytes] = {}
    for name, b in sorted(reports.md.items()):
        entries[f"reports/{name}"] = b
    if reports.report_json is not None:
        entries["reports/report.json"] = reports.report_json
    if reports.report_sarif is not None:
        entries["reports/report.sarif"] = reports.report_sarif

    # 3) the offline-verifiable proof bundle
    proof_entries, proof = _build_proof_bundle(run, engagement_slug, base_dir, vault)
    entries.update(proof_entries)
    if proof.get("note"):
        notes.append(proof["note"])

    # 4) scrubbed engagement log
    log_text, dropped = _scrub_log(run)
    has_log = log_text is not None
    if has_log:
        entries["logs/engagement-log.jsonl"] = log_text.encode("utf-8")
        if dropped:
            notes.append(f"engagement log: dropped {dropped} unparseable line(s) (not shipped in the clear)")

    # 5) spine chain (verbatim, already redacted)
    spine = _find_spine(run, base_dir)
    for name, b in sorted(spine.items()):
        arc = f"spine/{name}"
        if _is_safe_rel(arc):
            entries[arc] = b

    # 6) drift record (verbatim)
    drift = _find_drift(run)
    has_drift = drift is not None
    if has_drift:
        entries["drift/drift.json"] = drift

    if not entries:
        notes.append("no report/proof/log/spine/drift artifact was found under the run dir")

    # 7) readable index + README (built from what we actually gathered — needs the signed flag, so we
    #    provision the signature FIRST over a provisional manifest, then finalise). We compute the
    #    manifest signature over the FINAL content entries, so add index/README, then manifest, then sig.
    included_preview = sorted(entries)  # the content entries so far (index/README added below)

    # We must know `signed` + `fingerprint` for the index/README text, but the manifest signs the FINAL
    # entries (which include index/README). Resolve the signer once up-front (idempotent given base_dir),
    # render index/README with the resulting signed/fingerprint, then build+sign the final manifest.
    probe_sig, probe_fp, sign_notes = _sign_manifest(b"probe", engagement_slug, base_dir, run, vault)
    signed = probe_sig is not None
    fingerprint = probe_fp or ""

    index_html = _render_index(
        engagement_slug=engagement_slug, facts=facts, reports=reports, proof=proof,
        spine_names=sorted(spine), has_drift=has_drift, has_log=has_log,
        signed=signed, fingerprint=fingerprint, generated_at=generated_at,
        included=included_preview)
    entries["index.html"] = index_html.encode("utf-8")

    readme = _render_readme(
        engagement_slug=engagement_slug, n_facts=len(facts), proof=proof, signed=signed,
        fingerprint=fingerprint, included=sorted(entries), notes=notes)
    entries["README.md"] = readme.encode("utf-8")

    # 8) manifest over the FINAL content entries, then the governance signature over the manifest bytes
    manifest_bytes = _build_manifest(entries, engagement_slug)
    manifest_sha = _sha256(manifest_bytes)

    all_entries = dict(entries)
    all_entries["MANIFEST.json"] = manifest_bytes
    sig_bytes, sig_fp, real_sign_notes = _sign_manifest(manifest_bytes, engagement_slug, base_dir, run, vault)
    if sig_bytes is not None:
        all_entries["MANIFEST.sig.json"] = sig_bytes
        all_entries["TRUST-ROOT-FINGERPRINT.txt"] = (sig_fp + "\n").encode("utf-8")
        signed = True
        fingerprint = sig_fp or fingerprint
    else:
        signed = False
        notes += real_sign_notes or sign_notes

    # 9) write the deterministic zip
    out = Path(out_zip)
    out.parent.mkdir(parents=True, exist_ok=True)
    _write_zip(out, all_entries)

    lead_count: Optional[int] = None
    if reports.export_doc is not None:
        summ = reports.export_doc.get("summary")
        if isinstance(summ, dict) and isinstance(summ.get("leads"), int):
            lead_count = summ["leads"]

    return {
        "ok": True,
        "dossier": str(out),
        "entries": len(all_entries),
        "facts": len(facts),
        "leads": lead_count,
        "signed": signed,
        "verify_cmd": (proof.get("verify_cmd") if proof.get("ok") else None),
        "trust_root_fingerprint": (fingerprint or None),
        "manifest_sha256": manifest_sha,
        "proof_bundle": bool(proof.get("ok")),
        "notes": notes,
    }
