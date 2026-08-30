"""The Range Control cockpit UI + routes (served on the control plane, :19011).

Three views on one page: a guided end-to-end tour (each step streams a real VIGIL verb), the capability
catalogue (capability × planted vuln × command × expected oracle result), and a live findings view (parsed
from the latest scan report). Owner-gold themed — this is the operator/control plane.
"""

from __future__ import annotations

import json
import os

from ..meridian import theme
from ..meridian.config import Config
from ..meridian.router import Ctx, Response, Router, StreamResponse
from . import compliance, runner
from .catalog import CAPABILITIES, capability_vulns


def _tour_rows() -> str:
    rows = ""
    for spec in runner.SPECS.values():
        if spec.group != "tour":
            continue
        rows += (
            f'<div class="run-row" data-run="{spec.id}">'
            f'<div><div class="run-label">{theme.esc(spec.label)}</div>'
            f'<div class="run-exp">{theme.esc(spec.expect)}</div></div>'
            f'<button class="btn owner sm run-btn" data-run="{spec.id}">Run ▸</button></div>'
        )
    return rows


def _catalog_cards() -> str:
    cards = ""
    for cap in CAPABILITIES:
        vulns = capability_vulns(cap)
        pills = "".join(
            f'<span class="sev sev-{v.severity if v.severity in ("critical","high","medium","low") else "info"}">'
            f'{theme.esc(v.vuln_class)}</span> '
            for v in vulns
        )
        run_btn = (f'<button class="btn owner sm run-btn" data-run="{cap.run_spec}">Run ▸</button>'
                   if cap.run_spec else '<span class="pill sm">catalog</span>')
        cards += (
            '<div class="card owner"><div class="card-h">'
            f'<span class="label">Capability</span><h3>{theme.esc(cap.title)}</h3></div>'
            f'<p style="color:var(--text-1)">{theme.esc(cap.blurb)}</p>'
            f'<div style="margin:8px 0">{pills}</div>'
            f'<pre class="mono" style="white-space:pre-wrap;background:var(--bg-2);padding:10px;border-radius:8px;'
            f'font-size:12px">{theme.esc(cap.command)}</pre>'
            f'<div style="display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:10px">'
            f'<span class="shield">✓ expect: {theme.esc(cap.expected)}</span>{run_btn}</div></div>'
        )
    return cards


_PAGE_JS = """
const out = document.getElementById('console');
function log(t){ out.textContent += t; out.scrollTop = out.scrollHeight; }
async function runOne(id){
  const btns = document.querySelectorAll('.run-btn'); btns.forEach(b=>b.disabled=true);
  log('\\n\\n==== run: '+id+' ====\\n');
  try {
    const resp = await fetch('/run/'+encodeURIComponent(id));
    const reader = resp.body.getReader(); const dec = new TextDecoder();
    for(;;){ const {done, value} = await reader.read(); if(done) break; log(dec.decode(value, {stream:true})); }
  } catch(e){ log('\\n[range-control] stream error: '+e+'\\n'); }
  btns.forEach(b=>b.disabled=false);
  refreshAll();
}
async function runAll(){
  const ids = Array.from(document.querySelectorAll('.run-row')).map(r=>r.dataset.run);
  for(const id of ids){ await runOne(id); }
}
const sevClass = s => (['critical','high','medium','low'].includes((s||'info').toLowerCase())?(s||'info').toLowerCase():'info');
async function refreshFindings(){
  try{
    const r = await fetch('/findings.json'); const d = await r.json();
    const box = document.getElementById('tab-findings');
    if(!d.findings || !d.findings.length){ box.innerHTML = '<p style="color:var(--text-2)">No findings captured yet — run step 2.</p>'; return; }
    box.innerHTML = d.findings.map(f=>{
      const fact = (f.grounding==='fact');
      return '<div class="finding"><span class="sev sev-'+sevClass(f.severity)+'">'+(f.bug_class||f.class||'?')+'</span> '
        + (fact?'<span class="shield">✓ FACT</span>':'<span class="pill sm">'+(f.grounding||'lead')+'</span>')
        + ' <span style="color:var(--text-1)">'+(f.title||'')+'</span></div>';
    }).join('');
  }catch(e){ /* ignore */ }
}
async function refreshCompliance(){
  try{
    const r = await fetch('/compliance.json'); const d = await r.json();
    const box = document.getElementById('tab-compliance');
    if(!d.rows || !d.rows.length){ box.innerHTML = '<p style="color:var(--text-2)">Run step 2 to map confirmed findings to controls.</p>'; return; }
    const fw = d.frameworks;
    box.innerHTML = '<div class="scroll-x"><table><thead><tr><th>Finding</th>'+fw.map(f=>'<th>'+f+'</th>').join('')
      +'</tr></thead><tbody>'+d.rows.map(row=>'<tr><td><span class="sev sev-'+sevClass(row.severity)+'">'+row.bug_class+'</span></td>'
      +fw.map(f=>'<td class="mono">'+(row.controls[f]||'—')+'</td>').join('')+'</tr>').join('')+'</tbody></table></div>';
  }catch(e){ /* ignore */ }
}
async function refreshImpact(){
  try{
    const r = await fetch('/impact.json'); const d = await r.json();
    const box = document.getElementById('tab-impact');
    if(!d.chains || !d.chains.length){ box.innerHTML = '<p style="color:var(--text-2)">Run step 2 to derive the business impact of what was confirmed.</p>'; return; }
    box.innerHTML = d.chains.map(c=>'<div class="finding"><span class="sev sev-'+sevClass(c.severity)+'">'+c.title+'</span>'
      +'<div style="color:var(--text-1);margin-top:4px">'+c.impact+'</div>'
      +'<div style="color:var(--text-2);font-size:12px;margin-top:2px">chain: '+c.chain+'</div></div>').join('');
  }catch(e){ /* ignore */ }
}
async function refreshEvidence(){
  try{
    const r = await fetch('/evidence.json'); const d = await r.json();
    const box = document.getElementById('tab-evidence');
    if(!d.present){ box.innerHTML = '<p style="color:var(--text-2)">Run the “signed evidence certificate” step to produce an auditor-verifiable bundle.</p>'; return; }
    box.innerHTML = '<div class="finding"><span class="shield">✓ SIGNED BUNDLE</span> '
      +'<span style="color:var(--text-1)">'+d.certificates+' certificate(s), '+d.chain+'-entry chain</span></div>'
      +'<div class="mono" style="font-size:12px;color:var(--text-2);margin-top:6px;word-break:break-all">trust-root: '+d.trust_root_fingerprint+'</div>'
      +'<p style="color:var(--text-1);margin-top:8px">An auditor re-verifies this bundle offline with '
      +'<span class="mono">framework.v2 evidence verify</span> — no trust in the tool that produced it.</p>';
  }catch(e){ /* ignore */ }
}
function refreshAll(){ refreshFindings(); refreshCompliance(); refreshImpact(); refreshEvidence(); }
function showTab(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.style.display='none');
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  const p=document.getElementById('tab-'+name); if(p) p.style.display='block';
  const b=document.querySelector('.tab-btn[data-tab="'+name+'"]'); if(b) b.classList.add('active');
}
document.addEventListener('click', e=>{
  const b = e.target.closest('.run-btn'); if(b){ runOne(b.dataset.run); }
  if(e.target.id==='run-all'){ runAll(); }
  const t = e.target.closest('.tab-btn'); if(t){ showTab(t.dataset.tab); }
});
showTab('findings'); refreshAll();
"""


def _cockpit(ctx: Ctx) -> Response:
    body = (
        '<main class="wrap">'
        '<div class="screen-head"><span class="label">Operator cockpit · drives VIGIL against MERIDIAN</span>'
        '<h1>Range Control</h1>'
        '<p class="sub">Run the real VIGIL verbs against the loopback range and watch the results. '
        'Nothing here bypasses a gate — it invokes the ordinary charter-scoped CLI.</p></div>'
        '<div class="grid cols-2">'
        # left: guided tour + console
        '<div><div class="card owner"><div class="card-h" style="display:flex;justify-content:space-between;'
        'align-items:center"><div><span class="label">Guided tour</span><h3>End-to-end, in order</h3></div>'
        '<button class="btn owner" id="run-all">Run all ▸</button></div>'
        f'{_tour_rows()}</div>'
        '<div class="card" style="margin-top:var(--sp-4)"><div class="card-h"><span class="label">Console</span>'
        '<h3>Live output</h3></div><pre class="console" id="console">Ready. Click a step, or “Run all”.\n'
        'The target portal is at http://127.0.0.1:19010/ .</pre></div>'
        # results: tabbed (findings / compliance / impact / evidence)
        '<div class="card" style="margin-top:var(--sp-4)"><div class="card-h"><span class="label">Assessment results</span>'
        '<h3>What VIGIL produced</h3></div>'
        '<div class="tabs">'
        '<button class="tab-btn active" data-tab="findings">Findings</button>'
        '<button class="tab-btn" data-tab="compliance">Compliance</button>'
        '<button class="tab-btn" data-tab="impact">Business impact</button>'
        '<button class="tab-btn" data-tab="evidence">Evidence</button></div>'
        '<div class="tab-panel" id="tab-findings"></div>'
        '<div class="tab-panel" id="tab-compliance" style="display:none"></div>'
        '<div class="tab-panel" id="tab-impact" style="display:none"></div>'
        '<div class="tab-panel" id="tab-evidence" style="display:none"></div>'
        '</div></div>'
        # right: capability catalogue
        f'<div><div class="card-h"><span class="label">Capability catalogue</span>'
        '<h3 style="margin-bottom:12px">Every VIGIL capability × the planted weakness</h3></div>'
        f'<div class="grid" style="gap:var(--sp-3)">{_catalog_cards()}</div></div>'
        '</div></main>'
        '<style>.run-row{display:flex;justify-content:space-between;align-items:center;gap:12px;'
        'padding:10px 0;border-top:1px solid var(--border)}.run-label{font-weight:600}'
        '.run-exp{font-size:12px;color:var(--text-2)}.finding{padding:8px 0;border-bottom:1px solid var(--border);'
        'font-size:13px}.tabs{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap}'
        '.tab-btn{background:var(--bg-2);border:1px solid var(--border-strong);color:var(--text-1);'
        'padding:6px 12px;border-radius:var(--r-pill);font-size:13px;font-weight:600;cursor:pointer}'
        '.tab-btn.active{background:var(--owner);border-color:var(--owner);color:#1a1205}</style>'
        f'<script>{_PAGE_JS}</script>'
    )
    return Response.html(theme.page("Range Control", body, plane="control", mode=ctx.mode))


def build_control_router(config: Config) -> Router:
    r = Router()

    def _run(ctx: Ctx) -> StreamResponse:
        spec_id = ctx.params.get("id", "")
        return StreamResponse(runner.run_stream(spec_id, config), content_type="text/plain; charset=utf-8")

    def _reverify_doc() -> dict:
        path = os.path.join(config.base_dir, "rc", "records.reverify.json")
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _confirmed() -> list[dict]:
        """The active findings that carry a re-executable oracle_context (the confirmed FACTs)."""
        return [f for f in _reverify_doc().get("active_findings", []) if f.get("oracle_context")]

    def _findings(ctx: Ctx) -> Response:
        doc = _reverify_doc()
        if not doc:
            return Response.json({"findings": []})
        slim = []
        # active findings: label FACT only when the finding carries a re-executable oracle_context (the
        # proof `framework.v2 verify` re-runs) — not merely because it sits in the active array.
        for f in doc.get("active_findings", []):
            where = f.get("param") or f.get("endpoint") or f.get("insertion_point") or ""
            proven = bool(f.get("oracle_context"))
            slim.append({"bug_class": f.get("bug_class") or "finding",
                         "grounding": "fact" if proven else "lead",
                         "severity": f.get("severity", "high"),
                         "title": (f"confirmed at {where}" if where else "confirmed by oracle")
                                  if proven else (f"active at {where}" if where else "active finding")})
        # passive findings are leads (missing headers, banners) — shown but not as FACTs
        for f in doc.get("passive_findings", []):
            slim.append({"bug_class": f.get("bug_class") or "passive",
                         "grounding": f.get("grounding") or "lead",
                         "severity": f.get("severity", "info"),
                         "title": f.get("title") or f.get("evidence") or ""})
        return Response.json({"findings": slim})

    def _compliance(ctx: Ctx) -> Response:
        rows = []
        for f in _confirmed():
            bc = f.get("bug_class") or "finding"
            where = f.get("param") or f.get("endpoint") or ""
            rows.append({"bug_class": f"{bc}{(' @ ' + where) if where else ''}",
                         "severity": f.get("severity", "high"),
                         "controls": compliance.mapped_row(bc)})
        return Response.json({"frameworks": compliance.FRAMEWORKS, "rows": rows})

    def _impact(ctx: Ctx) -> Response:
        from .impact import chains_for
        return Response.json({"chains": chains_for(_confirmed())})

    def _evidence(ctx: Ctx) -> Response:
        bundle = os.path.join(config.base_dir, "rc", "evidence", "evidence-bundle.json")
        try:
            with open(bundle, encoding="utf-8") as fh:
                b = json.load(fh)
        except (OSError, ValueError):
            return Response.json({"present": False})
        certs = b.get("certificates") or b.get("entries") or []
        # a stable out-of-band anchor for the trust root (the signer's public key) the operator can compare
        fp = "(verified by evidence verify)"
        try:
            import hashlib
            with open(os.path.join(config.base_dir, "rc", "trust-root.json"), encoding="utf-8") as fh:
                tr = json.load(fh)
            pub = tr["authorizers"][0]["public_key_b64"]
            fp = "sha256:" + hashlib.sha256(pub.encode()).hexdigest()[:32]
        except (OSError, ValueError, KeyError, IndexError):
            pass
        return Response.json({"present": True,
                              "certificates": len(certs) if isinstance(certs, list) else 0,
                              "chain": len(b.get("chain", [])) if isinstance(b.get("chain"), list) else 0,
                              "trust_root_fingerprint": fp})

    r.add("GET", "/", _cockpit)
    r.add("GET", "/run/<id>", _run)
    r.add("GET", "/compliance.json", _compliance)
    r.add("GET", "/impact.json", _impact)
    r.add("GET", "/evidence.json", _evidence)
    r.add("GET", "/findings.json", _findings)
    r.add("GET", "/healthz", lambda _c: Response.json({"status": "ok", "plane": "control"}))
    return r
