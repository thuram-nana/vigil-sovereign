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
from . import runner
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
  refreshFindings();
}
async function runAll(){
  const ids = Array.from(document.querySelectorAll('.run-row')).map(r=>r.dataset.run);
  for(const id of ids){ await runOne(id); }
}
async function refreshFindings(){
  try{
    const r = await fetch('/findings.json'); const d = await r.json();
    const box = document.getElementById('findings');
    if(!d.findings || !d.findings.length){ box.innerHTML = '<p style="color:var(--text-2)">No findings captured yet — run step 2.</p>'; return; }
    box.innerHTML = d.findings.map(f=>{
      const fact = (f.grounding==='fact');
      const sev = (f.severity||'info').toLowerCase();
      return '<div class="finding"><span class="sev sev-'+(['critical','high','medium','low'].includes(sev)?sev:'info')+'">'+(f.bug_class||f.class||'?')+'</span> '
        + (fact?'<span class="shield">✓ FACT</span>':'<span class="pill sm">'+(f.grounding||'lead')+'</span>')
        + ' <span style="color:var(--text-1)">'+(f.title||'')+'</span></div>';
    }).join('');
  }catch(e){ /* ignore */ }
}
document.addEventListener('click', e=>{
  const b = e.target.closest('.run-btn'); if(b){ runOne(b.dataset.run); }
  if(e.target.id==='run-all'){ runAll(); }
});
refreshFindings();
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
        '<div class="card" style="margin-top:var(--sp-4)"><div class="card-h"><span class="label">Findings</span>'
        '<h3>Oracle-confirmed</h3></div><div id="findings"></div></div></div>'
        # right: capability catalogue
        f'<div><div class="card-h"><span class="label">Capability catalogue</span>'
        '<h3 style="margin-bottom:12px">Every VIGIL capability × the planted weakness</h3></div>'
        f'<div class="grid" style="gap:var(--sp-3)">{_catalog_cards()}</div></div>'
        '</div></main>'
        '<style>.run-row{display:flex;justify-content:space-between;align-items:center;gap:12px;'
        'padding:10px 0;border-top:1px solid var(--border)}.run-label{font-weight:600}'
        '.run-exp{font-size:12px;color:var(--text-2)}.finding{padding:6px 0;border-bottom:1px solid var(--border);'
        'font-size:13px}</style>'
        f'<script>{_PAGE_JS}</script>'
    )
    return Response.html(theme.page("Range Control", body, plane="control", mode=ctx.mode))


def build_control_router(config: Config) -> Router:
    r = Router()

    def _run(ctx: Ctx) -> StreamResponse:
        spec_id = ctx.params.get("id", "")
        return StreamResponse(runner.run_stream(spec_id, config), content_type="text/plain; charset=utf-8")

    def _findings(ctx: Ctx) -> Response:
        path = os.path.join(config.base_dir, "rc", "records.reverify.json")
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
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

    r.add("GET", "/", _cockpit)
    r.add("GET", "/run/<id>", _run)
    r.add("GET", "/findings.json", _findings)
    r.add("GET", "/healthz", lambda _c: Response.json({"status": "ok", "plane": "control"}))
    return r
