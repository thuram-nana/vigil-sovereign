/* graph.js — world-model attack-graph: a hand-rolled force-directed SVG renderer.
 * No CDN, no library. Nodes coloured by kind, edges technique-labelled and belief-
 * weighted, attacker→crown-jewel paths highlighted, choke-points flagged. Deterministic
 * layout (seeded init) so the same graph draws the same way. */
window.Graph = (() => {
  const KIND_COLOR = {
    endpoint: '#4aa3ff', finding: '#ff8a3d', host: '#ff5470', datastore: '#f5c542',
    credential: '#c88bff', principal: '#37c8d6', cloud_resource: '#35d07f',
    service: '#8895a7', webapp: '#4aa3ff', session: '#c88bff', control: '#8895a7',
    network_segment: '#8895a7', attacker: '#f5a623',
  };
  const color = (kind) => (String(kind).includes('attacker') ? KIND_COLOR.attacker : (KIND_COLOR[kind] || '#8895a7'));

  function layout(nodes, edges, W, H) {
    const N = nodes.length; if (!N) return;
    // deterministic init on a circle (seed = index) so redraws are stable
    nodes.forEach((n, i) => {
      const a = (i / N) * Math.PI * 2;
      n.x = W / 2 + Math.cos(a) * Math.min(W, H) * 0.32;
      n.y = H / 2 + Math.sin(a) * Math.min(W, H) * 0.32;
      n.vx = 0; n.vy = 0;
      if (String(n.id).includes('attacker')) { n.x = W / 2; n.y = H - 60; } // anchor attacker low
    });
    const idx = new Map(nodes.map((n, i) => [n.id, i]));
    const REST = 90, KREP = 5200, KSPR = 0.045, DAMP = 0.85, CENTER = 0.008;
    for (let it = 0; it < 280; it++) {
      for (let i = 0; i < N; i++) {
        let fx = (W / 2 - nodes[i].x) * CENTER, fy = (H / 2 - nodes[i].y) * CENTER;
        for (let j = 0; j < N; j++) {
          if (i === j) continue;
          let dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          let d2 = dx * dx + dy * dy || 0.01, d = Math.sqrt(d2);
          const f = KREP / d2; fx += (dx / d) * f; fy += (dy / d) * f;
        }
        nodes[i]._fx = fx; nodes[i]._fy = fy;
      }
      for (const e of edges) {
        const a = nodes[idx.get(e.src)], b = nodes[idx.get(e.dst)]; if (!a || !b) continue;
        let dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 0.01;
        const f = (d - REST) * KSPR;
        a._fx += (dx / d) * f; a._fy += (dy / d) * f;
        b._fx -= (dx / d) * f; b._fy -= (dy / d) * f;
      }
      for (const n of nodes) {
        if (String(n.id).includes('attacker')) continue; // keep the anchor
        n.vx = (n.vx + n._fx) * DAMP; n.vy = (n.vy + n._fy) * DAMP;
        n.x += Math.max(-12, Math.min(12, n.vx)); n.y += Math.max(-12, Math.min(12, n.vy));
        n.x = Math.max(30, Math.min(W - 30, n.x)); n.y = Math.max(30, Math.min(H - 30, n.y));
      }
    }
  }

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

  function render(container, data, onPick) {
    const nodes = (data.nodes || []).map((n) => ({ ...n }));
    const edges = data.edges || [];
    if (!nodes.length) { container.innerHTML = '<div class="empty">no world-model nodes — a run with chainable findings (IDOR/SSRF/deserialization) populates the graph</div>'; return; }
    const W = Math.max(720, container.clientWidth || 900), H = 560;
    layout(nodes, edges, W, H);
    const pos = new Map(nodes.map((n) => [n.id, n]));
    // edges that lie on an attack path -> highlight; choke edges -> danger dashed
    const pathEdges = new Set(); (data.paths || []).forEach((p) => (p.steps || []).forEach((s) => pathEdges.add(s.src + '>' + s.dst)));
    const chokeEdges = new Set(); (data.chokes || []).forEach((c) => chokeEdges.add(c.src + '>' + c.dst));

    const lines = edges.map((e) => {
      const a = pos.get(e.src), b = pos.get(e.dst); if (!a || !b) return '';
      const key = e.src + '>' + e.dst;
      const onPath = pathEdges.has(key), choke = chokeEdges.has(key);
      const stroke = choke ? 'var(--danger)' : onPath ? 'var(--accent)' : 'var(--border-strong)';
      const w = choke ? 2.4 : onPath ? 2.2 : 1;
      const dash = choke ? 'stroke-dasharray="5 4"' : '';
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${stroke}" stroke-width="${w}" ${dash} opacity="${onPath || choke ? 0.95 : 0.4}"/>
        ${onPath ? `<text x="${mx}" y="${my - 3}" font-size="9" fill="var(--text-2)" text-anchor="middle" font-family="var(--font-mono)">${esc(e.technique)}</text>` : ''}`;
    }).join('');

    const circles = nodes.map((n, i) => {
      const isAtt = String(n.id).includes('attacker');
      const r = isAtt ? 11 : (n.kind === 'finding' ? 6 : 8);
      const label = String(n.id).replace(/^[a-z_]+:/, '').slice(0, 22);
      return `<g class="gnode" data-i="${i}" style="cursor:pointer">
        <circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${color(n.kind)}" stroke="var(--bg-0)" stroke-width="1.5"
          opacity="${0.55 + 0.45 * (n.belief == null ? 1 : n.belief)}"/>
        <text x="${n.x + r + 3}" y="${n.y + 3}" font-size="10" fill="var(--text-1)" font-family="var(--font-mono)">${esc(label)}</text>
      </g>`;
    }).join('');

    // legend by kind actually present
    const kinds = [...new Set(nodes.map((n) => (String(n.id).includes('attacker') ? 'attacker' : n.kind)))];
    const legend = kinds.map((k) => `<span class="row-flex" style="gap:5px"><span style="width:9px;height:9px;border-radius:50%;background:${color(k)};display:inline-block"></span><span class="muted" style="font-size:var(--fs-xs)">${esc(k)}</span></span>`).join('');

    container.innerHTML =
      `<div class="row-flex" style="flex-wrap:wrap;gap:12px;margin-bottom:8px">${legend}
        <span class="row-flex" style="gap:5px;margin-left:auto"><span style="width:16px;border-top:2px solid var(--accent);display:inline-block"></span><span class="muted" style="font-size:var(--fs-xs)">attack path</span></span>
        <span class="row-flex" style="gap:5px"><span style="width:16px;border-top:2px dashed var(--danger);display:inline-block"></span><span class="muted" style="font-size:var(--fs-xs)">choke-point</span></span></div>
      <svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" style="background:var(--bg-0);border:1px solid var(--border);border-radius:8px">${lines}${circles}</svg>`;

    container.querySelectorAll('.gnode').forEach((g) => g.addEventListener('click', () => {
      const n = nodes[+g.dataset.i]; if (onPick) onPick(n);
    }));
  }
  return { render, color };
})();
