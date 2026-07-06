/* graph.js — world-model attack-graph canvas.
 * Phase 0 stub: the full hand-rolled force-directed SVG renderer lands in Phase 2
 * (Attack Graph screen). Exposed as a global so app.js can call it once ready. */
window.Graph = {
  render(container /*, data */) {
    container.innerHTML =
      '<div class="stub"><b>Attack graph</b> — the world-model force-directed view ' +
      'renders here (Phase 2): typed nodes by kind, edges annotated with belief, ' +
      'attacker→crown-jewel paths, and choke-points.</div>';
  },
};
