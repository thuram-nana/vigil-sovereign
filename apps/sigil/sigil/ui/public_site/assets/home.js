/* VIGIL homepage hero: a rich spinning wireframe globe + a live network-activity counter.
   CSP-clean (same-origin, no inline), monochrome white, DPR-aware. Both animations hold still / settle under
   prefers-reduced-motion. No network, no eval: a purely decorative visual. */
"use strict";
(function () {
  var reduce = false;
  try { reduce = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion:reduce)").matches); } catch (e) { reduce = false; }

  // ---- the spinning wireframe globe ------------------------------------------------------------------------------
  (function () {
    var cv = document.getElementById("vigil-hero-globe");
    if (!cv) { return; }
    var ctx = cv.getContext && cv.getContext("2d");
    if (!ctx) { return; }
    var DPR = Math.min(window.devicePixelRatio || 1, 2), W, H, R, cx, cy;
    function size() {
      var r = cv.getBoundingClientRect();
      W = r.width || 420; H = r.height || 420;
      cv.width = W * DPR; cv.height = H * DPR; ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
      R = Math.min(W, H) * 0.44; cx = W / 2; cy = H / 2;
    }
    size();
    window.addEventListener("resize", size);
    var tilt = -0.42, ct = Math.cos(tilt), st = Math.sin(tilt);
    function rot3(p, a) { var x = p[0] * Math.cos(a) + p[2] * Math.sin(a), z = -p[0] * Math.sin(a) + p[2] * Math.cos(a), y = p[1]; return [x, y * ct - z * st, y * st + z * ct]; }
    function proj(p, a) { var q = rot3(p, a); return [cx + q[0] * R, cy + q[1] * R, q[2]]; }
    function sph(lat, lon) { var cl = Math.cos(lat); return [cl * Math.cos(lon), Math.sin(lat), cl * Math.sin(lon)]; }
    var N = 560, pts = [];
    for (var i = 0; i < N; i++) { var y = 1 - (i / (N - 1)) * 2; var rad = Math.sqrt(1 - y * y); var th = i * 2.399963; pts.push([Math.cos(th) * rad, y, Math.sin(th) * rad]); }
    var parallels = [-60, -30, 0, 30, 60].map(function (d) { return d * Math.PI / 180; });
    var meridians = []; for (var m = 0; m < 12; m++) { meridians.push(m / 12 * Math.PI * 2); }
    var hubs = [sph(0.71, -2.0), sph(0.18, -0.4), sph(0.62, 1.1), sph(-0.35, 0.3), sph(0.05, 2.4), sph(-0.55, -1.3), sph(0.4, -3.0)];
    var arcs = [[0, 1], [1, 2], [1, 3], [3, 4], [0, 5], [2, 6]].map(function (p, ix) { return { a: hubs[p[0]], b: hubs[p[1]], ph: ix * 0.17 }; });
    function slerp(a, b, t) { var d = a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; d = Math.max(-1, Math.min(1, d)); var om = Math.acos(d); if (om < 1e-4) { return a; } var s = Math.sin(om), s0 = Math.sin((1 - t) * om) / s, s1 = Math.sin(t * om) / s; return [a[0] * s0 + b[0] * s1, a[1] * s0 + b[1] * s1, a[2] * s0 + b[2] * s1]; }
    var rot = 0, tk = 0;
    function frame() {
      ctx.clearRect(0, 0, W, H);
      var g = ctx.createRadialGradient(cx, cy, R * 0.74, cx, cy, R * 1.12);
      g.addColorStop(0, "rgba(255,255,255,0)"); g.addColorStop(0.82, "rgba(255,255,255,0.05)"); g.addColorStop(1, "rgba(255,255,255,0)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R * 1.12, 0, 7); ctx.fill();
      ctx.lineWidth = 1;
      parallels.forEach(function (lat) {
        ctx.beginPath(); var s2 = false;
        for (var lon = 0; lon <= Math.PI * 2 + 0.01; lon += 0.12) { var p = proj(sph(lat, lon), rot); if (p[2] < -0.02) { s2 = false; continue; } s2 ? ctx.lineTo(p[0], p[1]) : (ctx.moveTo(p[0], p[1]), s2 = true); }
        ctx.strokeStyle = "rgba(255,255,255,0.09)"; ctx.stroke();
      });
      meridians.forEach(function (lon) {
        ctx.beginPath(); var s3 = false;
        for (var lat = -Math.PI / 2; lat <= Math.PI / 2 + 0.01; lat += 0.1) { var p = proj(sph(lat, lon), rot); if (p[2] < -0.02) { s3 = false; continue; } s3 ? ctx.lineTo(p[0], p[1]) : (ctx.moveTo(p[0], p[1]), s3 = true); }
        ctx.strokeStyle = "rgba(255,255,255,0.055)"; ctx.stroke();
      });
      for (var i2 = 0; i2 < pts.length; i2++) { var pp0 = proj(pts[i2], rot); if (pp0[2] < -0.1) { continue; } var depth = (pp0[2] + 1) / 2; ctx.beginPath(); ctx.arc(pp0[0], pp0[1], 0.5 + depth * 1.25, 0, 7); ctx.fillStyle = "rgba(255,255,255," + (0.08 + depth * 0.6).toFixed(3) + ")"; ctx.fill(); }
      for (var r2 = 0; r2 < arcs.length; r2++) {
        var A = arcs[r2].a, B = arcs[r2].b;
        ctx.beginPath(); for (var t = 0; t <= 1.0001; t += 0.035) { var pa = proj(slerp(A, B, t), rot); t === 0 ? ctx.moveTo(pa[0], pa[1]) : ctx.lineTo(pa[0], pa[1]); }
        ctx.strokeStyle = "rgba(255,255,255,0.16)"; ctx.lineWidth = 1; ctx.stroke();
        var tp = ((tk * 0.004) + arcs[r2].ph) % 1; var pu = proj(slerp(A, B, tp), rot);
        if (pu[2] > -0.05) { var gg = ctx.createRadialGradient(pu[0], pu[1], 0, pu[0], pu[1], 9); gg.addColorStop(0, "rgba(255,255,255,0.9)"); gg.addColorStop(1, "rgba(255,255,255,0)"); ctx.fillStyle = gg; ctx.beginPath(); ctx.arc(pu[0], pu[1], 9, 0, 7); ctx.fill(); ctx.beginPath(); ctx.arc(pu[0], pu[1], 1.7, 0, 7); ctx.fillStyle = "#fff"; ctx.fill(); }
      }
      for (var hb = 0; hb < hubs.length; hb++) { var ph = proj(hubs[hb], rot); if (ph[2] < -0.05) { continue; } var d2 = (ph[2] + 1) / 2; var puls = 0.6 + 0.4 * Math.sin(tk * 0.05 + hb); var rd = 2.1 + d2 * 1.3; var hg = ctx.createRadialGradient(ph[0], ph[1], 0, ph[0], ph[1], rd * 5); hg.addColorStop(0, "rgba(255,255,255," + (0.4 * puls).toFixed(3) + ")"); hg.addColorStop(1, "rgba(255,255,255,0)"); ctx.fillStyle = hg; ctx.beginPath(); ctx.arc(ph[0], ph[1], rd * 5, 0, 7); ctx.fill(); ctx.beginPath(); ctx.arc(ph[0], ph[1], rd, 0, 7); ctx.fillStyle = "rgba(255,255,255,0.95)"; ctx.fill(); }
      tk++; rot += 0.0018;
      if (!reduce) { requestAnimationFrame(frame); }
    }
    frame();
  })();

  // ---- the live network-activity counter -------------------------------------------------------------------------
  (function () {
    var el = document.getElementById("vigil-hero-signal");
    if (!el) { return; }
    var pool = [10, 20, 80, 120, 300, 500, 800, 1200, 1500, 2000, 3000, 5000, 7500, 10000];
    function render(v) { var n = Math.round(v); try { el.textContent = n.toLocaleString("en-US"); } catch (e) { el.textContent = String(n); } }
    if (reduce) { render(1500); return; }
    var cur = 1200, from = 1200, to = 1200, t0 = performance.now(), dur = 900, dueAt = performance.now() + 1500;
    render(cur);
    function pick() { var v = pool[Math.floor(Math.random() * pool.length)]; return v === to ? pool[(pool.indexOf(v) + 3) % pool.length] : v; }
    function tick() {
      var t = performance.now();
      if (t >= dueAt) { from = to; to = pick(); t0 = t; dueAt = t + 2600 + Math.random() * 1600; }
      var p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3);
      cur = from + (to - from) * e; render(cur);
      requestAnimationFrame(tick);
    }
    tick();
  })();
})();
