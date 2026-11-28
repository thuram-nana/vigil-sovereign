/* VIGIL homepage visuals: a dotted world globe with animated connection arcs, and a
   compact "recent CVEs" feed from the same-origin /api/cve.

   CSP-clean by construction: this file is served from /assets under default-src 'self';
   it registers no inline handler, injects no markup, and sets every feed-derived string
   through textContent (a hostile feed value can never become HTML). Both visuals are
   progressive: the page is complete without this script, the globe degrades to an empty
   (invisible) canvas if 2D canvas is unavailable, and the feed keeps its static resting
   copy if the fetch fails or the catalog is empty. prefers-reduced-motion is respected:
   the globe renders one static frame and starts no animation loop. */
(function () {
  "use strict";

  var reduceMotion = false;
  try { reduceMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches); }
  catch (e) { reduceMotion = false; }

  function cssVar(name, fallback) {
    try {
      var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback;
    } catch (e) { return fallback; }
  }
  function hexToRgb(hex) {
    var h = (hex || "").replace("#", "").trim();
    if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
    if (h.length !== 6) return null;
    var n = parseInt(h, 16);
    if (isNaN(n)) return null;
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255 };
  }
  function rgba(rgb, a) {
    return rgb ? ("rgba(" + rgb.r + "," + rgb.g + "," + rgb.b + "," + a + ")") : ("rgba(154,164,180," + a + ")");
  }

  /* =====================================================================
     THE GLOBE: an orthographic sphere of dotted continents with arcs.
     ===================================================================== */
  function initGlobe() {
    var canvas = document.getElementById("home-globe");
    if (!canvas || typeof canvas.getContext !== "function") return;
    var ctx;
    try { ctx = canvas.getContext("2d"); } catch (e) { return; }
    if (!ctx) return;

    // Land mask: for each 5deg latitude row (north -> south), the inclusive column
    // ranges (72 columns of 5deg longitude, column 0 = lon -180) that are land. A
    // coarse, hand-built silhouette: enough for a recognizable dotted world.
    var LAND = [
      [], [[20, 25], [26, 31]], [[15, 25], [26, 32], [52, 60]], [[9, 25], [26, 32], [40, 71]],
      [[2, 26], [27, 31], [36, 71]], [[2, 27], [28, 31], [36, 71]], [[5, 27], [33, 71]],
      [[5, 28], [32, 70]], [[5, 28], [32, 70]], [[6, 26], [32, 69]], [[7, 25], [32, 68]],
      [[8, 24], [32, 69]], [[10, 21], [32, 69]], [[12, 20], [33, 70]], [[14, 21], [31, 66]],
      [[15, 22], [30, 66]], [[20, 27], [29, 52], [55, 66]], [[19, 28], [30, 50], [55, 66]],
      [[19, 29], [31, 49], [55, 66]], [[19, 30], [32, 48], [56, 65]], [[19, 31], [32, 47], [57, 66]],
      [[20, 31], [33, 46], [56, 67]], [[20, 31], [34, 45], [56, 67]], [[21, 30], [35, 44], [57, 66]],
      [[22, 29], [36, 42], [57, 65]], [[23, 28], [58, 64], [66, 68]], [[23, 27], [66, 68]],
      [[24, 27]], [[24, 26]], [], [[20, 30]], [[0, 71]], [[0, 71]], [[0, 71]], [[0, 71]], [[0, 71]]
    ];
    var MASK_COLS = 72, MASK_ROWS = 36;
    function isLand(lat, lon) {
      var row = Math.floor((87.5 - lat) / 5);
      if (row < 0) row = 0; else if (row > MASK_ROWS - 1) row = MASK_ROWS - 1;
      var col = Math.floor((lon + 180) / 5);
      col = ((col % MASK_COLS) + MASK_COLS) % MASK_COLS;
      var ranges = LAND[row];
      for (var i = 0; i < ranges.length; i++) {
        if (col >= ranges[i][0] && col <= ranges[i][1]) return true;
      }
      return false;
    }

    // Even-ish dot spacing: longitude samples scale with cos(latitude).
    var dots = [];
    for (var lat = -84; lat <= 84; lat += 3) {
      var circ = Math.cos(lat * Math.PI / 180);
      var n = Math.max(6, Math.round(circ * 110));
      for (var k = 0; k < n; k++) {
        var lon = -180 + (360 * k) / n;
        if (!isLand(lat, lon)) continue;
        var phi = lat * Math.PI / 180, lam = lon * Math.PI / 180;
        dots.push([Math.cos(phi) * Math.cos(lam), Math.sin(phi), Math.cos(phi) * Math.sin(lam)]);
      }
    }

    // A few recognizable hubs, paired into connection routes.
    var P = {
      sfo: [37.6, -122.4], nyc: [40.7, -74], lon: [51.5, -0.1], fra: [50.1, 8.7],
      sao: [-23.5, -46.6], jnb: [-26.2, 28], dxb: [25.2, 55.3], sin: [1.35, 103.8],
      tok: [35.7, 139.7], syd: [-33.9, 151.2], mum: [19, 72.8], nbo: [-1.3, 36.8]
    };
    function v3(p) {
      var phi = p[0] * Math.PI / 180, lam = p[1] * Math.PI / 180;
      return [Math.cos(phi) * Math.cos(lam), Math.sin(phi), Math.cos(phi) * Math.sin(lam)];
    }
    var routes = [["sfo", "nyc"], ["nyc", "lon"], ["lon", "fra"], ["fra", "dxb"], ["dxb", "sin"],
                  ["sin", "tok"], ["sin", "syd"], ["sao", "jnb"], ["mum", "sin"], ["nbo", "dxb"],
                  ["sfo", "tok"], ["nyc", "sao"]];
    var arcs = routes.map(function (r, i) {
      return { a: v3(P[r[0]]), b: v3(P[r[1]]), phase: (i * 0.137) % 1 };
    });

    var dotRgb = hexToRgb(cssVar("--text-1", "#9aa4b4"));
    var rimRgb = hexToRgb(cssVar("--border-strong", "#2a2f3a"));
    var arcRgb = hexToRgb(cssVar("--text-2", "#626c7c"));
    var factRgb = hexToRgb(cssVar("--st-confirmed", "#4bbf8a"));

    var W = 0, H = 0, R = 0, cx = 0, cy = 0, dpr = 1;
    var tilt = 0.38, cosT = Math.cos(tilt), sinT = Math.sin(tilt);
    var spin0 = -1.0;   // at rest, Africa / Europe / the Atlantic face the viewer

    function size() {
      var rect = canvas.getBoundingClientRect();
      dpr = Math.min(2, window.devicePixelRatio || 1);
      var w = Math.max(10, Math.round(rect.width)), h = Math.max(10, Math.round(rect.height));
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      W = canvas.width; H = canvas.height;
      cx = W / 2; cy = H / 2; R = Math.min(W, H) * 0.46;
    }

    function project(v, spin) {
      var cs = Math.cos(spin), sn = Math.sin(spin);
      var x = v[0] * cs + v[2] * sn;
      var z = -v[0] * sn + v[2] * cs;
      var y = v[1];
      var y2 = y * cosT - z * sinT;
      var z2 = y * sinT + z * cosT;
      return { x: cx + x * R, y: cy - y2 * R, z: z2 };   // z2 > 0 = front hemisphere
    }
    function quad(a, qx, qy, b, t) {
      var u = 1 - t;
      return { x: u * u * a.x + 2 * u * t * qx + t * t * b.x, y: u * u * a.y + 2 * u * t * qy + t * t * b.y };
    }
    function marker(pt, edge) {
      ctx.beginPath();
      ctx.arc(pt.x, pt.y, Math.max(1, dpr * 1.1), 0, Math.PI * 2);
      ctx.fillStyle = rgba(factRgb, 0.35 + 0.5 * edge);
      ctx.fill();
    }

    function frame(spin, t) {
      ctx.clearRect(0, 0, W, H);

      // atmosphere rim + a faint inner fill
      var g = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R * 1.02);
      g.addColorStop(0, rgba(rimRgb, 0.10));
      g.addColorStop(1, rgba(rimRgb, 0));
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.02, 0, Math.PI * 2); ctx.fill();
      ctx.beginPath(); ctx.arc(cx, cy, R * 1.02, 0, Math.PI * 2);
      ctx.strokeStyle = rgba(rimRgb, 0.5); ctx.lineWidth = Math.max(1, dpr); ctx.stroke();

      // land dots
      var dotR = Math.max(0.8, R * 0.0085);
      for (var i = 0; i < dots.length; i++) {
        var p = project(dots[i], spin);
        if (p.z <= 0.02) continue;
        ctx.beginPath();
        ctx.arc(p.x, p.y, dotR * (0.7 + 0.5 * p.z), 0, Math.PI * 2);
        ctx.fillStyle = rgba(dotRgb, 0.22 + 0.58 * p.z);
        ctx.fill();
      }

      // arcs with travelling markers
      for (var j = 0; j < arcs.length; j++) {
        var A = project(arcs[j].a, spin), B = project(arcs[j].b, spin);
        if (A.z <= 0.04 || B.z <= 0.04) continue;
        var edge = Math.min(A.z, B.z);
        var mx = (A.x + B.x) / 2, my = (A.y + B.y) / 2;
        var dx = B.x - A.x, dy = B.y - A.y, d = Math.sqrt(dx * dx + dy * dy);
        var ox = cx - mx, oy = cy - my, ol = Math.sqrt(ox * ox + oy * oy) || 1;
        var lift = Math.min(R * 0.5, d * 0.35 + R * 0.1);
        var qx = mx - (ox / ol) * lift, qy = my - (oy / ol) * lift;

        ctx.beginPath();
        ctx.moveTo(A.x, A.y);
        ctx.quadraticCurveTo(qx, qy, B.x, B.y);
        ctx.strokeStyle = rgba(arcRgb, 0.12 + 0.34 * edge);
        ctx.lineWidth = Math.max(0.8, dpr * 0.8);
        ctx.stroke();

        marker(A, edge); marker(B, edge);

        var tt = reduceMotion ? 0.5 : ((t * 0.00012 + arcs[j].phase) % 1);
        var pulse = quad(A, qx, qy, B, tt);
        ctx.beginPath();
        ctx.arc(pulse.x, pulse.y, Math.max(1.3, dpr * 1.6), 0, Math.PI * 2);
        ctx.fillStyle = rgba(factRgb, 0.45 + 0.45 * edge);
        ctx.fill();
      }
    }

    function render(t) { frame(spin0 + (reduceMotion ? 0 : t * 0.00004), t); }

    var raf = 0;
    function loop(t) { render(t); raf = window.requestAnimationFrame(loop); }
    function start() {
      size();
      if (reduceMotion) { render(0); return; }
      if (raf) window.cancelAnimationFrame(raf);
      raf = window.requestAnimationFrame(loop);
    }

    var rz = 0;
    function onResize() {
      clearTimeout(rz);
      rz = setTimeout(function () { try { size(); if (reduceMotion) render(0); } catch (e) {} }, 150);
    }
    try { window.addEventListener("resize", onResize, { passive: true }); }
    catch (e) { window.addEventListener("resize", onResize); }

    try { start(); } catch (e) { /* leave the canvas empty (nothing visible) */ }
  }

  /* =====================================================================
     THE CVE FEED: VIGIL's own recent CVEs from the same-origin /api/cve.
     ===================================================================== */
  function sevClass(s) {
    return ({ critical: "critical", high: "high", medium: "medium", low: "low" })[String(s || "").toLowerCase()] || "info";
  }
  function cveRow(rec) {
    var a = document.createElement("a");
    a.className = "cve-mini__row";
    a.setAttribute("href", "/cve/" + encodeURIComponent(rec.id || ""));

    var id = document.createElement("span");
    id.className = "cve-mini__id";
    id.textContent = rec.id || "CVE";
    a.appendChild(id);

    var title = document.createElement("span");
    title.className = "cve-mini__title";
    title.textContent = rec.title || rec.description || "Advisory";
    a.appendChild(title);

    if (rec.kev) {
      var kev = document.createElement("span");
      kev.className = "cve-mini__kev";
      kev.textContent = "KEV";
      a.appendChild(kev);
    }
    if (rec.severity) {
      var sev = document.createElement("span");
      sev.className = "cve-mini__sev cve-mini__sev--" + sevClass(rec.severity);
      sev.textContent = (rec.cvss_base != null ? (rec.cvss_base + " ") : "") + rec.severity;
      a.appendChild(sev);
    }
    return a;
  }
  function initCveFeed() {
    var mount = document.getElementById("home-cve");
    if (!mount || typeof window.fetch !== "function") return;
    window.fetch("/api/cve?per_page=6&order=published_desc", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r && r.ok ? r.json() : null; })
      .then(function (res) {
        if (!res || res.populated === false || !res.items || !res.items.length) return;  // keep the static copy
        var frag = document.createDocumentFragment();
        res.items.slice(0, 6).forEach(function (rec) { if (rec && rec.id) frag.appendChild(cveRow(rec)); });
        if (!frag.childNodes.length) return;
        mount.textContent = "";
        mount.appendChild(frag);
      })
      .catch(function () { /* leave the static resting copy; never surface an error */ });
  }

  function boot() {
    try { initGlobe(); } catch (e) {}
    try { initCveFeed(); } catch (e) {}
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
