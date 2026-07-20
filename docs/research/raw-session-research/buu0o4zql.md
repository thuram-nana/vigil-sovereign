===== bridge/server.py =====
     1	"""The SIGIL bridge server (Phase 9 W1-B) — the WireGuard-bound HTTP transport that lets an
     2	AUTHORIZED phone reach the desktop `BridgeDaemon`. It forks the WS-C glass-cockpit server
     3	(`sigil.ui.server`) verbatim in shape (ThreadingHTTPServer + BaseHTTPRequestHandler, the strict
     4	CSP/nosniff/no-referrer header set, the body cap + 30s timeout, the never-log-auth `log_message`,
     5	the SSE structure, the anti-DNS-rebinding Host/Origin/Referer gate) and changes ONLY three things:
     6	
     7	  • THE BIND. It binds a `bind_ok` address (loopback or a PRIVATE/WireGuard address) — NEVER
     8	    0.0.0.0 / a public address. The constructor asserts this; the CLI asserts it too. This is the
     9	    non-negotiable exposure guard: the tunnel, not the transport, is the network boundary.
    10	
    11	  • THE AUTH. There is NO wire bearer secret (the ui's printed token is gone). Authentication IS a
    12	    per-request Ed25519 signature the phone makes with ITS OWN owner-authorized device key — the
    13	    Wave-1 device envelope (`bridge.envelope`). The server verifies the signature against the
    14	    owner-minted authorized-device set (recomputed PER REQUEST so a revocation takes effect at once),
    15	    binds the authenticated envelope `action` to the endpoint it hit (a `read:pending` envelope can
    16	    never reach the more-sensitive `read:recall`), applies a wallclock timestamp-freshness window
    17	    (injectable clock), and for EFFECTFUL actions (panic/relay) additionally runs the envelope's
    18	    strict monotonic-nonce replay gate (`consume(effectful=True)`). The owner trust-root is NEVER used
    19	    to sign anything here — the phone signs, the server only verifies.
    20	
    21	  • THE ALLOWLIST. The anti-rebind Host/Origin allowlist is derived from the REAL bound address (plus
    22	    the loopback pair when bound to loopback, for dev), not a hardcoded 127.0.0.1.
    23	
    24	Everything sensitive stays off the minimal frames: `/api/pending` and the SSE stream carry only
    25	`{seq, tier, kind}` — never a subject, never a payload, never a secret. `serve()` now wraps the
    26	transport in an owner-PINNED self-signed TLS cert (the phone PWA needs a secure context — https or
    27	localhost — to install and register a service worker; over a bare WireGuard IP that means self-signed
    28	TLS whose sha256 fingerprint the owner pins once, stable across restarts). `build_server` itself
    29	stays plain HTTP so the in-tunnel test harness is unchanged and TLS can be terminated upstream if
    30	preferred. Offense-free."""
    31	from __future__ import annotations
    32	
    33	import base64
    34	import ipaddress
    35	import json
    36	import os
    37	import time
    38	from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    39	from pathlib import Path
    40	from urllib.parse import parse_qs, urlparse
    41	
    42	from ..config import SPINE_PATH
    43	from ..governor.identity import owner_pubkey
    44	from ..mesh import authorized_devices
    45	from ..spine.store import SpineStore
    46	from ..spine.verify import verify_record
    47	from .daemon import BridgeDaemon, bind_ok
    48	from .envelope import consume, verify_envelope
    49	from .notifier import PushNotifier
    50	
    51	_WEBAPP = Path(__file__).parent / "webapp"       # the PWA is a later slice — served if present, else 404
    52	_CSP = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    53	_DEFAULT_PORT = 8722
    54	_TS_WINDOW = 120.0                               # ± seconds a request timestamp may differ from the server clock
    55	
    56	# Each network endpoint declares the ONE envelope action that authorizes it. Binding the
    57	# authenticated action to the endpoint stops a captured lesser-scoped envelope (e.g. `read:pending`,
    58	# which leaks only {seq,tier,kind}) from being replayed against a more-sensitive endpoint (e.g.
    59	# `read:recall`, which surfaces the owner's on-screen OCR history). `/api/graph` piggybacks on the
    60	# `read:snapshot` scope: graph returns only aggregate health, strictly LESS sensitive than the
    61	# snapshot, so a snapshot-scoped envelope reaching it is not an escalation (and a lesser envelope
    62	# still cannot reach it).
    63	_READ_ACTION = {
    64	    "/api/pending": "read:pending",
    65	    "/api/snapshot": "read:snapshot",
    66	    "/api/graph": "read:snapshot",
    67	    "/api/stream": "read:stream",
    68	    "/api/recall": "read:recall",
    69	}
    70	
    71	
    72	class BridgeServer(ThreadingHTTPServer):
    73	    daemon_threads = True
    74	
    75	    def __init__(self, addr, handler, *, spine_path, trusted_pubkey=None, clock=None,
    76	                 ts_window: float = _TS_WINDOW):
    77	        host = addr[0]
    78	        if not bind_ok(host):
    79	            raise ValueError(
    80	                f"refusing to bind {host!r}: the bridge binds loopback or a PRIVATE (WireGuard) "
    81	                f"address only — never 0.0.0.0 / an unspecified / a public address")
    82	        super().__init__(addr, handler)
    83	        self.spine_path = Path(spine_path)
    84	        # the owner PUBLIC key is the trust anchor (injectable for tests); NO private key ever lives here
    85	        self.trusted_pubkey = trusted_pubkey if trusted_pubkey is not None else owner_pubkey()
    86	        self.clock = clock or time.time          # injectable wallclock so the freshness gate is deterministic
    87	        self.ts_window = ts_window
    88	        port = self.server_address[1]            # the ACTUAL bound port (correct even for port 0)
    89	        hosts = {f"{host}:{port}"}
    90	        origins = {f"http://{host}:{port}"}
    91	        if ipaddress.ip_address(host).is_loopback:   # dev convenience only — not added for a WG bind
    92	            hosts |= {f"127.0.0.1:{port}", f"localhost:{port}"}
    93	            origins |= {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
    94	        self.allowed_hosts = frozenset(hosts)
    95	        self.allowed_origins = frozenset(origins)
    96	
    97	    def store(self) -> SpineStore:
    98	        return SpineStore(self.spine_path)       # fresh read each request (cheap, current)
    99	
   100	    def daemon(self) -> BridgeDaemon:
   101	        return BridgeDaemon(self.store(), trusted_pubkey=self.trusted_pubkey)
   102	
   103	
   104	def _json_bytes(obj) -> bytes:
   105	    return json.dumps(obj, ensure_ascii=False).encode("utf-8")
   106	
   107	
   108	class Handler(BaseHTTPRequestHandler):
   109	    server_version = "sigil-bridge/1.0"
   110	    timeout = 30                                  # per-connection socket timeout (no hung reader)
   111	    _MAX_BODY = 65536                             # bodies are tiny; cap to avoid a Content-Length hang/alloc
   112	
   113	    # never log auth (an envelope can ride in ?env= for SSE; never write it to a log)
   114	    def log_message(self, fmt, *args):  # noqa: A003
   115	        pass
   116	
   117	    # --- request helpers --------------------------------------------------------------------------
   118	    def _query(self) -> dict:
   119	        return parse_qs(urlparse(self.path).query)
   120	
   121	    def _authorized_now(self):
   122	        """The owner-minted authorized-device set, recomputed PER REQUEST — a revoke takes effect now."""
   123	        return authorized_devices(self.server.store(), self.server.trusted_pubkey)
   124	
   125	    def _envelope_payload(self):
   126	        """The device envelope: base64url of canonical JSON, in `X-SIGIL-Envelope` (GET/POST) or the
   127	        `?env=` query (SSE, which cannot set a header). Returns the payload dict, or None if absent/
   128	        malformed (fail-closed — the caller denies)."""
   129	        raw = self.headers.get("X-SIGIL-Envelope") or (self._query().get("env", [""])[0])
   130	        if not raw:
   131	            return None
   132	        try:
   133	            data = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
   134	            payload = json.loads(data)
   135	        except Exception:  # noqa: BLE001 — any decode/parse failure is an unauthenticated request
   136	            return None
   137	        return payload if isinstance(payload, dict) else None
   138	
   139	    def _fresh(self, core) -> bool:
   140	        """The server-layer wallclock freshness window (the envelope module is pure — it never reads a
   141	        clock — so freshness lives HERE). A non-numeric / far-off timestamp fails closed."""
   142	        try:
   143	            ts = float(core.get("ts"))
   144	        except (TypeError, ValueError):
   145	            return False
   146	        return abs(self.server.clock() - ts) <= self.server.ts_window
   147	
   148	    def _authed(self, action: str):
   149	        """Authenticate a READ: verify the device signature, apply freshness, bind the action to this
   150	        endpoint. Reads are side-effect-free, so they are NOT receipted (no spine write per GET) — the
   151	        freshness window is their replay bound. Returns the core, or None after sending a deny."""
   152	        payload = self._envelope_payload()
   153	        if payload is None:
   154	            self._deny(401, "missing/invalid device envelope")
   155	            return None
   156	        ok, core = verify_envelope(payload, self._authorized_now())
   157	        if not ok:
   158	            self._deny(401, f"unauthenticated: {core}")
   159	            return None
   160	        if not self._fresh(core):
   161	            self._deny(401, "stale request (timestamp outside freshness window)")
   162	            return None
   163	        if core.get("action") != action:
   164	            self._deny(403, "envelope action does not authorize this endpoint")
   165	            return None
   166	        return core
   167	
   168	    def _authed_effectful(self, action: str):
   169	        """Authenticate an EFFECTFUL request (panic/relay): verify + freshness + endpoint-bind, then run
   170	        the envelope's strict monotonic-nonce replay gate and receipt it on the spine
   171	        (`consume(effectful=True)`). A replayed/stale-nonce envelope is refused. Returns core or None."""
   172	        payload = self._envelope_payload()
   173	        if payload is None:
   174	            self._deny(401, "missing/invalid device envelope")
   175	            return None
   176	        authorized = self._authorized_now()
   177	        ok, core = verify_envelope(payload, authorized)
   178	        if not ok:
   179	            self._deny(401, f"unauthenticated: {core}")
   180	            return None
   181	        if not self._fresh(core):
   182	            self._deny(401, "stale request (timestamp outside freshness window)")
   183	            return None
   184	        if core.get("action") != action:
   185	            self._deny(403, "envelope action does not authorize this endpoint")
   186	            return None
   187	        try:
   188	            return consume(self.server.store(), payload, authorized, effectful=True)
   189	        except ValueError as e:                   # replay / invalid nonce (fail-closed)
   190	            self._deny(409, f"refused: {str(e)[:120]}")
   191	            return None
   192	        except Exception as e:  # noqa: BLE001 — never let a consume error crash the handler (no RemoteDisconnected)
   193	            self._deny(400, f"refused: {type(e).__name__}")
   194	            return None
   195	
   196	    def _rebind_ok(self) -> bool:
   197	        """The anti-DNS-rebinding gate (ui `_action_ok` logic, minus the token — the envelope is the
   198	        credential): the `Host` must be in the WG-derived allowlist, an `Origin`, if present, must
   199	        EXACT-match an allowed origin (a prefix like `http://IP:PORT.evil.com` must NOT pass), and a
   200	        `Referer`, if present, must sit under an allowed origin. Applied to the whole POST action
   201	        plane as defense-in-depth."""
   202	        if self.headers.get("Host", "") not in self.server.allowed_hosts:
   203	            return False
   204	        o = self.headers.get("Origin") or ""
   205	        ref = self.headers.get("Referer") or ""
   206	        if o and o not in self.server.allowed_origins:
   207	            return False
   208	        if ref and not any(ref.startswith(a + "/") or ref == a for a in self.server.allowed_origins):
   209	            return False
   210	        return True
   211	
   212	    # --- response helpers -------------------------------------------------------------------------
   213	    def _send(self, code: int, body: bytes, ctype="application/json"):
   214	        self.send_response(code)
   215	        self.send_header("Content-Type", ctype)
   216	        self.send_header("Content-Length", str(len(body)))
   217	        self.send_header("Content-Security-Policy", _CSP)
   218	        self.send_header("X-Content-Type-Options", "nosniff")
   219	        self.send_header("Referrer-Policy", "no-referrer")
   220	        self.end_headers()
   221	        try:
   222	            self.wfile.write(body)
   223	        except (BrokenPipeError, ConnectionResetError):
   224	            pass
   225	
   226	    def _json(self, obj, code=200):
   227	        self._send(code, _json_bytes(obj))
   228	
   229	    def _deny(self, code=403, msg="forbidden"):
   230	        self._json({"error": msg}, code)
   231	
   232	    # --- GET (read plane) -------------------------------------------------------------------------
   233	    def do_GET(self):
   234	        path = urlparse(self.path).path
   235	        if path in ("/", "/index.html"):
   236	            return self._serve_index()
   237	        if path.startswith("/static/"):
   238	            return self._serve_static(path[len("/static/"):])
   239	        if not path.startswith("/api/"):
   240	            return self._deny(404, "not found")
   241	        if path == "/api/stream":
   242	            return self._sse()                    # SSE authenticates via ?env= inside _authed
   243	        if path == "/api/pending":
   244	            if self._authed(_READ_ACTION[path]) is None:
   245	                return
   246	            return self._json({"pending": self.server.daemon().pending()})   # {seq,tier,kind} only
   247	        if path == "/api/snapshot":
   248	            if self._authed(_READ_ACTION[path]) is None:
   249	                return
   250	            from ..dashboard import snapshot
   251	            return self._json(snapshot(self.server.store()))
   252	        if path == "/api/graph":
   253	            if self._authed(_READ_ACTION[path]) is None:
   254	                return
   255	            return self._graph()
   256	        if path.startswith("/api/record/"):
   257	            if self._authed("read:record") is None:
   258	                return
   259	            return self._record(path.rsplit("/", 1)[-1])
   260	        if path == "/api/recall":
   261	            if self._authed(_READ_ACTION[path]) is None:
   262	                return
   263	            subject = self._query().get("subject", [""])[0]
   264	            return self._json({"subject": subject, "recall": self.server.daemon().recall(subject)})
   265	        return self._deny(404, "unknown endpoint")
   266	
   267	    def _serve_index(self):
   268	        idx = _WEBAPP / "index.html"
   269	        if not idx.is_file():
   270	            return self._deny(404, "bridge PWA not built yet")   # graceful — the webapp is a later slice
   271	        try:
   272	            self._send(200, idx.read_bytes(), ctype="text/html; charset=utf-8")
   273	        except OSError:
   274	            self._deny(404, "not found")
   275	
   276	    def _serve_static(self, sub: str):
   277	        base = _WEBAPP.resolve()
   278	        target = (base / sub).resolve()
   279	        if base != target and base not in target.parents:        # traversal guard (allowlist by containment)
   280	            return self._deny(404, "not found")
   281	        if not target.is_file():
   282	            return self._deny(404, "not found")                  # includes: webapp dir absent (later slice)
   283	        name = target.name
   284	        ctype = ("application/javascript" if name.endswith(".js")
   285	                 else "text/css" if name.endswith(".css")
   286	                 else "text/html" if name.endswith(".html")
   287	                 else "application/octet-stream")
   288	        try:
   289	            self._send(200, target.read_bytes(), ctype=f"{ctype}; charset=utf-8")
   290	        except OSError:
   291	            self._deny(404, "not found")
   292	
   293	    def _record(self, raw):
   294	        try:
   295	            seq = int(raw)
   296	        except ValueError:
   297	            return self._deny(400, "bad seq")
   298	        rec = self.server.store().get(seq)
   299	        if rec is None:
   300	            return self._json({"error": "no such record", "seq": seq,
   301	                               "note": "no grounded record — not fabricated"}, 404)
   302	        ok, reason = verify_record(rec)                          # re-verify the atom LIVE (prove-don't-guess)
   303	        self._json({"seq": rec.seq, "kind": rec.kind, "source": rec.source, "actor": rec.actor,
   304	                    "ts": rec.ts, "entry_hash": rec.entry_hash, "prev_hash": rec.prev_hash,
   305	                    "payload": rec.payload, "integrity_ok": ok, "integrity_reason": reason})
   306	
   307	    def _graph(self):
   308	        try:
   309	            from ..graph import health
   310	            self._json({"health": health()})
   311	        except Exception as e:  # noqa: BLE001 — graph may not be built yet (ImportError included)
   312	            self._json({"error": "graph unavailable", "note": str(e)[:200]})
   313	
   314	    def _sse(self):
   315	        if self._authed("read:stream") is None:                  # deny already sent (401/403)
   316	            return
   317	        self.send_response(200)
   318	        self.send_header("Content-Type", "text/event-stream")
   319	        self.send_header("Cache-Control", "no-cache")
   320	        self.send_header("Content-Security-Policy", _CSP)
   321	        self.send_header("X-Content-Type-Options", "nosniff")
   322	        self.send_header("Referrer-Policy", "no-referrer")
   323	        self.end_headers()
   324	        try:
   325	            since = int(self._query().get("since", ["-1"])[0])
   326	        except (ValueError, TypeError):
   327	            since = -1                                            # any malformed cursor → from genesis
   328	        notifier = PushNotifier(self.server.store(), since_seq=since)
   329	        try:
   330	            while True:
   331	                sent = False
   332	                for ev in notifier.poll():
   333	                    frame = {"seq": ev["seq"], "tier": ev["tier"], "kind": ev["kind"]}   # minimal — no subject
   334	                    self.wfile.write(f"data: {json.dumps(frame, ensure_ascii=False)}\n\n".encode("utf-8"))
   335	                    sent = True
   336	                self.wfile.write(b": hb\n\n")                     # heartbeat / flush
   337	                self.wfile.flush()
   338	                if not sent:
   339	                    time.sleep(0.25)
   340	        except (BrokenPipeError, ConnectionResetError, OSError):
   341	            return                                                # client closed — end the stream
   342	
   343	    # --- POST (action plane) ----------------------------------------------------------------------
   344	    def do_POST(self):
   345	        path = urlparse(self.path).path
   346	        if path not in ("/api/action", "/api/panic", "/api/relay", "/api/gesture/arm"):
   347	            return self._deny(404, "not found")
   348	        length = int(self.headers.get("Content-Length", "0") or "0")
   349	        if length > self._MAX_BODY:                              # cap the body (no CL hang / alloc)
   350	            return self._deny(413, "body too large")
   351	        body_bytes = self.rfile.read(length) if length else b""
   352	        if not self._rebind_ok():                               # anti-rebind gate on the whole action plane
   353	            return self._deny(403, "action denied (origin / host — possible DNS rebinding)")
   354	        if path == "/api/action":
   355	            return self._device_action(body_bytes)
   356	        if path == "/api/gesture/arm":
   357	            return self._device_arm(body_bytes)
   358	        # panic / relay — effectful, envelope-authenticated with the strict nonce replay gate
   359	        action = "panic" if path == "/api/panic" else "relay"
   360	        core = self._authed_effectful(action)
   361	        if core is None:
   362	            return
   363	        if action == "panic":
   364	            return self._json({"ok": True, "seq": self.server.daemon().panic_engage(by="phone")})
   365	        a = core.get("args")                                     # the relayed command is INSIDE the signed core;
   366	        text = str(a.get("text", "")) if isinstance(a, dict) else ""   # signed args may be ANY JSON type — guard
   367	        return self._json({"ok": True, "reply": self.server.daemon().relay(text)})
   368	
   369	    def _device_action(self, body_bytes):
   370	        """The phone posts its OWN device-signed `governor.approval` payload. The SERVER only VERIFIES
   371	        (it never signs) — `submit_device_approval` accepts it iff the signing device is currently
   372	        authorized AND the signature verifies; the signed `target_seq` binds, so no nonce is needed."""
   373	        try:
   374	            body = json.loads(body_bytes or b"{}")
   375	        except (ValueError, TypeError) as e:
   376	            return self._deny(400, f"bad request: {e}")
   377	        if not isinstance(body, dict):
   378	            return self._deny(400, "bad request: body must be a JSON object")
   379	        try:
   380	            seq = self.server.daemon().submit_device_approval(body)
   381	        except ValueError as e:                                  # unauthorized / forged / not-an-approval
   382	            return self._deny(403, f"approval refused: {str(e)[:200]}")
   383	        except Exception as e:  # noqa: BLE001 — never leak internals as a 500
   384	            return self._deny(400, f"action failed: {str(e)[:200]}")
   385	        self._json({"ok": True, "seq": seq})
   386	
   387	    def _device_arm(self, body_bytes):
   388	        """The phone posts its OWN device-signed gesture arm request. The SERVER only VERIFIES + RECORDS
   389	        it (`submit_arm_request`, fail-closed on unauthorized/forged); the live SessionGate re-verifies
   390	        and enforces freshness / kill-switch / single-session / TTL when it consumes it. Recording is
   391	        necessary-but-not-sufficient to arm — the trust boundary is `arm_by_device`, not this endpoint."""
   392	        try:
   393	            body = json.loads(body_bytes or b"{}")
   394	        except (ValueError, TypeError) as e:
   395	            return self._deny(400, f"bad request: {e}")
   396	        if not isinstance(body, dict):
   397	            return self._deny(400, "bad request: body must be a JSON object")
   398	        try:
   399	            seq = self.server.daemon().submit_arm_request(body)
   400	        except ValueError as e:                                  # unauthorized / forged / not-an-arm-request
   401	            return self._deny(403, f"arm refused: {str(e)[:200]}")
   402	        except Exception as e:  # noqa: BLE001 — never leak internals as a 500
   403	            return self._deny(400, f"arm failed: {str(e)[:200]}")
   404	        self._json({"ok": True, "seq": seq})
   405	
   406	
   407	def build_server(*, addr: str, port: int = _DEFAULT_PORT, spine_path=None, trusted_pubkey=None,
   408	                 clock=None) -> BridgeServer:
   409	    """Build (but do not run) the bridge server bound to `addr` (asserted `bind_ok`). `trusted_pubkey`
   410	    and `clock` are injectable for deterministic tests; both default to the real owner identity / wallclock."""
   411	    return BridgeServer((addr, port), Handler,
   412	                        spine_path=Path(spine_path) if spine_path else SPINE_PATH,
   413	                        trusted_pubkey=trusted_pubkey, clock=clock)
   414	
   415	
   416	def _write_secure(path: Path, data: bytes) -> None:
   417	    """Write `data` to `path` created 0600 up-front (no world-readable window) — the vault/secrets
   418	    secure-file idiom (`os.open(..., 0o600)`)."""
   419	    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
   420	    with os.fdopen(fd, "wb") as fh:
   421	        fh.write(data)
   422	
   423	
   424	def _fingerprint(cert) -> str:
   425	    """The pinned identity: sha256 of the DER cert, hex, colon-grouped byte pairs (openssl-style,
   426	    upper-case) — what the owner eyeball-matches on the phone once."""
   427	    from cryptography.hazmat.primitives import hashes
   428	    h = cert.fingerprint(hashes.SHA256()).hex().upper()      # fingerprint() == sha256 of the DER encoding
   429	    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
   430	
   431	
   432	def ensure_bridge_cert(addr: str) -> tuple[str, str, str]:
   433	    """Mint (or REUSE) a minimal owner-pinned self-signed TLS cert for the bridge bound to `addr`,
   434	    returning `(certfile, keyfile, sha256_fingerprint)`.
   435	
   436	    The cert carries `addr` as its CN and (when `addr` is an IP — always true for a `bind_ok` bridge)
   437	    as an `x509.IPAddress` SubjectAlternativeName, so an IP-literal TLS connection matches. Cert+key
   438	    live under `SIGIL_HOME/bridge/` (dir 0700, files 0600). If a cert already exists FOR THIS ADDR it
   439	    is REUSED — the fingerprint is therefore STABLE across restarts, so the owner pins it exactly once
   440	    (a changed fingerprint later means a MITM / a wiped key, not a benign restart). An EC P-256 key is
   441	    used (easy for `cryptography`, accepted by `ssl`). Validity ~2 years; a real wallclock is fine here
   442	    (this is TLS notBefore/notAfter, not spine or learning math)."""
   443	    import datetime
   444	    import ipaddress as _ip
   445	
   446	    from cryptography import x509
   447	    from cryptography.hazmat.primitives import hashes, serialization
   448	    from cryptography.hazmat.primitives.asymmetric import ec
   449	    from cryptography.x509.oid import NameOID
   450	
   451	    from ..config import SIGIL_HOME                          # read at call-time (patchable in tests)
   452	
   453	    bridge_dir = Path(SIGIL_HOME) / "bridge"
   454	    bridge_dir.mkdir(parents=True, exist_ok=True)
   455	    try:
   456	        os.chmod(bridge_dir, 0o700)                          # owner-only, like the spine/keys dirs
   457	    except OSError:
   458	        pass
   459	    tag = addr.replace(":", "_").replace("/", "_").replace("%", "_")   # one stable cert per bind addr
   460	    certfile = bridge_dir / f"cert-{tag}.pem"
   461	    keyfile = bridge_dir / f"key-{tag}.pem"
   462	
   463	    if certfile.is_file() and keyfile.is_file():             # REUSE → stable fingerprint (pin once)
   464	        cert = x509.load_pem_x509_certificate(certfile.read_bytes())
   465	        return str(certfile), str(keyfile), _fingerprint(cert)
   466	
   467	    key = ec.generate_private_key(ec.SECP256R1())
   468	    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, addr)])
   469	    try:                                                     # bind addr is an IP by construction (bind_ok)
   470	        san = x509.SubjectAlternativeName([x509.IPAddress(_ip.ip_address(addr))])
   471	    except ValueError:                                       # defensive: a hostname would use a DNS SAN
   472	        san = x509.SubjectAlternativeName([x509.DNSName(addr)])
   473	    now = datetime.datetime.now(datetime.timezone.utc)       # real wallclock (tz-aware; TLS validity, not spine math)
   474	    cert = (
   475	        x509.CertificateBuilder()
   476	        .subject_name(name)
   477	        .issuer_name(name)                                   # self-signed: issuer == subject
   478	        .public_key(key.public_key())
   479	        .serial_number(x509.random_serial_number())
   480	        .not_valid_before(now - datetime.timedelta(minutes=5))   # small skew tolerance
   481	        .not_valid_after(now + datetime.timedelta(days=730))     # ~2 years
   482	        .add_extension(san, critical=False)
   483	        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
   484	        .sign(key, hashes.SHA256())
   485	    )
   486	    _write_secure(certfile, cert.public_bytes(serialization.Encoding.PEM))
   487	    _write_secure(keyfile, key.private_bytes(serialization.Encoding.PEM,
   488	                                             serialization.PrivateFormat.PKCS8,
   489	                                             serialization.NoEncryption()))
   490	    return str(certfile), str(keyfile), _fingerprint(cert)
   491	
   492	
   493	def serve(*, addr: str, port: int = _DEFAULT_PORT, spine_path=None, tls: bool = True) -> None:
   494	    """Run the WireGuard-bound bridge transport. With `tls=True` (default) it wraps the listening
   495	    socket in an owner-pinned self-signed TLS cert (`ensure_bridge_cert`) BEFORE serving, printing the
   496	    `https://` bind URL + the sha256 fingerprint to pin on the phone. With `tls=False` it serves plain
   497	    HTTP (degraded: no secure context → the PWA cannot install / register a service worker) and prints
   498	    an honest warning. `build_server` stays plain — TLS lives only here."""
   499	    srv = build_server(addr=addr, port=port, spine_path=spine_path)
   500	    bound = srv.server_address[1]
   501	    if tls:
   502	        import ssl
   503	        certfile, keyfile, fp = ensure_bridge_cert(addr)
   504	        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
   505	        ctx.load_cert_chain(certfile, keyfile)
   506	        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)   # wrap the listener before serve_forever
   507	        print(f"  SIGIL bridge → https://{addr}:{bound}/   (WireGuard-bound; loopback/private only — NO wire secret)")
   508	        print(f"  TLS fingerprint (sha256): {fp}")
   509	        print("    ↳ PIN this once on the phone — it is stable across restarts; a later change means MITM")
   510	    else:
   511	        print(f"  SIGIL bridge → http://{addr}:{bound}/   (WireGuard-bound; loopback/private only — NO wire secret)")
   512	        print("  WARNING: --no-tls → plain HTTP, NO secure context: the phone CANNOT install the PWA or")
   513	        print("           register a service worker. Use TLS unless you terminate it upstream in the tunnel.")
   514	    print("  pair a phone (owner, at the desktop):  sigil mesh authorize <device-id> <device-pubkey>")
   515	    print("  every request must carry an authorized-device signature (X-SIGIL-Envelope) — there is no token")
   516	    try:
   517	        srv.serve_forever()
   518	    except KeyboardInterrupt:
   519	        srv.shutdown()
