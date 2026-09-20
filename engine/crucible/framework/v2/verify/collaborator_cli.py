"""
verify.collaborator_cli — `python3 -m framework.v2 collaborator serve`.

Runs the operator-hosted OOB relay (verify.collaborator.RelayServer). The
operator runs this on a host they own and have put on the engagement's charter
allowlist; the scanner (via the engage runner's --oob-relay-url) then confirms
blind classes against remote targets. Polling is secret-gated — print/keep the
secret and pass it to the scanner.
"""

from __future__ import annotations

import argparse

from .collaborator import RelayServer


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m framework.v2 collaborator",
        description="Self-hostable out-of-band interaction relay (sovereign OOB collaborator).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve", help="Run the relay until interrupted.")
    serve.add_argument("--host", default="0.0.0.0",
                       help="Bind address (bind a public/allowlisted interface to reach it from a remote target).")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--secret", default=None,
                       help="Shared secret gating the poll endpoint (random if omitted).")
    serve.add_argument("--collector-keypair-file", default=None,
                       help="Path to a JSON keypair {\"private_key_b64\":..,\"public_key_b64\":..} for the "
                            "independent collector (VF-2b), so the pinned public key is STABLE across relay "
                            "restarts. Omit to mint a fresh keypair each run. The PUBLIC key is printed for "
                            "out-of-band distribution to the scanner; the private key is never printed.")
    serve.add_argument("--no-sign", action="store_true",
                       help="Run the relay WITHOUT a collector key (VF-2a token-only). A remote scanner then "
                            "refuses it (remote OOB requires a VF-2b pin); use only for a loopback/test relay.")
    args = parser.parse_args(argv)

    if args.cmd == "serve":
        # VF-2b: an INDEPENDENT collector keypair so every recorded interaction is signed into a receipt the
        # scanner's verifier checks against the PINNED collector pubkey. Mint one by default (or load a stable
        # keypair file so the pin survives restarts); print only the PUBLIC key, out-of-band, for the operator
        # to pin at the scanner. --no-sign drops to VF-2a (token-only), which a remote scanner refuses by design.
        import json as _json
        from vigil_core import KeyPair, generate_keypair
        collector_kp = None
        if not args.no_sign:
            if args.collector_keypair_file:
                with open(args.collector_keypair_file, encoding="utf-8") as fh:
                    kd = _json.load(fh)
                collector_kp = KeyPair(public_key_b64=str(kd["public_key_b64"]),
                                       private_key_b64=str(kd["private_key_b64"]))
            else:
                collector_kp = generate_keypair()
        relay = RelayServer(host=args.host, port=args.port, secret=args.secret,
                            collector_keypair=collector_kp)
        relay.start()
        # X6: this stdlib relay serves plain HTTP. For a REMOTE bind, front it with a TLS reverse
        # proxy and give the scanner the https:// URL — the scanner REFUSES a non-loopback http://
        # relay (the poll secret + hits must not cross the network in the clear). The poll secret
        # goes in the X-Relay-Key HEADER, never a ?key= query (which lands in access logs).
        _scheme = "http" if args.host in ("127.0.0.1", "localhost", "::1") else "https (front with TLS)"
        print("CRUCIBLE OOB relay")
        print(f"  bound     : http://{args.host}:{relay.port}  (serve URL to scanner as: {_scheme})")
        print(f"  secret    : {relay.secret}")
        if relay.collector_pubkey:
            # VF-2b: distribute this PUBLIC key out-of-band; the scanner PINS it (charter oob_collector_pubkey
            # / --oob-collector-pubkey) so a compromised relay handing over its own key cannot defeat the pin.
            print(f"  collector : {relay.collector_pubkey}   (VF-2b: pin this at the scanner OUT-OF-BAND)")
        else:
            print("  collector : (none — VF-2a token-only; a REMOTE scanner will refuse this relay)")
        print(f"  callbacks : {_scheme}://<this-host>:{relay.port}/<token>")
        print(f"  poll      : GET {_scheme}://<this-host>:{relay.port}/_poll/<token>")
        print(f"              header  X-Relay-Key: <secret>")
        print("  (put this host on the engagement charter allowlist; Ctrl-C to stop)")
        relay.serve_forever()
        return 0
    return 2
