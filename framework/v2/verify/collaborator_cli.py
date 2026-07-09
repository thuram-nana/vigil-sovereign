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
    args = parser.parse_args(argv)

    if args.cmd == "serve":
        relay = RelayServer(host=args.host, port=args.port, secret=args.secret)
        relay.start()
        # X6: this stdlib relay serves plain HTTP. For a REMOTE bind, front it with a TLS reverse
        # proxy and give the scanner the https:// URL — the scanner REFUSES a non-loopback http://
        # relay (the poll secret + hits must not cross the network in the clear). The poll secret
        # goes in the X-Relay-Key HEADER, never a ?key= query (which lands in access logs).
        _scheme = "http" if args.host in ("127.0.0.1", "localhost", "::1") else "https (front with TLS)"
        print("CRUCIBLE OOB relay")
        print(f"  bound     : http://{args.host}:{relay.port}  (serve URL to scanner as: {_scheme})")
        print(f"  secret    : {relay.secret}")
        print(f"  callbacks : {_scheme}://<this-host>:{relay.port}/<token>")
        print(f"  poll      : GET {_scheme}://<this-host>:{relay.port}/_poll/<token>")
        print(f"              header  X-Relay-Key: <secret>")
        print("  (put this host on the engagement charter allowlist; Ctrl-C to stop)")
        relay.serve_forever()
        return 0
    return 2
