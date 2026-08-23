"""
cli — the ``vigil-gateway`` command.

Subcommands:
  serve-proxy       run the filtering forward proxy (L7 scope enforcement)
  render-firewall   print the nft ruleset for the sandbox network (L3/L4 deny-default)
  check-firewall    validate the ruleset with `nft --check` (no privilege needed)
  apply-firewall    load the ruleset with `nft -f` (needs CAP_NET_ADMIN)
  render-compose    print the docker-compose fragment for the locked-down topology
  ensure-networks   create the internal sandbox network + the egress network
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .config import GatewayConfig, firewall_from_env
from .docker import SandboxNetworking


def _configure_logging(verbose: bool) -> None:
    """Install the ONE shared structured-JSON + redaction handler (W6-5), governed by the single
    VIGIL_LOG_LEVEL (``-v`` forces DEBUG). ``vigil_core`` is co-installed in the offense environment the
    gateway runs in; the try/except keeps the gateway's zero-third-party-dependency startup robust — if
    the shared core is somehow unavailable it falls back to the stdlib basic config rather than failing to
    start the egress gate."""
    level = "DEBUG" if verbose else None
    try:
        from vigil_core.logging_setup import configure_logging as _shared_configure

        _shared_configure(level, handler_name="vigil-gateway", force=True)
    except Exception:  # noqa: BLE001 — never let logging setup stop the egress gate from starting
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s vigil-gateway %(levelname)s %(name)s: %(message)s",
        )


async def _serve(config: GatewayConfig, host: str, port: int) -> int:
    proxy = config.proxy()
    server = await proxy.serve(host, port)
    async with server:
        await server.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vigil-gateway", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("serve-proxy", help="run the filtering forward proxy")
    sp.add_argument("--host", default=None)
    sp.add_argument("--port", type=int, default=None)

    sub.add_parser("render-firewall", help="print the nft ruleset")
    sub.add_parser("check-firewall", help="validate the ruleset with nft --check")
    sub.add_parser("apply-firewall", help="load the ruleset with nft -f (needs privilege)")

    rc = sub.add_parser("render-compose", help="print the docker-compose fragment")
    # Default "" -> the content-addressed interpolation form (image: vigil-gateway:${VIGIL_GATEWAY_IMAGE_TAG
    # :-latest}); pass an explicit reference to pin the printed compose to a specific tag.
    rc.add_argument("--gateway-image", default="")
    rc.add_argument("--charter-slug", default="")
    sub.add_parser("ensure-networks", help="create the sandbox + egress docker networks")

    args = parser.parse_args(argv)
    _configure_logging(args.verbose)

    if args.command == "render-compose":
        print(SandboxNetworking().render_compose(gateway_image=args.gateway_image, charter_slug=args.charter_slug))
        return 0
    if args.command == "ensure-networks":
        SandboxNetworking().ensure_networks()
        print("networks ensured")
        return 0
    # The L3/L4 firewall is pure packet policy — it needs NO charter scope (only the L7 proxy does), so
    # these run without VIGIL_GATEWAY_CHARTER_SLUG. That is what lets the compose init service apply the
    # backstop automatically at gateway bring-up, before Strix starts.
    if args.command == "render-firewall":
        print(firewall_from_env().render())
        return 0
    if args.command == "check-firewall":
        firewall_from_env().check()
        print("nft --check OK")
        return 0
    if args.command == "apply-firewall":
        firewall_from_env().apply()
        print("firewall applied")
        return 0

    config = GatewayConfig.from_env()

    if args.command == "serve-proxy":
        host = args.host or config.proxy_host
        port = args.port or config.proxy_port
        try:
            return asyncio.run(_serve(config, host, port))
        except KeyboardInterrupt:
            return 0
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
