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

from .config import GatewayConfig
from .docker import SandboxNetworking


def _configure_logging(verbose: bool) -> None:
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
    rc.add_argument("--gateway-image", default="vigil-gateway:latest")
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

    config = GatewayConfig.from_env()

    if args.command == "serve-proxy":
        host = args.host or config.proxy_host
        port = args.port or config.proxy_port
        try:
            return asyncio.run(_serve(config, host, port))
        except KeyboardInterrupt:
            return 0
    if args.command == "render-firewall":
        print(config.firewall().render())
        return 0
    if args.command == "check-firewall":
        config.firewall().check()
        print("nft --check OK")
        return 0
    if args.command == "apply-firewall":
        config.firewall().apply()
        print("firewall applied")
        return 0

    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
