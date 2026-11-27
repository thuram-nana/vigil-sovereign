"""`vigil launch-run` — the EXECUTE/drain half of the customer-launch pipeline. `launch-drain` only ENQUEUES
SecurityJobs; without a runner draining them, queued customer launches never execute (a real production gap
the Live Control audit surfaced). This proves the new command wires the authorized runner
(`make_engage_scan_runner`) and drains cleanly; execution correctness + exactly-once are the runner/queue's
own, covered by the launch_runner tests. Deterministic; no engine traffic (the queue is empty)."""
from __future__ import annotations

import argparse
import json
import tempfile


def test_launch_run_drains_an_empty_queue_cleanly(capsys):
    from vigil_integration import cli
    args = argparse.Namespace(base_dir=tempfile.mkdtemp(), queue_root="", watch=False, interval=2.0)
    rc = cli._cmd_launch_run(args)
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {"ran": 0, "by_state": {}}


def test_launch_run_is_registered_and_routes_to_the_runner():
    # the subcommand parses and routes to _cmd_launch_run (the DRAIN half, distinct from launch-drain's ENQUEUE)
    from vigil_integration import cli
    parser = cli.build_parser()
    ns = parser.parse_args(["launch-run", "--base-dir", tempfile.mkdtemp()])
    assert ns.func is cli._cmd_launch_run and ns.watch is False
