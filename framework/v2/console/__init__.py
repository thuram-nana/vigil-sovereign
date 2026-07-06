"""
framework.v2.console — the CRUCIBLE Ops Console.

A decoupled, read-only, loopback-only operator UI. It never touches the scan/engage
hot path: it READS the artifacts the framework already writes (reports, the memory
and authority stores, the world-model) and TAILS the append-only structured log
(`common.logging` JSONL) for the live view. Nothing in this package is imported by
the scanner or the engagement runner — if the console is down, every CLI path works
exactly as before. Stdlib-only (`http.server` + `sqlite3` + `urllib` + vanilla JS);
binds 127.0.0.1 only; issues zero outbound network calls.
"""
