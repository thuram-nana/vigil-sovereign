"""VIGIL public CVE catalog — a sovereign-side, OFFENSE-FREE subsystem for the public `/cve` pages.

CVE data (NVD, OSV, CISA-KEV, FIRST EPSS) is entirely PUBLIC, so the public catalog is built by its own
stdlib ingest and served read-only — it does NOT import the offense-plane intel parsers (that would breach
FATAL-2 and drag an offense dependency into the public path). The engine keeps its own engagement-scoped
intel; this catalog is the standing, browsable, public mirror.
"""
