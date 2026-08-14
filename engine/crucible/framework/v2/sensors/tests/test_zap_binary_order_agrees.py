"""Every place that resolves the ZAP binary must agree on the ORDER it tries names in.

THE DEFECT THIS PINS. ZAP installs under several names — ``zaproxy`` (the Kali package launcher),
``zap.sh`` (the upstream shell wrapper) and ``zap-cli``. Three separate places in the engine walk a
list of those names and take the first that resolves on PATH:

  * the tool registry's ``zaproxy`` entry            — ``tools/registry.py`` (binary + alt_binaries)
  * the web-scanner sensor                           — ``sensors/web_scanner.py`` (_ZAP_BINARIES)
  * the eval/benchmark adapter                        — ``eval/adapters.py`` (ZapAdapter)

If those lists DISAGREE, then on a host that carries two of the names the sensor and the adapter spawn
DIFFERENT programs for the same nominal tool — a silent, host-dependent split. That is exactly what had
happened: the adapter still listed ``zap.sh`` first while the sensor (correctly) listed ``zaproxy``
first. The registry is the single source of truth; the other two now DERIVE from it via
``binary_resolution_order``. This test is the guard that keeps them from drifting apart again.

Pure construction: it reads three module constants and compares them. No ZAP, no subprocess, no packet.
"""

from __future__ import annotations

from framework.v2.tools.registry import binary_resolution_order


def test_the_registry_defines_zap_in_the_expected_order():
    """The canonical order is the registry's, and it is ``zaproxy`` first. Pinning the literal here
    (not just 'they all match') means a change to the registry's order is a deliberate, reviewed edit
    rather than something the other two silently follow off a cliff."""
    assert binary_resolution_order("zaproxy") == ("zaproxy", "zap.sh", "zap-cli")


def test_the_sensor_resolves_zap_in_the_registry_order():
    from framework.v2.sensors import web_scanner
    assert web_scanner._ZAP_BINARIES == binary_resolution_order("zaproxy"), (
        "the web-scanner sensor's ZAP binary order has drifted from the registry — on a host with "
        "more than one ZAP name installed it would spawn a different program than the catalogue reports"
    )


def test_the_eval_adapter_resolves_zap_in_the_registry_order():
    from framework.v2.eval.adapters import ZapAdapter
    # The adapter takes its order from the registry at construction; assert the constructed default,
    # not a class attribute, because that is what actually decides which binary a benchmark run spawns.
    assert ZapAdapter()._binaries == binary_resolution_order("zaproxy"), (
        "the eval ZAP adapter's binary order has drifted from the registry — this was the live bug: "
        "the adapter resolved zap.sh before zaproxy while the sensor resolved zaproxy first"
    )


def test_all_three_zap_binary_sites_agree():
    """The property that actually matters, stated directly: whatever the order is, all three sites use
    the SAME one. This is the mutation control — revert any single site to its own hardcoded tuple and
    this fails while the per-site tests above still describe which one broke."""
    from framework.v2.eval.adapters import ZapAdapter
    from framework.v2.sensors import web_scanner
    registry = binary_resolution_order("zaproxy")
    assert web_scanner._ZAP_BINARIES == registry == ZapAdapter()._binaries
