"""
sensors — the Universal Sensor/Producer framework (Wave 2).

CRUCIBLE is the reasoning OS; every tool is a SENSOR. A ``Sensor`` is a gated W1.4 ``Tool`` that also
knows how to NORMALIZE its output into the ONE evidence model: ``run_sensor`` gates it (kill-switch /
entitlement / scope / destructive / egress), then its ``normalize`` turns the raw output into
``intel.Observation``s that project into the shared world-model as provenance-labelled facts
(``GROUNDING_INTEL``) — never oracle-proof until a deterministic oracle re-verifies them.

Wave 2.1 ships the framework + a safe reference producer (``DeclaredServiceSensor``, the first
HOST/SERVICE/HOSTS minter). Wave 2.2 adds the ``NmapServiceSensor`` (the first mature external engine
driven as a gated sensor); Wave 2.3 the service-reachability oracle. Wave 4a wraps the Nuclei/ZAP/Burp
parsers as gated WEB-SCANNER sensors (``web_scanner``) that mint findings as third-party LEADS which
a CRUCIBLE oracle re-verifies.
"""

from __future__ import annotations

from .base import Sensor, SensorResult, service_observations
from .builtin import DeclaredServiceSensor, default_registry, register_builtin_sensors
from .cloud import (
    CloudInventoryPullSensor,
    CloudPostureImportSensor,
    cloud_observations,
    cloud_posture_leads,
    confirm_cloud_posture_facts,
    confirm_cloud_privilege_path,
    normalize_cloud_export,
)
from .cicd import WorkflowScanSensor, cicd_control_observations, parse_workflows
from .tls_cert import CertScanSensor, cert_control_observations, parse_certs
from .android_manifest import AndroidManifestSensor, parse_android_manifest
from .mesh import MeshConfigSensor, mesh_control_observations, parse_mesh
from .email_auth import EmailAuthSensor, email_auth_observations, parse_email_auth_export
from .k8s_runtime import KubeBenchSensor, kube_bench_observations, parse_kube_bench
from .fuzz import FuzzHarnessSensor, confirm_crash, default_fuzz_cases
from .nmap import NmapServiceSensor, parse_nmap_xml
from .pipeline import run_sensor
from .sbom import SbomVulnSensor, parse_sca_report, sca_observations
from .tshark import TsharkFlowSensor, parse_tshark_fields
from .web_scanner import (
    BurpWebSensor,
    NucleiResultsImportSensor,
    NucleiTemplateSensor,
    NucleiWebSensor,
    WebLead,
    ZapWebSensor,
    confirm_web_lead,
    web_lead_from_finding,
    web_lead_observations,
    web_leads_from_findings,
)

__all__ = [
    "Sensor", "SensorResult", "service_observations",
    "run_sensor",
    "DeclaredServiceSensor", "default_registry", "register_builtin_sensors",
    "NmapServiceSensor", "parse_nmap_xml",
    # Workstream D.1 — gated fuzz/ASan robustness producer
    "FuzzHarnessSensor", "confirm_crash", "default_fuzz_cases",
    "TsharkFlowSensor", "parse_tshark_fields",
    # Wave 4a — web-scanner sensors
    "NucleiWebSensor", "NucleiTemplateSensor", "NucleiResultsImportSensor",
    "ZapWebSensor", "BurpWebSensor",
    "WebLead", "web_lead_observations", "web_lead_from_finding",
    "web_leads_from_findings", "confirm_web_lead",
    # Wave 5a — cloud / IAM / CSPM sensors
    "CloudPostureImportSensor", "CloudInventoryPullSensor",
    "cloud_observations", "cloud_posture_leads", "normalize_cloud_export",
    "confirm_cloud_privilege_path", "confirm_cloud_posture_facts",
    # Workstream C — Kubernetes-runtime posture sensor (kube-bench offline ingest -> CIS leads)
    "KubeBenchSensor", "parse_kube_bench", "kube_bench_observations",
    # CI/CD posture sensor (GitHub-Actions workflow offline ingest -> CI/CD control leads)
    "WorkflowScanSensor", "parse_workflows", "cicd_control_observations",
    # TLS/cert posture sensor (X.509 certificate offline ingest -> weak-crypto leads)
    "CertScanSensor", "parse_certs", "cert_control_observations",
    # Android-manifest posture sensor (decoded AndroidManifest.xml -> exported-component leads)
    "AndroidManifestSensor", "parse_android_manifest",
    # Service-mesh posture sensor (Istio/Linkerd config -> mesh-posture leads)
    "MeshConfigSensor", "parse_mesh", "mesh_control_observations",
    # Email-auth posture sensor (FORGE Domain 10: DNS policy export -> spoofing-posture leads)
    "EmailAuthSensor", "parse_email_auth_export", "email_auth_observations",
]
