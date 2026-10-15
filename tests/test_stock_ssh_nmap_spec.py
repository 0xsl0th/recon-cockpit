"""NULL-only stock SSH recognition retains observed versions without scope."""

import hashlib
from pathlib import Path
import re
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent import stock_http_production_nmap_spec as http
from recon_cockpit.secure_agent import stock_ssh_nmap_spec as spec
from recon_cockpit.secure_agent import stock_ssh_spec as selection


def test_compiled_payload_is_distinct_null_only_and_changes_no_other_file():
    old = native.compiled_files(native.NMAP_SERVICE)
    new = spec.compiled_files()
    assert [(a, b) for a, b in zip(old, new, strict=True) if a != b] == [(
        ("compiled:nmap-service-probes", spec.PROBE_DESTINATION, native.NMAP_SERVICE_PROBES),
        (spec.PROBE_SOURCE, spec.PROBE_DESTINATION, spec.PROBES))]
    assert [line for line in spec.PROBES.splitlines() if line.startswith(b"Probe ")] == [b"Probe TCP NULL q||"]
    assert b"GetRequest" not in spec.PROBES and b"GET " not in spec.PROBES
    assert b"fallback" not in spec.PROBES and b"sslports" not in spec.PROBES
    assert len({hashlib.sha256(raw).hexdigest() for raw in
                (spec.PROBES, native.NMAP_SERVICE_PROBES, http.PROBES)}) == 3


@pytest.mark.parametrize("version", [b"10.2p1", b"9.7p10", b"10.2", b"1", b"999.999.999p999"])
@pytest.mark.parametrize("comment", [b"", b" Owned-lab-B", b" " + selection.HOSTILE_ADDENDUM.encode(), b" " + b"x" * 200])
def test_only_the_observed_full_version_is_extracted(version, comment):
    raw = b"SSH-2.0-OpenSSH_" + version + comment + b"\r\n"
    match = re.fullmatch(spec.SSH_PATTERN, raw)
    assert match and match.groups() == (version,)
    assert len(raw) <= selection.budgets("O1")["max_response_bytes"]


@pytest.mark.parametrize("raw", [
    b"SSH-2.0-OpenSSH_10.2p\r\n", b"SSH-2.0-OpenSSH_10.2p1000\r\n",
    b"SSH-2.0-OpenSSH_10.2p1garbage\r\n", b"SSH-2.0-OpenSSH_10.2.1.2\r\n",
    b"SSH-2.0-OpenSSH_1000.2p1\r\n", b"SSH-2.0-OpenSSH_10.2p1\n",
    b"SSH-1.99-OpenSSH_10.2p1\r\n", b"SSH-2.0-other_10.2p1\r\n",
    b"prefix\r\nSSH-2.0-OpenSSH_10.2p1\r\n", b"SSH-2.0-OpenSSH_10.2p1\r\npayload",
    b"SSH-2.0-OpenSSH_10.2p1 \x00\r\n", b"SSH-2.0-OpenSSH_10.2p1 \x7f\r\n",
    b"SSH-2.0-OpenSSH_10.2p1 " + b"x" * 201 + b"\r\n",
])
def test_unrecognized_or_unbounded_identification_does_not_invent_version(raw):
    assert re.fullmatch(spec.SSH_PATTERN, raw) is None


def test_recognition_constants_import_without_runtime_dependencies():
    script = "import runpy,sys; runpy.run_path(sys.argv[1]); assert 'recon_cockpit.secure_agent.network_tools_runtime' not in sys.modules"
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(Path(spec.__file__).resolve())],
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
