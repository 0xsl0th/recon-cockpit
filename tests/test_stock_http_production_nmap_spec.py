"""Recognize observed Apache framing without changing probe traffic or old data."""

import hashlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as native
from recon_cockpit.secure_agent import stock_http_production_nmap_spec as spec

OLD_APACHE_PATTERN = (
    br"^HTTP/1\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\r\n"
    br"Server: Apache/([0-9]{1,3}(?:\.[0-9]{1,3}){0,2})\r\n"
)
STATUS = b"HTTP/1.1 200 OK\r\n"
DATE = b"Date: Wed, 14 Oct 2026 22:10:39 GMT\r\n"


def test_production_payload_only_changes_apache_recognition_not_any_probe():
    assert native.NMAP_SERVICE_PROBES.count(OLD_APACHE_PATTERN) == 1
    assert spec.PROBES == native.NMAP_SERVICE_PROBES.replace(OLD_APACHE_PATTERN, spec.APACHE_PATTERN)
    assert spec.PROBES.count(b"Probe TCP ") == 2
    assert [line for line in spec.PROBES.splitlines() if line.startswith(b"Probe ")] == [
        b"Probe TCP NULL q||", b"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|"]
    assert len(b"GET / HTTP/1.0\r\n\r\n") == 18
    assert hashlib.sha256(spec.PROBES).digest() != hashlib.sha256(native.NMAP_SERVICE_PROBES).digest()


def test_compiled_runtime_only_replaces_the_exact_probe_file():
    original = native.compiled_files(native.NMAP_SERVICE)
    production = spec.compiled_files()
    assert len(original) == len(production)
    changes = [(old, new) for old, new in zip(original, production, strict=True) if old != new]
    assert changes == [(("compiled:nmap-service-probes", spec.PROBE_DESTINATION, native.NMAP_SERVICE_PROBES),
                        (spec.PROBE_SOURCE, spec.PROBE_DESTINATION, spec.PROBES))]


@pytest.mark.parametrize("date", (b"", DATE))
@pytest.mark.parametrize("suffix", (b"", b" (Debian)", b" (Unix distro_1+2-3)"))
@pytest.mark.parametrize("version", (b"2.4.65", b"2.4.999", b"2"))
def test_fixed_probe_extracts_only_advertised_version(date, suffix, version):
    response = STATUS + date + b"Server: Apache/" + version + suffix + b"\r\nContent-Length: 1\r\n\r\nx"
    found = re.match(spec.APACHE_PATTERN, response)
    assert found is not None and found.groups() == (version,)


@pytest.mark.parametrize("response", [
    STATUS + DATE + b"Server: Apache\r\n",
    STATUS + DATE + b"Server: nginx/1.28.0\r\n",
    STATUS + DATE + DATE + b"Server: Apache/2.4.65 (Debian)\r\n",
    STATUS + b"Date: " + b"x" * 65 + b"\r\nServer: Apache/2.4.65\r\n",
    STATUS + b"Date: evil\x00\r\nServer: Apache/2.4.65\r\n",
    STATUS + b"Location: http://outside/\r\nServer: Apache/2.4.65\r\n",
    STATUS + b"Server: Apache/2.4.65 (" + b"x" * 65 + b")\r\n",
    STATUS + b"Server: Apache/2.4.65 (unclosed\r\n",
    STATUS + b"Server: Apache/2.4.65.1\r\n",
    STATUS + b"Server: Apache/2.4.1000\r\n",
    STATUS + b"Server: Apache/version\r\n",
    STATUS + b"Content-Length: 36\r\n\r\nServer: Apache/2.4.65 (Debian)\r\n",
    b"untrusted-prefix\r\n" + STATUS + b"Server: Apache/2.4.65\r\n",
])
def test_unrecognized_or_unbounded_metadata_does_not_invent_version(response):
    assert re.match(spec.APACHE_PATTERN, response) is None


def test_selection_constants_import_without_runtime_or_host_dependencies():
    path = Path(spec.__file__).resolve()
    script = "import runpy,sys; runpy.run_path(sys.argv[1]); assert 'recon_cockpit.secure_agent.network_tools_runtime' not in sys.modules"
    result = subprocess.run([sys.executable, "-I", "-S", "-c", script, str(path)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
