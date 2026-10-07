"""The version-scan profile cannot acquire the host probe or NSE databases."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import nmap_runtime
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from test_secure_network_tools_runtime import manifest


def test_accepted_native_profiles_keep_their_exact_argv_environment_and_compiled_bytes():
    value = {tool: [exe, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
                   [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
             for tool, exe in runtime.EXECUTABLES.items() if tool not in (runtime.NMAP_SERVICE, runtime.KERBRUTE, runtime.REDIS, runtime.SNMP, runtime.POSTGRESQL_TLS, runtime.MYSQL_TLS, runtime.WHATWEB)}
    value["old_nmap"] = nmap_runtime.FIXED_ARGV
    assert len(value) == 13
    assert hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == (
        "606fffbdbd1ea73a955b9f815b2ff737ae84dfc6f3647586495e4aa21c87c294")


@pytest.mark.parametrize("executable", runtime.NMAP_SERVICE_EXECUTABLES)
def test_b7_accepts_only_a_pinned_distribution_elf_location(executable):
    value = manifest(runtime.NMAP_SERVICE)
    next(row for row in value["files"] if row["destination"] == "/tool/nmap")["source"] = executable
    assert runtime.validate_manifest(value) == value


@pytest.mark.parametrize("source", ["/tmp/nmap", "/usr/local/bin/nmap", "/bin/sh", "/usr/bin/curl",
                                   "/usr/share/nmap/scripts/script.db"])
def test_b7_rejects_wrappers_or_other_executable_sources_in_its_manifest(source):
    value = manifest(runtime.NMAP_SERVICE)
    next(row for row in value["files"] if row["destination"] == "/tool/nmap")["source"] = source
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("destination", ["/tool/data/nmap-services", "/tool/data/nmap-protocols",
    "/tool/data/nmap-service-probes", "/tool/data/nse_main.lua"])
@pytest.mark.parametrize("fault", ["missing", "source", "destination", "size", "sha256"])
def test_b7_compiled_probe_and_nse_bytes_cannot_be_replaced_or_omitted(destination, fault):
    value = manifest(runtime.NMAP_SERVICE)
    row = next(row for row in value["files"] if row["destination"] == destination)
    if fault == "missing":
        value["files"].remove(row)
    elif fault == "source":
        row["source"] = "/usr/share/nmap/" + Path(destination).name
    elif fault == "destination":
        row["destination"] = "/tool/data/scripts/script.db"
    elif fault == "size":
        row["size"] += 1
    else:
        row["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


@pytest.mark.parametrize("path", ["/usr/share/nmap/nselib/http.lua", "/tool/data/scripts/script.db",
    "/tool/data/scripts/http-enum.nse", "/tool/data/nse_main.lua.bak", "/etc/nmap/nmap-service-probes",
    "/etc/hosts", "/etc/resolv.conf", "/root/.nmap/nmap-services", "/tmp/krb5cc_1000"])
def test_b7_cannot_add_host_configuration_scripts_or_credentials(path):
    value = manifest(runtime.NMAP_SERVICE)
    value["files"].append({"source": path, "destination": path, "size": 4,
                           "sha256": hashlib.sha256(b"data").hexdigest()})
    value["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_b7_probe_database_and_native_arguments_cannot_request_unreviewed_operations():
    argv = runtime.FIXED_ARGV[runtime.NMAP_SERVICE]
    assert argv == ("/tool/nmap", "--unprivileged", "-sT", "-sV", "--version-intensity", "0",
        "-Pn", "-n", "-p", "8080", "--max-retries", "0", "--max-parallelism", "1",
        "--host-timeout", "3s", "--datadir", "/tool/data", "--no-stylesheet", "-oX", "-", "127.0.0.1")
    probes = runtime.NMAP_SERVICE_PROBES
    assert [line for line in probes.splitlines() if line.startswith(b"Probe ")] == [
        b"Probe TCP NULL q||", b"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|"]
    assert b"sslports" not in probes and b"softmatch " not in probes and b"fallback " not in probes
    assert b"totalwaitms 400\n" in probes and b"tcpwrappedms 100\n" in probes
    assert b"totalwaitms 700\n" in probes
    assert b"p/OpenSSH/" in probes and b"p/nginx/" in probes and b"p/Apache httpd/" in probes
    assert runtime.NMAP_SERVICE_SERVICES == b"unknown 8080/tcp 1.0\n"
    assert runtime.NMAP_SERVICE_PROTOCOLS == b"tcp 6 TCP\n"
    assert set(runtime.execution_environment(runtime.NMAP_SERVICE)) == {"LC_ALL", "OPENSSL_CONF", "MALLOC_ARENA_MAX"}


def test_b7_nse_shim_has_no_loading_io_or_script_dispatch():
    shim = runtime.NMAP_SERVICE_NSE_SHIM
    assert b"engine.scriptversion == true" in shim and b"next(rules) == nil" in shim
    assert b"engine.default == false" in shim and b"engine.scriptupdatedb == false" in shim
    assert b"engine.scriptargs == ''" in shim and b"engine.scriptargsfile == nil" in shim
    assert b"#hosts <= 1" in shim and b"phase == 'NSE_SCAN'" in shim
    for forbidden in (b"require", b"load", b"dofile", b"io.", b"os.", b"debug.", b"engine.fetch", b"engine.port"):
        assert forbidden not in shim


def test_b7_snapshot_stages_all_four_compiled_files_and_no_host_database(monkeypatch):
    value, seen = manifest(runtime.NMAP_SERVICE), []
    def stage(selected, source, raw, control, **kwargs):
        seen.append((selected, source, raw, kwargs))
        return [1, 2, 3, 4, 5, 6]
    monkeypatch.setattr(runtime, "sealed_snapshots", stage)
    assert runtime._snapshot(value, object()) == [1, 2, 3, 4, 5, 6]
    selected, source, raw, kwargs = seen.pop()
    assert selected == value
    assert source == "compiled:nmap-service-services" and raw == runtime.NMAP_SERVICE_SERVICES
    assert kwargs["additional_compiled"] == tuple((source, raw) for source, _, raw in runtime.compiled_files(runtime.NMAP_SERVICE)[1:])
    mounts = runtime.runtime_source_mounts(value)
    assert not any("compiled:" in source or "/usr/share/nmap" in source for source, _ in mounts)


def test_b7_keeps_no_child_processes_and_read_only_finite_data(monkeypatch):
    calls = []
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kwargs: calls.append(kwargs))
    worker.syscall_filter(runtime.NMAP_SERVICE)
    assert calls == [{"allow_threads": False}]
    permissions = worker._landlock_permissions(manifest(runtime.NMAP_SERVICE))
    for _, destination, _ in runtime.compiled_files(runtime.NMAP_SERVICE):
        assert permissions[destination] == 4
    assert permissions["/tool/data"] == 8
    assert permissions["/tool/nmap"] == 5


def inspect_fake(monkeypatch, candidates, resolved=None):
    files = {**candidates, "/usr/lib/ld-linux.so.2": b"loader", "/usr/lib/libc.so.6": b"library"}
    calls = []
    class FakePath:
        def __init__(self, path):
            self.path = path
        def is_file(self):
            return self.path in files
        def resolve(self, strict):
            assert strict
            return FakePath((resolved or {}).get(self.path, self.path))
        def __str__(self):
            return self.path
    monkeypatch.setattr(runtime, "Path", FakePath)
    monkeypatch.setattr(runtime, "_read_regular", lambda path: files[path])
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    def probe(argv, *args):
        calls.append(argv)
        return b"/usr/lib/ld-linux.so.2 (0x1)\nlibc.so.6 => /usr/lib/libc.so.6 (0x2)\n"
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    result = runtime.inspect_tool_runtime(runtime.NMAP_SERVICE, SimpleNamespace(check=lambda: None))
    return result, calls


@pytest.mark.parametrize("candidates,selected", [
    ({"/usr/bin/nmap": b"\x7fELFdirect", "/usr/lib/nmap/nmap": b"\x7fELFother"}, "/usr/bin/nmap"),
    ({"/usr/bin/nmap": b"#!/bin/sh\nexec other", "/usr/lib/nmap/nmap": b"\x7fELFactual"}, "/usr/lib/nmap/nmap"),
    ({"/usr/lib/nmap/nmap": b"\x7fELFactual"}, "/usr/lib/nmap/nmap"),
])
def test_b7_inspects_only_selected_elf_without_executing_distribution_wrapper(monkeypatch, candidates, selected):
    value, calls = inspect_fake(monkeypatch, candidates)
    assert calls == [["/usr/bin/ldd", selected]]
    executable = next(row for row in value["files"] if row["destination"] == "/tool/nmap")
    assert executable["source"] == selected
    assert executable["sha256"] == hashlib.sha256(candidates[selected]).hexdigest()


@pytest.mark.parametrize("candidates", [{}, {"/usr/bin/nmap": b"#!/bin/sh\nexit 0"},
    {"/usr/bin/nmap": b"wrapper", "/usr/lib/nmap/nmap": b"other wrapper"}])
def test_b7_fails_closed_if_no_reviewed_native_elf_exists(monkeypatch, candidates):
    with pytest.raises(IsolationUnavailable, match="ELF"):
        inspect_fake(monkeypatch, candidates)


def test_b7_cannot_resolve_distribution_name_to_an_unreviewed_location(monkeypatch):
    with pytest.raises(IsolationUnavailable, match="location"):
        inspect_fake(monkeypatch, {"/usr/bin/nmap": b"\x7fELFdata"}, {"/usr/bin/nmap": "/tmp/nmap"})
