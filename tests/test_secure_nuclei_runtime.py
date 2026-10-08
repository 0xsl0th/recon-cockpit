"""Portable checks for the separate pinned static runtime and scratch boundary.

Kernel witnesses remain native acceptance gates; these tests never invoke Nuclei.
"""

from copy import deepcopy
import fcntl
import hashlib
import io
import json
import os
import resource
import stat
import struct
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_nuclei_runtime as nuclei
from recon_cockpit.secure_agent import network_tools_nuclei_worker as worker
from recon_cockpit.secure_agent import network_tools_runtime as shared
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


def control():
    return ExecutionControl(time.monotonic() + 20)


def elf(*kinds):
    value = bytearray(4096)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", value, 16, 2, 62, 1)
    struct.pack_into("<Q", value, 32, 64)
    struct.pack_into("<HHH", value, 52, 64, 56, len(kinds))
    for index, kind in enumerate(kinds):
        struct.pack_into("<I", value, 64 + 56 * index, kind)
    return bytes(value)


def provision(tmp_path, monkeypatch, raw=None):
    raw = elf(1) if raw is None else raw
    path = tmp_path / "pinned-static-elf"
    path.write_bytes(raw)
    monkeypatch.setattr(nuclei, "EXECUTABLE", str(path))
    monkeypatch.setattr(nuclei, "EXECUTABLE_SIZE", len(raw))
    monkeypatch.setattr(nuclei, "EXECUTABLE_SHA256", hashlib.sha256(raw).hexdigest())
    return path, nuclei.manifest()


def test_static_profile_is_exact_separate_and_does_not_raise_shared_limits():
    value = nuclei.manifest()
    assert shared.validate_manifest(value, tool_id=shared.NUCLEI) == value
    assert "interpreter" not in value
    assert nuclei.EXECUTABLE_SIZE == 143294626
    assert nuclei.EXECUTABLE_SHA256 == "c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251"
    assert nuclei.MAX_FILE_BYTES == 160 * 1024 * 1024
    assert nuclei.MAX_RUNTIME_BYTES == 192 * 1024 * 1024
    assert shared.MAX_FILE_BYTES == 16 * 1024 * 1024
    assert shared.MAX_RUNTIME_BYTES == 64 * 1024 * 1024
    assert all("ld-linux" not in str(row) for row in value["files"])
    assert len(value["files"]) == 8


def test_all_pre_certificate_runtime_bytes_remain_unchanged():
    # Independent digest recorded at merged PR68, also retained by the C15 tests.
    selected = {tool: [executable, shared.FIXED_ARGV[tool], shared.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in shared.compiled_files(tool)]]
        for tool, executable in shared.EXECUTABLES.items() if tool not in (shared.NUCLEI, shared.TLS_CERTIFICATE)}
    assert len(selected) == 30
    assert hashlib.sha256(shared.encode(selected)).hexdigest() == (
        "e95562a6d07d64a67e31a2fc621da7101e3132343012c850d5c1ae474d6dc655")


@pytest.mark.parametrize("fault", ["profile", "tool", "interpreter", "source", "destination",
    "size", "boolean_size", "hash", "extra", "missing", "reordered", "cross_tool"])
def test_static_manifest_rejects_freshly_committed_mutations(fault):
    value = nuclei.manifest()
    binary = next(row for row in value["files"] if row["destination"] == nuclei.DESTINATION)
    selected = shared.NUCLEI
    if fault == "profile": value["profile"] = shared.PROFILE
    elif fault == "tool": value["tool_id"] = shared.TLS_CERTIFICATE
    elif fault == "interpreter": value["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
    elif fault == "source": binary["source"] = "/tmp/nuclei"
    elif fault == "destination": binary["destination"] = "/tool/other"
    elif fault == "size": binary["size"] += 1
    elif fault == "boolean_size": binary["size"] = True
    elif fault == "hash": binary["sha256"] = "a" * 64
    elif fault == "extra": value["files"].append(deepcopy(binary))
    elif fault == "missing": value["files"].pop()
    elif fault == "reordered": value["files"].reverse()
    else: selected = shared.TLS_CERTIFICATE
    with pytest.raises(ValueError):
        shared.validate_manifest(value, tool_id=selected)


@pytest.mark.parametrize("kinds", [(2,), (3,), (1, 2), (1, 3), (4,), ()])
def test_static_elf_rejects_loader_dynamic_and_missing_load_headers(kinds):
    with pytest.raises(IsolationUnavailable):
        nuclei.validate_elf(elf(*kinds))


@pytest.mark.parametrize("fault", ["class", "endian", "arch", "shared", "offset", "width", "count", "short"])
def test_static_elf_rejects_wrong_architecture_and_unbounded_headers(fault):
    value = bytearray(elf(1))
    if fault == "class": value[4] = 1
    elif fault == "endian": value[5] = 2
    elif fault == "arch": struct.pack_into("<H", value, 18, 183)
    elif fault == "shared": struct.pack_into("<H", value, 16, 3)
    elif fault == "offset": struct.pack_into("<Q", value, 32, 4096)
    elif fault == "width": struct.pack_into("<H", value, 54, 64)
    elif fault == "count": struct.pack_into("<H", value, 56, 33)
    else: value = value[:63]
    with pytest.raises(IsolationUnavailable):
        nuclei.validate_elf(bytes(value))


@pytest.mark.skipif(not hasattr(os, "memfd_create") or not hasattr(fcntl, "F_GET_SEALS"),
                   reason="requires Linux memfd sealing")
def test_streamed_snapshots_are_exact_sealed_and_do_not_call_native(tmp_path, monkeypatch):
    path, value = provision(tmp_path, monkeypatch, elf(1) + b"x" * (2 * nuclei.CHUNK_BYTES))
    reads, original_read = [], nuclei.os.read
    def read(fd, maximum):
        reads.append(maximum)
        return original_read(fd, maximum)
    monkeypatch.setattr(nuclei.os, "read", read)
    assert nuclei.inspect_runtime(control()) == value
    descriptors = nuclei.snapshot(value, control())
    try:
        assert max(reads) <= nuclei.CHUNK_BYTES
        for row, descriptor in zip(value["files"], descriptors):
            assert os.fstat(descriptor).st_size == row["size"]
            assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == (
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            with pytest.raises(OSError, match="Operation not permitted"):
                os.write(descriptor, b"x")
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@pytest.mark.parametrize("fault", ["changed", "truncated", "symlink", "capability"])
def test_streamed_runtime_refuses_unpinned_files(tmp_path, monkeypatch, fault):
    path, value = provision(tmp_path, monkeypatch)
    if fault == "changed": path.write_bytes(b"X" + path.read_bytes()[1:])
    elif fault == "truncated": path.write_bytes(b"X")
    elif fault == "symlink":
        replacement = tmp_path / "replacement"
        path.rename(replacement)
        path.symlink_to(replacement)
    else: monkeypatch.setattr(nuclei.os, "listxattr", lambda _: ["security.capability"])
    with pytest.raises((IsolationUnavailable, OSError)):
        nuclei.inspect_runtime(control())


@pytest.mark.skipif(not hasattr(os, "memfd_create") or not hasattr(fcntl, "F_GET_SEALS"),
                   reason="requires Linux memfd sealing")
def test_streaming_deadline_interrupts_and_closes_all_snapshots(tmp_path, monkeypatch):
    _, value = provision(tmp_path, monkeypatch, elf(1) + b"x" * (2 * nuclei.CHUNK_BYTES))
    descriptors, create = [], nuclei.os.memfd_create
    def track(*args):
        descriptor = create(*args)
        descriptors.append(descriptor)
        return descriptor
    monkeypatch.setattr(nuclei.os, "memfd_create", track)
    class Stopped:
        checks = 0
        def check(self):
            self.checks += 1
            if self.checks >= 12:
                raise RuntimeError("authority_deadline")
    with pytest.raises(RuntimeError, match="authority_deadline"):
        nuclei.snapshot(value, Stopped())
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_native_environment_and_command_are_closed(monkeypatch):
    for name in ("HOME", "NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR", "HTTP_PROXY", "HTTPS_PROXY",
                 "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "GITLAB_TOKEN", "LD_PRELOAD", "TMPDIR"):
        monkeypatch.setenv(name, "/injected/credential")
    env = shared.execution_environment(shared.NUCLEI)
    assert env == nuclei.ENVIRONMENT
    assert sum(name.startswith("DISABLE_NUCLEI_TEMPLATES_") for name in env) == 5
    assert all(value == "true" for name, value in env.items() if name.startswith("DISABLE_"))
    assert env["GOMAXPROCS"] == "1" and env["GOMEMLIMIT"] == "64MiB"
    assert "/injected/credential" not in env.values()
    argv = shared.FIXED_ARGV[shared.NUCLEI]
    assert argv == nuclei.FIXED_ARGV
    assert argv[argv.index("-u") + 1] == "http://127.0.0.1:8080/public/"
    assert {"-duc", "-ni", "-dr", "-no-httpx", "-no-stdin", "-matcher-status", "-omit-template"} <= set(argv)
    assert argv[argv.index("-retries") + 1] == "0"
    assert all(argv[argv.index(flag) + 1] == "1" for flag in ("-c", "-pc", "-prc", "-tlc", "-jsc", "-bs", "-rl"))
    assert not {"-code", "-headless", "-file", "-output", "-proxy", "-dashboard-upload", "-report-config"} & set(argv)
    assert b"redirects: false" in nuclei.TEMPLATE
    assert nuclei.TEMPLATE.count(b"method: GET") == 1


def test_worker_command_uses_only_static_snapshots_and_private_setup_capability(monkeypatch):
    monkeypatch.setattr(nuclei, "_trusted_program", lambda name: "/usr/bin/" + name)
    value = nuclei.manifest()
    argv = shared._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3"),
          (nuclei.EXECUTABLE, nuclei.EXECUTABLE), ("/usr/bin/bwrap", "/usr/bin/bwrap")]),
        value, list(range(20, 20 + len(value["files"]))), "a" * 64, "b" * 64)
    assert nuclei.EXECUTABLE not in argv
    assert argv.count("--ro-bind-data") == len(value["files"])
    assert "CAP_SYS_ADMIN" in argv and "CAP_SETPCAP" in argv
    assert not {"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "--share-net", "--bind"} & set(argv)
    assert "--unshare-user" in argv and "--clearenv" in argv
    assert "/app/recon_cockpit/secure_agent/network_tools_nuclei_worker.py" in argv
    assert all("ld-linux" not in arg for arg in argv)
    with pytest.raises(ValueError):
        nuclei.command(SimpleNamespace(), ("stdlib", []), value, [], "a", "b")


def test_landlock_only_allows_writes_to_nonexecutable_scratch():
    permissions = worker.landlock_permissions(nuclei.manifest())
    write_rights = 2 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 2048 | 4096 | 8192 | 16384
    assert [path for path, rights in permissions.items() if rights & write_rights] == ["/scratch"]
    assert permissions["/scratch"] & 1 == 0
    assert permissions["/scratch"] & (64 | 512 | 1024 | 2048 | 4096) == 0
    assert [path for path, rights in permissions.items() if rights & 1] == ["/tool/nuclei"]
    assert not any(path.startswith(("/home", "/root", "/app", "/usr/bin")) for path in permissions)


def test_native_resource_caps_are_profile_specific_and_never_raise_inherited_hard_limits(monkeypatch):
    limits = {}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda key, value: limits.update({key: value}))
    worker._limits()
    assert limits == {resource.RLIMIT_AS: (2 * 1024 * 1024 * 1024,) * 2,
        resource.RLIMIT_CPU: (5, 5), resource.RLIMIT_NOFILE: (64, 64), resource.RLIMIT_NPROC: (16, 16),
        resource.RLIMIT_CORE: (0, 0), resource.RLIMIT_FSIZE: (65536, 65536)}
    monkeypatch.setattr(worker.resource, "getrlimit", lambda _: (2, 2))
    worker._limits()
    assert set(limits.values()) == {(0, 0), (2, 2)}


@pytest.mark.parametrize("fault", [None, "noexec", "nosuid", "nodev", "readonly", "bytes", "inodes", "duplicate", "type"])
def test_scratch_mount_proof_requires_kernel_byte_inode_and_permission_limits(monkeypatch, fault):
    options = ["rw", "nosuid", "nodev", "noexec"]
    if fault in options: options.remove(fault)
    if fault == "readonly": options[0] = "ro"
    kind = "ext4" if fault == "type" else "tmpfs"
    line = f"1 2 0:1 / /scratch {','.join(options)} - {kind} tmpfs rw\n"
    monkeypatch.setattr(worker.Path, "read_text", lambda *_args, **_kwargs: line * (2 if fault == "duplicate" else 1))
    monkeypatch.setattr(worker.os, "statvfs", lambda _: SimpleNamespace(f_frsize=4096,
        f_blocks=nuclei.SCRATCH_BYTES // 4096 + (fault == "bytes"), f_files=128 + (fault == "inodes")))
    if fault is None:
        worker.verify_scratch_mount()
    else:
        with pytest.raises(ValueError, match="nuclei_scratch_kernel_limits"):
            worker.verify_scratch_mount()


@pytest.mark.parametrize("failure", [None, "verify_mounted", "mount_scratch", "scratch_allocation_witness",
    "seed_scratch", "_limits", "drop_privileges", "syscall_filter", "_witnesses",
    "_thread_bound_witness", "_metadata_transport_witness", "close_authority_descriptors",
    "apply_landlock", "scratch_execution_and_file_witness"])
def test_worker_emits_readiness_and_execs_only_after_every_boundary_proof(monkeypatch, failure):
    events = []
    value = nuclei.manifest()
    raw = json.dumps({"runtime": value}).encode()
    monkeypatch.setattr(worker.sys, "argv", ["worker", "a" * 64, "b" * 64])
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    monkeypatch.setattr(worker.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    monkeypatch.setattr(worker, "consume_launch", lambda *_: ({"tool_id": nuclei.TOOL_ID,
        "host_namespaces": {}}, time.monotonic() + 20, {}, shared.manifest_digest(value)))
    monkeypatch.setattr(worker, "assert_lab_namespaces", lambda *_: None)
    def event(name):
        def run(*_args, **_kwargs):
            events.append(name)
            if name == failure:
                raise ValueError("witness_failed")
        return run
    functions = [(nuclei, "verify_mounted"), (worker, "mount_scratch"),
        (worker, "scratch_allocation_witness"), (worker, "seed_scratch"), (worker, "_limits"),
        (worker.worker, "drop_privileges"), (worker.common, "syscall_filter"), (worker.common, "_witnesses"),
        (worker.common, "_thread_bound_witness"), (worker.shared_worker, "_metadata_transport_witness"),
        (worker, "close_authority_descriptors"), (worker.common, "apply_landlock"),
        (worker, "scratch_execution_and_file_witness")]
    for module, name in functions:
        monkeypatch.setattr(module, name, event(name))
    monkeypatch.setattr(worker.os, "write", event("ready"))
    class ExecReached(BaseException): pass
    def execute(path, argv, environment):
        assert (path, argv, environment) == (nuclei.DESTINATION, nuclei.FIXED_ARGV, nuclei.ENVIRONMENT)
        events.append("exec")
        raise ExecReached
    monkeypatch.setattr(worker.os, "execve", execute)
    if failure is None:
        with pytest.raises(ExecReached):
            worker.main()
        assert events == [name for _, name in functions] + ["ready", "exec"]
    else:
        assert worker.main() == 78
        assert events[-1] == failure and "ready" not in events and "exec" not in events
