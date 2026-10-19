"""One-second, networkless parser execution; isolation failure has no fallback."""

import os
import hashlib
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from . import name_tls_parser as parser
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _namespaces, _runtime_files, _trusted_program
from .planner_worker import BOUNDARY_NAMES
from . import name_tls_python_runtime as sources

MODULES = ("name_tls_wire", "name_tls_parser", "name_tls_parser_worker", "tls_posture_hello",
           "http_headers_parser", "planner_worker", "name_tls_worker_common", "name_tls_topology_spec")
SOURCE_MODULES = (*MODULES, *sources.PACKAGE_FILES)
READY = b"NAME_TLS_PARSER_READY_V1 "
FORBIDDEN = {"nft", "bwrap", "nsenter", "ip", "curl", "ffuf", "dig", "openssl", "ssh-keyscan",
             "ldapsearch", "smbclient", "rpcinfo", "showmount", "nmap", "kerbrute", "dnsmasq", "nginx"}


def _command(bootstrap, descriptors, info_fd):
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--as-pid-1", "--info-fd", str(info_fd),
            "--clearenv", "--setenv", "LC_ALL", "C", "--chdir", "/",
            "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in FORBIDDEN:
            argv += ["--ro-bind", source, destination]
    sources.mount_sources(argv, SOURCE_MODULES, descriptors)
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/", "/usr/bin/python3", "-I", "-S",
             "/app/recon_cockpit/secure_agent/name_tls_parser_worker.py", *_namespaces().values()]
    return argv


def _read_at(directory, name, maximum):
    descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
    try:
        raw = os.read(descriptor, maximum + 1)
        if len(raw) > maximum:
            raise ValueError("name_tls_parser_process_observation_limit")
        return raw.decode("ascii")
    finally:
        os.close(descriptor)


def _observe_process(pid, readiness):
    if type(pid) is not int or pid <= 0:
        raise ValueError("name_tls_parser_process_identity")
    descriptor = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        namespaces = {name: os.readlink("ns/" + name, dir_fd=descriptor) for name in ("user", "net", "mnt", "pid")}
        if namespaces != readiness["namespaces"] or any(namespaces[name] == value for name, value in _namespaces().items()):
            raise ValueError("name_tls_parser_namespace_mapping")
        mappings = {}
        for name, expected in (("uid", os.getuid()), ("gid", os.getgid())):
            mappings[name + "_map"] = [list(map(int, line.split())) for line in _read_at(descriptor, name + "_map", 1024).splitlines()]
            if expected <= 0 or mappings[name + "_map"] != [[65534, expected, 1]]:
                raise ValueError("name_tls_parser_host_mapping")
        fields = dict(line.split(":", 1) for line in _read_at(descriptor, "status", 8192).splitlines() if ":" in line)
        if (any(int(fields[name].strip(), 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                or fields["NoNewPrivs"].strip() != "1" or fields["Threads"].strip() != "1"):
            raise ValueError("name_tls_parser_process_boundary")
        fd_directory = os.open("fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=descriptor)
        try:
            if set(os.listdir(fd_directory)) != {"0", "1", "2"}:
                raise ValueError("name_tls_parser_retained_descriptor")
        finally:
            os.close(fd_directory)
        return {"payload_pid": pid, "namespaces": namespaces, **mappings, "retained_descriptors": [0, 1, 2],
                "capabilities_zero": True, "no_new_privs": True, "threads": 1}
    finally:
        os.close(descriptor)


def _readiness(raw):
    value = parser.load_json(raw, 2048)
    from .name_tls_topology_spec import validate_namespace_identity
    if (set(value) != {"parser_version", "boundary_checks", "identity", "namespaces", "runtime_absence_verified"}
            or value["parser_version"] != parser.PARSER_VERSION or value["runtime_absence_verified"] is not True
            or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
            or any(item is not True for item in value["boundary_checks"].values())
            or type(value["namespaces"]) is not dict or set(value["namespaces"]) != {"user", "net", "mnt", "pid"}):
        raise ValueError("name_tls_parser_readiness")
    validate_namespace_identity(value["identity"])
    return value


def _capture(argv, request, control, descriptors, info_read, info_write):
    """Inspect the actual waiting parser before releasing any untrusted bytes."""
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=(*descriptors.values(), info_write), start_new_session=True, bufsize=0,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    finally:
        os.close(info_write)
    ready, observed, info, pending = None, None, bytearray(), bytearray()
    stdout, stderr, offset = bytearray(), bytearray(), 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream, tag in ((process.stdout, "stdout"), (process.stderr, "stderr"), (info_read, "info")):
                descriptor = stream if type(stream) is int else stream.fileno()
                os.set_blocking(descriptor, False)
                selector.register(stream, selectors.EVENT_READ, tag)
            while selector.get_map():
                control.check()
                for key, _ in selector.select(min(.02, control.remaining())):
                    control.check()
                    if key.data == "stdin":
                        count = os.write(key.fd, request[offset:offset + 4096])
                        offset += count
                        if offset == len(request):
                            selector.unregister(process.stdin)
                            process.stdin.close()
                        continue
                    chunk = os.read(key.fd, 8193)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "info":
                        info.extend(chunk)
                        if len(info) > 4096:
                            raise ValueError("name_tls_parser_info_limit")
                    elif key.data == "stderr":
                        stderr.extend(chunk)
                    elif ready is None:
                        pending.extend(chunk)
                        if len(pending) > 4096:
                            raise ValueError("name_tls_parser_readiness_limit")
                        if b"\n" in pending:
                            line, tail = bytes(pending).split(b"\n", 1)
                            if not line.startswith(READY) or tail:
                                raise ValueError("name_tls_parser_readiness_order")
                            ready = _readiness(line[len(READY):])
                    else:
                        if observed is None:
                            raise ValueError("name_tls_parser_premature_result")
                        stdout.extend(chunk)
                    if len(stdout) + len(stderr) > parser.MAX_OUTPUT_BYTES:
                        raise ValueError("name_tls_parser_output_limit")
                if observed is None and ready is not None and info:
                    try:
                        value = parser.load_json(bytes(info), 4096)
                    except ValueError:
                        if len(info) >= 4096:
                            raise
                    else:
                        observed = _observe_process(value.get("child-pid"), ready)
                        os.set_blocking(process.stdin.fileno(), False)
                        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            control.check()
            process.wait(timeout=control.remaining())
        if ready is None or observed is None or offset != len(request) or process.returncode != 0 or stderr:
            raise ValueError("name_tls_parser_execution_incomplete")
        return bytes(stdout), {"readiness": ready, "parent_observation": observed,
            "wrapper_pid": process.pid, "exit_code": process.returncode, "input_sha256": hashlib.sha256(request).hexdigest(),
            "reply_sha256": hashlib.sha256(stdout).hexdigest(), "elapsed_ms": round((time.monotonic() - started) * 1000),
            "process_reaped": True}
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


def parse_isolated_operation(raw, *, deadline=None, control=None, closure=None, bundle=None, return_receipt=False):
    if type(raw) is not bytes or not 4 < len(raw) <= parser.MAX_INPUT_BYTES:
        raise ValueError("name_tls_parser_input_limit")
    if sys.platform != "linux" or (closure is None and os.geteuid() == 0):
        raise IsolationUnavailable("Name TLS parser requires unprivileged Linux isolation")
    if control is not None and type(control) is not ExecutionControl:
        raise ValueError("name_tls_parser_control")
    if type(return_receipt) is not bool:
        raise ValueError("name_tls_parser_receipt_option")
    clock = time.monotonic if control is None else control.clock
    bounds = [clock() + 1]
    if control is not None:
        control.check()
        bounds.append(control.deadline)
    if deadline is not None:
        ExecutionControl(deadline, clock=clock).check()
        bounds.append(deadline)
    bounded = ExecutionControl(min(bounds), None if control is None else control.cancelled, clock)
    if closure is None:
        bootstrap = _runtime_files("/usr/bin/python3", None, control=bounded)
    else:
        if (type(closure) is not dict or type(closure.get("stdlib")) is not str or not closure["stdlib"].startswith("/")
                or type(closure.get("files")) is not list or not closure["files"]):
            raise IsolationUnavailable("Name TLS parser closure invalid")
        files = []
        for item in closure["files"]:
            pair = (item, item) if type(item) is str else item
            if (type(pair) not in (list, tuple) or len(pair) != 2
                    or any(type(p) is not str or not p.startswith("/") or ".." in Path(p).parts for p in pair)):
                raise IsolationUnavailable("Name TLS parser closure invalid")
            files.append(pair)
        bootstrap = closure["stdlib"], files
    bounded.check()
    descriptors = sources.snapshot_sources(bundle, SOURCE_MODULES, bounded)
    info_read, info_write = os.pipe2(os.O_CLOEXEC)
    try:
        stdout, receipt = _capture(_command(bootstrap, descriptors, info_write), raw, bounded, descriptors, info_read, info_write)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise IsolationUnavailable("Name TLS parser isolation unavailable") from error
    finally:
        for descriptor in (*descriptors.values(), info_read):
            try:
                os.close(descriptor)
            except OSError:
                pass
    try:
        value = parser.load_json(stdout)
        if (set(value) != {"parser_version", "boundary_checks", "identity", "namespaces", "runtime_absence_verified", "status", "result"}
                or value["parser_version"] != parser.PARSER_VERSION or value["runtime_absence_verified"] is not True
                or type(value["boundary_checks"]) is not dict or set(value["boundary_checks"]) != BOUNDARY_NAMES
                or any(item is not True for item in value["boundary_checks"].values())
                or value["status"] not in ("parsed", "invalid")):
            raise ValueError("name_tls_parser_boundary_reply")
        if {key: value[key] for key in receipt["readiness"]} != receipt["readiness"]:
            raise ValueError("name_tls_parser_boundary_changed")
        if value["status"] == "parsed":
            result = parser.validate_result(value["result"])
            if result["input_sha256"] != hashlib.sha256(raw).hexdigest():
                raise ValueError("name_tls_parser_input_commitment")
            receipt["python_sources_sha256"] = sources.source_digest(bundle["python_sources"])
            return (result, receipt) if return_receipt else result
        if value["result"] is not None:
            raise ValueError("name_tls_parser_invalid_reply")
    except (ValueError, TypeError, RecursionError, KeyError):
        raise IsolationUnavailable("Name TLS parser reply invalid") from None
    raise ValueError("name_tls_invalid_native_observation")
