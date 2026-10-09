"""Private fixed-program runtime; never executes Nmap on the host network."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from .execution import ExecutionControl
from .isolation import (IsolationUnavailable, _capture_bounded, _namespaces,
                        _runtime_files, _runtime_probe, _trusted_program)
from .nmap_parser import PARSER_VERSION


PROFILE = "nmap-tcp-connect-runtime-v1"
MAX_OUTPUT_BYTES = 16384
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
FIXED_ARGV = ("/tool/nmap", "--unprivileged", "-sT", "-Pn", "-n", "-p", "8080",
              "--max-retries", "0", "--max-parallelism", "1", "--host-timeout", "3s",
              "--datadir", "/tool/data", "--no-stylesheet", "-oX", "-", "127.0.0.1")
# Some distribution packages use a trailing version dot (liblinear.so.4.2.).
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
MODULES = ("nmap_worker", "nmap_execution", "nmap_runtime", "nmap_parser", "nmap_contract",
           "models", "worker", "execution", "isolation", "owned_lab_executor", "executor_worker",
           "owned_lab_contract", "assessment_contract", "session_limits", "tool_parameters", "tool_adapters")
READY_PREFIX = b"RECON_NMAP_READY_V1 "


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def manifest_digest(value):
    return hashlib.sha256(encode(validate_manifest(value))).hexdigest()


def validate_manifest(value):
    if (type(value) is not dict or set(value) != {"version", "profile", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE or value["executable"] != "/tool/nmap"
            or type(value["interpreter"]) is not str or not LIBRARY.fullmatch(value["interpreter"])
            or type(value["files"]) is not list or not 4 <= len(value["files"]) <= 128):
        raise ValueError("invalid_nmap_runtime_manifest")
    destinations, sources, total = set(), set(), 0
    for item in value["files"]:
        if (type(item) is not dict or set(item) != {"source", "destination", "sha256", "size"}
                or type(item["source"]) is not str or type(item["destination"]) is not str
                or type(item["size"]) is not int or not 1 <= item["size"] <= MAX_FILE_BYTES
                or type(item["sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                or any(".." in item[key] or "//" in item[key] for key in ("source", "destination"))):
            raise ValueError("invalid_nmap_runtime_file")
        source, destination = item["source"], item["destination"]
        if destination == "/tool/nmap":
            accepted = source in {"/usr/bin/nmap", "/usr/lib/nmap/nmap"}
        elif destination in {"/tool/data/nmap-services", "/tool/data/nmap-protocols"}:
            accepted = source == "/usr/share/nmap/" + destination.rsplit("/", 1)[1]
        else:
            accepted = bool(LIBRARY.fullmatch(source) and LIBRARY.fullmatch(destination))
        if not accepted or destination in destinations:
            raise ValueError("invalid_nmap_runtime_path")
        destinations.add(destination)
        sources.add(source)
        total += item["size"]
    if (total > MAX_RUNTIME_BYTES or not {"/tool/nmap", "/tool/data/nmap-services",
            "/tool/data/nmap-protocols", value["interpreter"]} <= destinations
            or value["files"] != sorted(value["files"], key=lambda item: item["destination"])):
        raise ValueError("invalid_nmap_runtime_closure")
    return value


def _read_regular(source):
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE_BYTES:
            raise IsolationUnavailable("Nmap runtime contains an invalid file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) != info.st_size:
            raise IsolationUnavailable("Nmap runtime changed during inspection")
        return raw
    finally:
        os.close(descriptor)


def inspect_nmap_runtime(control):
    """Inspect fixed distribution files only. No version command or scan runs."""
    control.check()
    executable = None
    for candidate in ("/usr/bin/nmap", "/usr/lib/nmap/nmap"):
        if Path(candidate).is_file():
            raw = _read_regular(str(Path(candidate).resolve(strict=True)))
            if raw.startswith(b"\x7fELF"):
                executable = str(Path(candidate).resolve(strict=True))
                break
    if executable not in {"/usr/bin/nmap", "/usr/lib/nmap/nmap"}:
        raise IsolationUnavailable("A supported distribution Nmap ELF is required; wrappers are refused")
    listing = _runtime_probe([_trusted_program("ldd"), executable], 3, 32768, control).decode("ascii")
    if "not found" in listing:
        raise IsolationUnavailable("Nmap has missing shared libraries")
    paths = sorted(set(re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", listing)))
    interpreters = [p for p in paths if re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?ld-linux[^/]*\.so\.[0-9]+", p)]
    if len(interpreters) != 1 or not paths or any(not LIBRARY.fullmatch(path) for path in paths):
        raise IsolationUnavailable("Unsupported Nmap dynamic runtime")
    entries = [(executable, "/tool/nmap")]
    entries += [(str(Path(path).resolve(strict=True)), path) for path in paths]
    entries += [("/usr/share/nmap/" + name, "/tool/data/" + name)
                for name in ("nmap-services", "nmap-protocols")]
    files = []
    for source, destination in sorted(entries, key=lambda pair: pair[1]):
        control.check()
        raw = _read_regular(source)
        files.append({"source": source, "destination": destination,
                      "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return validate_manifest({"version": "1", "profile": PROFILE, "executable": "/tool/nmap",
                              "interpreter": interpreters[0], "files": files})


def runtime_source_mounts(manifest):
    return [(path, path) for path in sorted({item["source"] for item in validate_manifest(manifest)["files"]})]


def _snapshot(manifest, control):
    """Sealed byte copies discard host file capabilities and close hash races."""
    import fcntl
    descriptors = []
    try:
        for item in validate_manifest(manifest)["files"]:
            control.check()
            raw = _read_regular(item["source"])
            if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise IsolationUnavailable("Nmap runtime differs from its pinned manifest")
            fd = os.memfd_create("recon-nmap-runtime", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptors
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise


_CLOSE_EXCEPT = """import os,sys
keep={int(v) for v in sys.argv[1].split(',')}
for name in os.listdir('/proc/self/fd'):
    if int(name)>2 and int(name) not in keep:
        try: os.close(int(name))
        except OSError as exc:
            if exc.errno != 9: raise
os.execv(sys.argv[2],sys.argv[2:])
"""


def _command(lab, bootstrap, manifest, descriptors, nonce, commitment, *, web=False, headers=False):
    stdlib, files = bootstrap
    tool_destinations = {item["destination"] for item in manifest["files"]}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "LC_ALL", "C", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if destination not in tool_destinations and Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in (*MODULES, *(('web_lab_contract', 'web_fixture') if web else ()),
                 *(('http_headers_lab_contract', 'http_headers_fixture') if headers else ())):
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    # All staged descriptors are consumed by Bubblewrap, not inherited by Nmap.
    for item, fd in zip(manifest["files"], descriptors):
        mode = "0555" if item["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(fd), item["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/nmap_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
            "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
            ",".join(map(str, descriptors)), *argv]


def _parse_isolated(raw, control, bootstrap):
    stdlib, files = bootstrap
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--die-with-parent", "--new-session", "--clearenv", "--setenv", "LC_ALL", "C",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev", "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    for name in ("nmap_parser", "nmap_parser_worker", "planner_worker"):
        argv += ["--ro-bind", str(Path(__file__).with_name(name + ".py")), "/app/" + name + ".py"]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/nmap_parser_worker.py", *_namespaces().values()]
    code, stdout, _, reason = _capture_bounded(argv, raw, min(2, control.remaining()), 1024, control=control)
    if code != 0 or reason is not None:
        raise ValueError("isolated_nmap_parser_refused")
    value = json.loads(stdout)
    if (type(value) is not dict or set(value) != {"parser_version", "results"}
            or value["parser_version"] != PARSER_VERSION or type(value["results"]) is not list
            or len(value["results"]) != 1 or type(value["results"][0]) is not dict):
        raise ValueError("invalid_nmap_parser_reply")
    row = value["results"][0]
    if (set(row) != {"target", "port", "state"} or row["target"] != "127.0.0.1"
            or type(row["port"]) is not int or row["port"] != 8080
            or type(row["state"]) is not str or row["state"] not in {"open", "closed", "filtered"}):
        raise ValueError("invalid_nmap_parser_reply")
    return value["results"]


def parse_isolated_xml(raw, *, deadline=None):
    """Read-only evidence revalidation; starts no lab, tool or provider.

    Runtime inspection gets at most eight seconds and the parser two, all
    bounded by the original session deadline when called during an assessment.
    Offline inspection may instead create its own short parser-only deadline.
    """
    if sys.platform != "linux" or os.geteuid() == 0:
        raise IsolationUnavailable("Nmap evidence parsing requires unprivileged Linux isolation")
    if type(raw) is not bytes or not raw or len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("invalid_nmap_xml_size")
    if deadline is not None:
        ExecutionControl(deadline).check()
    control = ExecutionControl(min(time.monotonic() + 10, deadline) if deadline is not None
                               else time.monotonic() + 10)
    bootstrap = _runtime_files("/usr/bin/python3", None, control=control)
    return _parse_isolated(raw, control, bootstrap)


def run_nmap_owned(*, lab, launch, control, closure=None):
    """Called only after root-owned admission; worker independently rechecks it."""
    if sys.platform != "linux" or type(control) is not ExecutionControl:
        raise IsolationUnavailable("Nmap execution requires Linux authority control")
    control.check()
    lab._check(control)
    lab._verify_pins()
    manifest = inspect_nmap_runtime(control) if closure is None else validate_manifest(closure["nmap_runtime"])
    bootstrap = lab._runtime(control) if closure is None else (
        closure["stdlib"], [(p, p) for p in closure["files"] if Path(p).name not in {"nft", "bwrap", "nsenter"}])
    launch = {**launch, "runtime": manifest}
    raw = encode(launch)
    if len(raw) > 65536:
        raise IsolationUnavailable("Nmap launch envelope exceeds its bound")
    commitment = hashlib.sha256(raw).hexdigest()
    nonce = launch["launch"]["nonce"]
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    descriptors = _snapshot(manifest, control)
    try:
        code, stdout, stderr, reason = _capture_bounded(
            _command(lab, bootstrap, manifest, descriptors, nonce, commitment,
                     **({'web': True} if launch['mode'] == 'owned_web_lab' else
                        {'headers': True} if launch['mode'] == 'owned_http_headers_lab' else {})), raw,
            min(5, control.remaining()), MAX_OUTPUT_BYTES + len(prefix), control=control,
            pass_fds=(*lab._namespace_fds, *descriptors))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    control.check()
    if not stderr.startswith(prefix):
        raise IsolationUnavailable("Nmap confinement was not verified; no host fallback")
    stderr = stderr[len(prefix):]
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        raise IsolationUnavailable("Nmap transport exceeded its fixed output ceiling")
    status = reason or ("succeeded" if code == 0 else "failed")
    rows = []
    if status == "succeeded":
        try:
            rows = _parse_isolated(stdout, control, bootstrap)
        except (ValueError, UnicodeError, RecursionError):
            status = "failed"
            reason = "invalid_xml"
    checks = dict.fromkeys(("forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
                           "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
                           "raw_sockets_blocked", "landlock_applied", "python_unreadable"), True)
    return {"status": status, "results": rows, "bytes_received": len(stdout) + len(stderr),
            "truncated": reason == "output_limit", "boundary_checks": checks,
            "raw_xml_base64": base64.b64encode(stdout).decode("ascii"),
            "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
            "provenance": {"runtime_sha256": manifest_digest(manifest), "runtime_manifest": manifest,
                           "xml_sha256": hashlib.sha256(stdout).hexdigest(),
                           "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "parser_version": PARSER_VERSION,
                           "exit_code": code, "stop_reason": reason}}
