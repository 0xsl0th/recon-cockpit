"""Pinned DNS/TLS/SSH/LDAP executables for the disconnected single-action network lab.

Only reviewed executable, library and compiled fixture data bytes enter the
tool filesystem. Neither a proposal nor tool output chooses files or argv.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .tool_runtime_common import _read_regular, _CLOSE_EXCEPT, sealed_snapshots
from .execution import ExecutionControl
from .isolation import IsolationUnavailable, _capture_bounded, _runtime_probe, _trusted_program


PROFILE = "network-tools-runtime-v1"
DIG = "dig_dns_query_v1"
OPENSSL = "openssl_tls_handshake_v1"
SSH = "ssh_host_keys_v1"
LDAP = "ldap_rootdse_v1"
MAX_OUTPUT_BYTES = 8192
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 12288
READY_PREFIX = b"RECON_NETWORK_TOOL_READY_V1 "
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
EXECUTABLES = {DIG: "/usr/bin/dig", OPENSSL: "/usr/bin/openssl",
               SSH: "/usr/bin/ssh-keyscan", LDAP: "/usr/bin/ldapsearch"}
FIXED_ARGV = {
    DIG: ("/tool/dig", "-r", "-4", "@127.0.0.1", "-p", "8080", "harbordesk.test.", "A",
          "+tcp", "+norecurse", "+tries=1", "+time=2", "+nosearch", "+noedns",
          "+nobadcookie", "+noadflag", "+nocdflag", "+noall", "+comments", "+question",
          "+answer", "+additional", "+nocmd"),
    OPENSSL: ("/tool/openssl", "s_client", "-4", "-connect", "127.0.0.1:8080",
          "-servername", "harbordesk.test", "-verify_hostname", "harbordesk.test",
          "-verify_return_error", "-CAfile", "/tool/data/fixture-ca.pem", "-no-CApath", "-no-CAstore",
          "-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-brief", "-no_ign_eof"),
    SSH: ("/tool/ssh-keyscan", "-4", "-T", "2", "-p", "8080", "-t", "rsa", "127.0.0.1"),
    LDAP: ("/tool/ldapsearch", "-x", "-LLL", "-P", "3", "-H", "ldap://127.0.0.1:8080",
           "-s", "base", "-b", "", "-a", "never", "-l", "2", "-z", "1",
           "-o", "nettimeout=2", "-o", "ldif_wrap=no", "(objectClass=*)",
           "namingContexts", "supportedLDAPVersion", "supportedSASLMechanisms", "vendorName"),
}
MODULES = ("tool_runtime_common", "tool_worker_common", "network_tools_runtime", "network_tools_worker", "network_tools_execution", "network_tools_contract",
           "network_tools_lab_contract", "network_tools_fixture", "models", "worker", "execution",
           "isolation", "owned_lab_executor", "executor_worker", "owned_lab_contract",
           "assessment_contract", "tool_parameters", "tool_adapters")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def execution_environment(tool_id):
    if type(tool_id) is not str or tool_id not in EXECUTABLES:
        raise ValueError("unsupported_network_tool")
    value = {"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"}
    if tool_id == DIG:
        value["UV_THREADPOOL_SIZE"] = "1"
    if tool_id == LDAP:
        # Disable every system/user LDAP default before libldap initializes.
        value["LDAPNOINIT"] = "1"
    return value


def _compiled(tool_id):
    if tool_id == OPENSSL:
        from .network_tools_fixture import CA_PEM
        return "compiled:fixture-ca", "/tool/data/fixture-ca.pem", CA_PEM
    if tool_id == DIG:
        # No host resolver, search list, or user configuration enters the tool.
        return "compiled:resolver", "/etc/resolv.conf", b"# fixed TCP nameserver supplied by reviewed argv\n"
    if tool_id in (SSH, LDAP):
        return None  # These profiles need no configuration, credentials, or trust file.
    raise ValueError("unsupported_network_tool")


def validate_manifest(value, *, tool_id=None):
    if (type(value) is not dict or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE
            or type(value["tool_id"]) is not str or value["tool_id"] not in EXECUTABLES
            or (tool_id is not None and value["tool_id"] != tool_id)
            or value["executable"] != FIXED_ARGV[value["tool_id"]][0]
            or type(value["interpreter"]) is not str or not LIBRARY.fullmatch(value["interpreter"])
            or type(value["files"]) is not list
            or not (3 if value["tool_id"] in (DIG, OPENSSL) else 2) <= len(value["files"]) <= 48
            or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_network_tool_manifest")
    data = _compiled(value["tool_id"])
    source_name, destination_name, compiled = data if data is not None else (None, None, None)
    destinations, total = set(), 0
    for item in value["files"]:
        if (type(item) is not dict or set(item) != {"source", "destination", "sha256", "size"}
                or type(item["source"]) is not str or type(item["destination"]) is not str
                or type(item["size"]) is not int or not 1 <= item["size"] <= MAX_FILE_BYTES
                or type(item["sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                or any(".." in item[key] or "//" in item[key] for key in ("source", "destination"))):
            raise ValueError("invalid_network_tool_runtime_file")
        source, destination = item["source"], item["destination"]
        if destination == value["executable"]:
            accepted = source == EXECUTABLES[value["tool_id"]]
        elif data is not None and destination == destination_name:
            accepted = (source == source_name and item["size"] == len(compiled)
                        and item["sha256"] == hashlib.sha256(compiled).hexdigest())
        else:
            accepted = bool(LIBRARY.fullmatch(source) and LIBRARY.fullmatch(destination))
        if not accepted or destination in destinations:
            raise ValueError("invalid_network_tool_runtime_path")
        destinations.add(destination)
        total += item["size"]
    required = {value["executable"], value["interpreter"]} | ({destination_name} if data is not None else set())
    if (total > MAX_RUNTIME_BYTES or not required <= destinations
            or value["files"] != sorted(value["files"], key=lambda item: item["destination"])):
        raise ValueError("invalid_network_tool_runtime_closure")
    return value


def manifest_digest(value):
    return hashlib.sha256(encode(validate_manifest(value))).hexdigest()


def inspect_tool_runtime(tool_id, control):
    """Inspect the selected distribution ELF; never execute a tool on the host."""
    if type(tool_id) is not str or tool_id not in EXECUTABLES:
        raise ValueError("unsupported_network_tool")
    control.check()
    executable = EXECUTABLES[tool_id]
    if not _read_regular(executable).startswith(b"\x7fELF"):
        raise IsolationUnavailable("A distribution ELF network tool is required")
    listing = _runtime_probe([_trusted_program("ldd"), executable], 3, 32768, control).decode("ascii")
    paths = sorted(set(re.findall(r"(?:=>\s+)?(/[^\s]+)\s+\(", listing)))
    interpreters = [p for p in paths if re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?ld-linux[^/]*\.so\.[0-9]+", p)]
    if "not found" in listing or len(interpreters) != 1 or any(not LIBRARY.fullmatch(p) for p in paths):
        raise IsolationUnavailable("Unsupported network tool dynamic runtime")
    entries = [(executable, FIXED_ARGV[tool_id][0])]
    entries += [(str(Path(path).resolve(strict=True)), path) for path in paths]
    files = []
    for source, destination in entries:
        control.check()
        raw = _read_regular(source)
        files.append({"source": source, "destination": destination, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    data = _compiled(tool_id)
    if data is not None:
        source, destination, raw = data
        files.append({"source": source, "destination": destination, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    return validate_manifest({"version": "1", "profile": PROFILE, "tool_id": tool_id,
        "executable": FIXED_ARGV[tool_id][0], "interpreter": interpreters[0],
        "files": sorted(files, key=lambda item: item["destination"])})


def runtime_source_mounts(manifest):
    return [(path, path) for path in sorted({item["source"] for item in validate_manifest(manifest)["files"]
                                            if not item["source"].startswith("compiled:")})]


def _snapshot(manifest, control):
    validate_manifest(manifest)
    data = _compiled(manifest["tool_id"])
    source, _, raw = data if data is not None else (None, None, None)
    return sealed_snapshots(manifest, source, raw, control)


def _command(lab, bootstrap, manifest, descriptors, nonce, commitment):
    stdlib, files = bootstrap
    tool_paths = {item["destination"] for item in manifest["files"]}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if destination not in tool_paths and Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in MODULES:
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for item, fd in zip(manifest["files"], descriptors):
        mode = "0555" if item["destination"] in {manifest["executable"], manifest["interpreter"]} else "0444"
        argv += ["--perms", mode, "--ro-bind-data", str(fd), item["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
             "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/network_tools_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
            "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
            ",".join(map(str, descriptors)), *argv]


def run_network_tool_owned(*, lab, launch, control, closure=None, manifest=None):
    if sys.platform != "linux" or type(control) is not ExecutionControl:
        raise IsolationUnavailable("Network tools require Linux authority control")
    control.check()
    lab._check(control)
    lab._verify_pins()
    selected = launch["launch"]["action"]["tool_id"]
    pinned = None if manifest is None else validate_manifest(manifest, tool_id=selected)
    manifest = ((inspect_tool_runtime(selected, control) if pinned is None else pinned) if closure is None else
                validate_manifest(closure["network_tools_runtime"], tool_id=selected))
    if pinned is not None and manifest_digest(pinned) != manifest_digest(manifest):
        raise IsolationUnavailable("Network tool authority runtime changed")
    bootstrap = lab._runtime(control) if closure is None else (
        closure["stdlib"], [(p, p) for p in closure["files"] if Path(p).name not in {"nft", "bwrap", "nsenter"}])
    envelope = {**launch, "runtime": manifest}
    raw = encode(envelope)
    if len(raw) > 32768:
        raise IsolationUnavailable("Network tool launch envelope exceeds its bound")
    commitment = hashlib.sha256(raw).hexdigest()
    prefix = READY_PREFIX + commitment.encode("ascii") + b"\n"
    descriptors = _snapshot(manifest, control)
    try:
        code, stdout, stderr, reason = _capture_bounded(
            _command(lab, bootstrap, manifest, descriptors, launch["launch"]["nonce"], commitment), raw,
            min(launch["launch"]["action"]["parameters"]["timeout_seconds"], control.remaining()),
            MAX_OUTPUT_BYTES + len(prefix), control=control, pass_fds=(*lab._namespace_fds, *descriptors))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
    control.check()
    if not stderr.startswith(prefix):
        raise IsolationUnavailable("Network tool confinement was not verified; no fallback")
    stderr = stderr[len(prefix):]
    # Capture includes a trusted readiness prefix; retained tool bytes have the
    # separate advertised ceiling even when the transport limit interrupts it.
    if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
        reason = "output_limit"
        stdout, stderr = stdout[:MAX_OUTPUT_BYTES], stderr[:max(0, MAX_OUTPUT_BYTES - len(stdout))]
    from .network_tools_contract import parser_version
    status = reason or ("succeeded" if code == 0 else "failed")
    return {"status": status, "results": [], "tool_observation": None,
        "bytes_received": len(stdout) + len(stderr), "truncated": reason == "output_limit",
        "boundary_checks": dict.fromkeys(("forbidden_ip_blocked", "forbidden_port_blocked", "namespace_creation_blocked",
            "capabilities_dropped", "no_new_privs", "root_read_only", "process_creation_blocked",
            "raw_sockets_blocked", "landlock_applied", "python_unreadable"), True),
        "raw_output_base64": base64.b64encode(stdout).decode("ascii"),
        "raw_stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "provenance": {"runtime_sha256": manifest_digest(manifest), "runtime_manifest": manifest,
            "output_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "parser_version": parser_version(selected), "exit_code": code, "stop_reason": reason}}
