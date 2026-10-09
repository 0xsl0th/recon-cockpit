"""Fixed OpenSSL development probes; not a production authority executor.

Only the diagnostic's private pipe selects one of four compiled argument lists.
The tool runs in the owner's disconnected namespace with the ordinary resource
limits. This boundary does not prevent a TLS HelloRetryRequest from eliciting a
second ClientHello; the diagnostic measures that unresolved feasibility gate.
"""

import hashlib
import json
import math
import os
import re
import resource
import socket
import stat
import sys
import time
from types import MappingProxyType


VERSIONS = ("tls1", "tls1_1", "tls1_2", "tls1_3")
CA_SIZE = 591
CA_SHA256 = "617015dc0014927cacb2c334ed861b091ea4846b2461540aa4aac3fa2138b84d"
MAX_REQUEST_BYTES = 16384
MAX_OUTPUT_BYTES = 8192
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
PROFILE = "tls-posture-development-runtime-v1"
READY_PREFIX = b"RECON_TLS_DIAGNOSTIC_READY_V1 "
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
ENVIRONMENT = MappingProxyType({"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"})
COMMON_ARGV = (
    "/tool/openssl", "s_client", "-4", "-connect", "127.0.0.1:8080",
    "-servername", "harbordesk.test", "-verify_hostname", "harbordesk.test",
    "-verify_return_error", "-verify", "1", "-auth_level", "2",
    "-CAfile", "/tool/data/fixture-ca.pem", "-no-CApath", "-no-CAstore",
    "-groups", "P-256", "-no_comp", "-no_ticket", "-no_renegotiation",
    "-no_legacy_server_connect", "-no_tx_cert_comp", "-no_rx_cert_comp",
    "-brief", "-state", "-msg", "-nocommands", "-no_ign_eof",
)
FIXED_ARGV = MappingProxyType({
    "tls1": COMMON_ARGV + ("-tls1", "-cipher", "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0"),
    "tls1_1": COMMON_ARGV + ("-tls1_1", "-cipher", "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0"),
    "tls1_2": COMMON_ARGV + ("-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2"),
    "tls1_3": COMMON_ARGV + ("-tls1_3", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2",
                              "-ciphersuites", "TLS_AES_256_GCM_SHA384"),
})


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_diagnostic_field")
        result[key] = value
    return result


def validate_manifest(value):
    if (type(value) is not dict
            or set(value) != {"version", "profile", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE
            or value["executable"] != "/tool/openssl"
            or type(value["interpreter"]) is not str
            or re.fullmatch(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?ld-linux[^/]*\.so\.[0-9]+", value["interpreter"]) is None
            or type(value["files"]) is not list or not 3 <= len(value["files"]) <= 48
            or len(encode(value)) > 12288):
        raise ValueError("invalid_diagnostic_manifest")
    destinations, total = set(), 0
    for item in value["files"]:
        if (type(item) is not dict or set(item) != {"source", "destination", "size", "sha256"}
                or type(item["source"]) is not str or type(item["destination"]) is not str
                or any(".." in item[key] or "//" in item[key] for key in ("source", "destination"))
                or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE_BYTES
                or type(item["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
            raise ValueError("invalid_diagnostic_runtime_file")
        source, destination = item["source"], item["destination"]
        if destination == "/tool/openssl":
            valid = source == "/usr/bin/openssl"
        elif destination == "/tool/data/fixture-ca.pem":
            valid = source == "compiled:fixture-ca" and item["size"] == CA_SIZE and item["sha256"] == CA_SHA256
        else:
            valid = bool(LIBRARY.fullmatch(source) and LIBRARY.fullmatch(destination))
        if not valid or destination in destinations:
            raise ValueError("unreviewed_diagnostic_runtime_path")
        destinations.add(destination)
        total += item["size"]
    if (not {"/tool/openssl", "/tool/data/fixture-ca.pem", value["interpreter"]} <= destinations
            or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])):
        raise ValueError("invalid_diagnostic_runtime_closure")
    return value


def validate_request(raw, commitment, *, now=None):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST_BYTES
            or type(commitment) is not str or re.fullmatch(r"[0-9a-f]{64}", commitment) is None
            or hashlib.sha256(raw).hexdigest() != commitment):
        raise ValueError("invalid_diagnostic_request_commitment")
    value = json.loads(raw, object_pairs_hook=_unique)
    if (type(value) is not dict
            or set(value) != {"version", "deadline", "host_namespaces", "lab_namespaces", "manifest"}
            or type(value["version"]) is not str or value["version"] not in VERSIONS):
        raise ValueError("invalid_diagnostic_request")
    now = time.monotonic() if now is None else now
    if (type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - now <= 5):
        raise ValueError("invalid_diagnostic_deadline")
    for key in ("host_namespaces", "lab_namespaces"):
        namespaces = value[key]
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(name + r":\[\d+\]", item) is None
                       for name, item in namespaces.items())):
            raise ValueError("invalid_diagnostic_namespaces")
    if any(value["host_namespaces"][name] == value["lab_namespaces"][name]
           for name in value["host_namespaces"]):
        raise ValueError("diagnostic_owner_namespace_not_private")
    validate_manifest(value["manifest"])
    return value


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("diagnostic_inherited_descriptor")


def close_private_descriptors():
    # libffi/loaded bootstrap helpers can retain descriptors after the initial
    # entry check. Close them all before the tool, as the accepted worker does.
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError as exc:
                if exc.errno != 9:
                    raise


def _namespaces(request, worker):
    if sys.platform != "linux" or os.getuid() != 0 or os.getgid() != 0:
        raise ValueError("invalid_diagnostic_namespace_identity")
    for name in ("user", "net", "mnt", "pid"):
        current = os.readlink("/proc/self/ns/" + name)
        if current == request["host_namespaces"][name]:
            raise ValueError("diagnostic_host_namespace")
        if ((name == "net" and current != request["lab_namespaces"][name])
                or (name != "net" and current == request["lab_namespaces"][name])):
            raise ValueError("diagnostic_owner_namespace_mismatch")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("diagnostic_interface_mismatch")
    with open("/proc/self/uid_map", encoding="ascii") as source:
        if [tuple(map(int, line.split())) for line in source] != [(0, 0, 1)]:
            raise ValueError("diagnostic_uid_mapping")
    if int(worker._status()["CapEff"], 16) & (1 << 12):
        raise ValueError("diagnostic_net_admin_forbidden")


def limits():
    for kind, maximum in ((resource.RLIMIT_AS, 256 * 1024 * 1024), (resource.RLIMIT_CPU, 5),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 1),
                           (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))


def verify_files(manifest):
    validate_manifest(manifest)
    for item in manifest["files"]:
        fd = os.open(item["destination"], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != item["size"]:
                raise ValueError("diagnostic_mounted_size_mismatch")
            with os.fdopen(os.dup(fd), "rb") as source:
                raw = source.read(item["size"] + 1)
            if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError("diagnostic_mounted_hash_mismatch")
            if item["destination"] == "/tool/openssl" and not raw.startswith(b"\x7fELF"):
                raise ValueError("diagnostic_requires_openssl_elf")
            if "security.capability" in os.listxattr(fd):
                raise ValueError("diagnostic_file_capabilities")
        finally:
            os.close(fd)


def permissions(manifest):
    value = {item["destination"]: 4 for item in validate_manifest(manifest)["files"]}
    value[manifest["executable"]] |= 1
    value[manifest["interpreter"]] |= 1
    value.update({"/dev/null": 6, "/dev/random": 4, "/dev/urandom": 4,
                  "/proc/self/status": 4, "/tool/data": 8})
    return value


def main():
    try:
        private_descriptors()
        if len(sys.argv) != 2 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("diagnostic_requires_private_pipe")
        request = validate_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1), sys.argv[1])
        # The client mount contains only these shared mechanics, never the owner
        # fixture or its deliberately public synthetic private key.
        sys.path.insert(0, "/app")
        from recon_cockpit.secure_agent import tool_worker_common as common, worker
        _namespaces(request, worker)
        verify_files(request["manifest"])
        limits()
        worker.drop_privileges()
        common.syscall_filter(allow_threads=False)
        common._witnesses()
        try:
            denied = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        except PermissionError:
            pass
        else:
            denied.close()
            raise ValueError("diagnostic_udp_allowed")
        sys.stdin.close()
        close_private_descriptors()
        private_descriptors()
        try:
            os.close(0)
        except OSError as exc:
            if exc.errno != 9:
                raise
        empty = os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC)
        os.dup2(empty, 0, inheritable=True)
        if empty != 0:
            os.close(empty)
        else:
            os.set_inheritable(0, True)
        common.apply_landlock(permissions(request["manifest"]))
        if time.monotonic() >= request["deadline"]:
            raise ValueError("diagnostic_expired")
        os.write(2, READY_PREFIX + sys.argv[1].encode("ascii") + b"\n")
        os.execve("/tool/openssl", FIXED_ARGV[request["version"]], dict(ENVIRONMENT))
    except Exception:
        sys.stderr.write("tls_posture_diagnostic_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
