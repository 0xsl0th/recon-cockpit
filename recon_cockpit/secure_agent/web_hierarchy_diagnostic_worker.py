"""Fixed owned-only ffuf feasibility worker, outside product authorization.

The private development pipe accepts no target, arguments, paths or credentials.
This worker measures the proposed corpus under confinement; it is not a session
authority, audit or human-approval executor.
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

if __name__ == "__main__":
    sys.path.insert(0, "/app")

from recon_cockpit.secure_agent.web_hierarchy_spec import CLIENT_SECONDS, MAX_OUTPUT_BYTES, WORDLIST


PROFILE = "web-hierarchy-development-runtime-v1"
READY_PREFIX = b"RECON_WEB_HIERARCHY_DIAGNOSTIC_READY_V1 "
MAX_REQUEST_BYTES = 16384
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
COMPILED_SOURCE = "compiled:web-hierarchy-paths"
COMPILED_DESTINATION = "/tool/data/hierarchy-paths.txt"
CONFIG_DIRECTORY = "/tool/config"
SCRAPER_DIRECTORY = CONFIG_DIRECTORY + "/ffuf/scraper"
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
INTERPRETER = re.compile(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?ld-linux[^/]*\.so\.[0-9]+\Z")
ENVIRONMENT = MappingProxyType({"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1",
    "GOMAXPROCS": "1", "GOMEMLIMIT": "64MiB", "XDG_CONFIG_HOME": CONFIG_DIRECTORY})
FIXED_ARGV = ("/tool/ffuf", "-u", "http://127.0.0.1:8080/harbordesk/FUZZ",
    "-w", COMPILED_DESTINATION, "-t", "1", "-rate", "4", "-timeout", "1",
    "-maxtime", "10", "-noninteractive", "-ignore-body", "-mc", "all", "-json",
    "-s", "-scrapers", "")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_web_hierarchy_field")
        value[key] = item
    return value


def validate_manifest(value):
    if (type(value) is not dict
            or set(value) != {"version", "profile", "executable", "interpreter", "files"}
            or value["version"] != "1" or value["profile"] != PROFILE
            or value["executable"] != "/tool/ffuf"
            or type(value["interpreter"]) is not str or not INTERPRETER.fullmatch(value["interpreter"])
            or type(value["files"]) is not list or not 3 <= len(value["files"]) <= 48
            or len(encode(value)) > 12288):
        raise ValueError("invalid_web_hierarchy_manifest")
    destinations, total = set(), 0
    for item in value["files"]:
        if (type(item) is not dict or set(item) != {"source", "destination", "size", "sha256"}
                or type(item["source"]) is not str or type(item["destination"]) is not str
                or any(".." in item[key] or "//" in item[key] for key in ("source", "destination"))
                or type(item["size"]) is not int or not 0 < item["size"] <= MAX_FILE_BYTES
                or type(item["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("invalid_web_hierarchy_runtime_file")
        source, destination = item["source"], item["destination"]
        if destination == "/tool/ffuf":
            valid = source == "/usr/bin/ffuf"
        elif destination == COMPILED_DESTINATION:
            valid = (source == COMPILED_SOURCE and item["size"] == len(WORDLIST)
                     and item["sha256"] == hashlib.sha256(WORDLIST).hexdigest())
        else:
            valid = bool(LIBRARY.fullmatch(source) and LIBRARY.fullmatch(destination))
        if not valid or destination in destinations:
            raise ValueError("unreviewed_web_hierarchy_runtime_path")
        destinations.add(destination)
        total += item["size"]
    if (not {"/tool/ffuf", COMPILED_DESTINATION, value["interpreter"]} <= destinations
            or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])):
        raise ValueError("invalid_web_hierarchy_runtime_closure")
    return value


def validate_request(raw, commitment, *, now=None):
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_REQUEST_BYTES
            or type(commitment) is not str or not re.fullmatch(r"[0-9a-f]{64}", commitment)
            or hashlib.sha256(raw).hexdigest() != commitment):
        raise ValueError("invalid_web_hierarchy_commitment")
    value = json.loads(raw, object_pairs_hook=_unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_web_hierarchy_constant")))
    if type(value) is not dict or set(value) != {"deadline", "host_namespaces", "lab_namespaces", "manifest"}:
        raise ValueError("invalid_web_hierarchy_request")
    now = time.monotonic() if now is None else now
    if (type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - now <= CLIENT_SECONDS):
        raise ValueError("invalid_web_hierarchy_deadline")
    for field in ("host_namespaces", "lab_namespaces"):
        namespaces = value[field]
        if (type(namespaces) is not dict or set(namespaces) != {"user", "net", "mnt", "pid"}
                or any(type(item) is not str or re.fullmatch(name + r":\[\d+\]", item) is None
                       for name, item in namespaces.items())):
            raise ValueError("invalid_web_hierarchy_namespaces")
    if any(value["host_namespaces"][name] == value["lab_namespaces"][name]
           for name in value["host_namespaces"]):
        raise ValueError("web_hierarchy_owner_namespace_not_private")
    validate_manifest(value["manifest"])
    return value


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError as exc:
                if exc.errno == 9:
                    continue
                raise
            raise ValueError("web_hierarchy_inherited_descriptor")


def close_private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.close(int(name))
            except OSError as exc:
                if exc.errno != 9:
                    raise


def _namespaces(request, worker):
    if sys.platform != "linux" or os.getuid() != 0 or os.getgid() != 0:
        raise ValueError("invalid_web_hierarchy_namespace_identity")
    for name in ("user", "net", "mnt", "pid"):
        current = os.readlink("/proc/self/ns/" + name)
        if current == request["host_namespaces"][name]:
            raise ValueError("web_hierarchy_host_namespace")
        if ((name == "net" and current != request["lab_namespaces"][name])
                or (name != "net" and current == request["lab_namespaces"][name])):
            raise ValueError("web_hierarchy_owner_namespace_mismatch")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise ValueError("web_hierarchy_interface_mismatch")
    with open("/proc/self/uid_map", encoding="ascii") as source:
        if [tuple(map(int, line.split())) for line in source] != [(0, 0, 1)]:
            raise ValueError("web_hierarchy_uid_mapping")
    if int(worker._status()["CapEff"], 16) & (1 << 12):
        raise ValueError("web_hierarchy_net_admin_forbidden")


def limits():
    # Preserve the accepted Go-runtime task and address-space ceilings.
    for kind, maximum in ((resource.RLIMIT_AS, 2048 * 1024 * 1024), (resource.RLIMIT_CPU, 5),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, 16),
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
                raise ValueError("web_hierarchy_mounted_size_mismatch")
            with os.fdopen(os.dup(fd), "rb") as source:
                raw = source.read(item["size"] + 1)
            if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError("web_hierarchy_mounted_hash_mismatch")
            if item["destination"] == manifest["executable"] and not raw.startswith(b"\x7fELF"):
                raise ValueError("web_hierarchy_requires_ffuf_elf")
            if "security.capability" in os.listxattr(fd):
                raise ValueError("web_hierarchy_file_capabilities")
        finally:
            os.close(fd)
    if os.listdir(SCRAPER_DIRECTORY):
        raise ValueError("web_hierarchy_scraper_directory_not_empty")


def permissions(manifest):
    value = {item["destination"]: 4 for item in validate_manifest(manifest)["files"]}
    value[manifest["executable"]] |= 1
    value[manifest["interpreter"]] |= 1
    value.update({"/dev/null": 6, "/dev/random": 4, "/dev/urandom": 4,
                  "/proc/self/status": 4, "/tool/data": 8, SCRAPER_DIRECTORY: 8})
    return value


def main():
    try:
        private_descriptors()
        if len(sys.argv) != 2 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("web_hierarchy_requires_private_pipe")
        request = validate_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1), sys.argv[1])
        from recon_cockpit.secure_agent import tool_worker_common as common, worker
        _namespaces(request, worker)
        verify_files(request["manifest"])
        limits()
        worker.drop_privileges()
        common.syscall_filter(allow_threads=True)
        common._witnesses()
        common._thread_bound_witness()
        try:
            denied = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        except PermissionError:
            pass
        else:
            denied.close()
            raise ValueError("web_hierarchy_udp_allowed")
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
            raise ValueError("web_hierarchy_expired")
        os.write(2, READY_PREFIX + sys.argv[1].encode("ascii") + b"\n")
        os.execve(FIXED_ARGV[0], FIXED_ARGV, dict(ENVIRONMENT))
    except Exception:
        sys.stderr.write("web_hierarchy_diagnostic_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
