"""One pinned static Nuclei ELF and compiled HTTP check; never caller-selected code.

The larger file ceiling and writable scratch belong only to this versioned
profile. Source bytes are streamed into sealed snapshots under authority time.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import stat
import struct

from .isolation import IsolationUnavailable, _trusted_program
from .tool_runtime_common import _CLOSE_EXCEPT

TOOL_ID = "nuclei_directory_listing_v1"
PROFILE = "network-tools-nuclei-static-runtime-v1"
EXECUTABLE = "/home/sloth/Code/recon-cockpit/.secure-agent/tools/nuclei-3.11.1"
DESTINATION = "/tool/nuclei"
EXECUTABLE_SIZE = 143294626
EXECUTABLE_SHA256 = "c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251"
MAX_FILE_BYTES = 160 * 1024 * 1024
MAX_RUNTIME_BYTES = 192 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192
SCRATCH = "/scratch"
SCRATCH_BYTES = 8 * 1024 * 1024
SCRATCH_INODES = 128
MAX_WRITE_BYTES = 64 * 1024
CHUNK_BYTES = 1024 * 1024
BOUNDARY_FIELDS = frozenset({"scratch_mount_bounded", "scratch_writes_confined", "scratch_noexec",
    "scratch_file_limit", "static_runtime_verified"})
TEMPLATE_ID = "recon-owned-directory-listing-v1"
TEMPLATE_PATH = "/tool/data/directory-listing.yaml"
TEMPLATE = b'''id: recon-owned-directory-listing-v1
info:
  name: Owned directory-listing signature
  author: recon-cockpit
  severity: info
http:
  - method: GET
    path: ["http://127.0.0.1:8080/public/"]
    headers:
      User-Agent: recon-cockpit-owned-nuclei/1
      Connection: close
      Accept-Encoding: identity
    redirects: false
    matchers:
      - type: dsl
        name: directory-listing-signature
        dsl:
          - 'status_code == 200 && contains(body, "<title>Index of /public/</title>") && contains(body, "<h1>Index of /public/</h1>") && contains(body, "href=\\"../\\"")'
'''
COMPILED = (
    ("compiled:nuclei-template", TEMPLATE_PATH, TEMPLATE),
    ("compiled:nuclei-config", "/tool/data/config.yaml", b"{}\n"),
    ("compiled:nuclei-templates-config", "/tool/data/templates-config.json",
     b'{"nuclei-templates-directory":"/tool/data","nuclei-templates-version":"v3.11.1"}\n'),
    ("compiled:nuclei-ignore", "/tool/data/nuclei-ignore.yaml", b"tags: []\nfiles: []\n"),
    ("compiled:nuclei-reporting", "/tool/data/reporting-config.yaml", b"{}\n"),
    ("compiled:nuclei-resolver", "/etc/resolv.conf", b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n"),
    ("compiled:nuclei-hosts", "/etc/hosts", b"127.0.0.1 localhost\n"),
)
CONFIG_SEEDS = (
    ("/tool/data/config.yaml", "/scratch/config/config.yaml"),
    ("/tool/data/config.yaml", "/scratch/home/.config/nuclei/config.yaml"),
    ("/tool/data/templates-config.json", "/scratch/config/.templates-config.json"),
    ("/tool/data/nuclei-ignore.yaml", "/scratch/config/.nuclei-ignore"),
    ("/tool/data/reporting-config.yaml", "/scratch/config/reporting-config.yaml"),
)
ENVIRONMENT = {
    "LC_ALL": "C", "HOME": "/scratch/home", "XDG_CONFIG_HOME": "/scratch/home/.config",
    "XDG_CACHE_HOME": "/scratch/cache", "TMPDIR": "/scratch/tmp",
    "NUCLEI_CONFIG_DIR": "/scratch/config", "NUCLEI_TEMPLATES_DIR": "/tool/data",
    "GOMAXPROCS": "1", "GOMEMLIMIT": "64MiB", "GODEBUG": "netdns=go",
    **{"DISABLE_NUCLEI_TEMPLATES_" + provider + "_DOWNLOAD": "true"
       for provider in ("PUBLIC", "GITHUB", "GITLAB", "AWS", "AZURE")},
}
FIXED_ARGV = (DESTINATION, "-t", TEMPLATE_PATH, "-u", "http://127.0.0.1:8080/public/",
    "-config", "/tool/data/config.yaml", "-jsonl", "-matcher-status", "-omit-template", "-silent",
    "-no-color", "-response-size-read", "2048", "-response-size-save", "4096", "-dr", "-retries", "0",
    "-no-httpx", "-no-stdin", "-duc", "-ni", "-dc", "-timeout", "2", "-rl", "1", "-bs", "1",
    "-c", "1", "-pc", "1", "-prc", "1", "-tlc", "1", "-jsc", "1")


def manifest():
    files = [{"source": EXECUTABLE, "destination": DESTINATION,
              "size": EXECUTABLE_SIZE, "sha256": EXECUTABLE_SHA256}]
    files += [{"source": source, "destination": destination, "size": len(raw),
               "sha256": hashlib.sha256(raw).hexdigest()} for source, destination, raw in COMPILED]
    return {"version": "1", "profile": PROFILE, "tool_id": TOOL_ID, "executable": DESTINATION,
            "files": sorted(files, key=lambda item: item["destination"])}


def validate_manifest(value, *, tool_id=None):
    from .network_tools_runtime import encode
    expected = manifest()
    # Exact types prevent bool/int equivalence from weakening byte commitments.
    if (type(value) is not dict or set(value) != set(expected) or tool_id not in (None, TOOL_ID)
            or any(type(value[key]) is not str for key in ("version", "profile", "tool_id", "executable"))
            or type(value["files"]) is not list or len(value["files"]) != len(expected["files"])):
        raise ValueError("invalid_nuclei_static_manifest")
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["size"]) is not int or not 0 < row["size"] <= MAX_FILE_BYTES
                or any(type(row[key]) is not str for key in ("source", "destination", "sha256"))):
            raise ValueError("invalid_nuclei_static_file")
    if (value != expected or sum(row["size"] for row in value["files"]) > MAX_RUNTIME_BYTES
            or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("invalid_nuclei_static_closure")
    return value


def validate_elf(header):
    """Validate fixed Linux x86-64 static ELF headers without invoking any ELF."""
    if (type(header) is not bytes or len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<HHI", header, 16) != (2, 62, 1)):
        raise IsolationUnavailable("Nuclei requires the pinned static x86-64 ELF")
    offset = struct.unpack_from("<Q", header, 32)[0]
    ehsize, phsize, count = struct.unpack_from("<HHH", header, 52)
    if ehsize != 64 or phsize != 56 or not 1 <= count <= 32 or offset < 64 or offset + count * phsize > len(header):
        raise IsolationUnavailable("Nuclei ELF headers exceed the reviewed bound")
    kinds = [struct.unpack_from("<I", header, offset + index * phsize)[0] for index in range(count)]
    if 1 not in kinds or 2 in kinds or 3 in kinds:
        raise IsolationUnavailable("Nuclei static runtime cannot contain a dynamic loader")


def _stream_file(path, row, control, *, sink=None):
    control.check()
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size != row["size"]
                or not 0 < info.st_size <= MAX_FILE_BYTES or "security.capability" in os.listxattr(descriptor)):
            raise IsolationUnavailable("Nuclei runtime file is not the pinned regular file")
        digest, total, header = hashlib.sha256(), 0, b""
        while True:
            control.check()
            chunk = os.read(descriptor, min(CHUNK_BYTES, row["size"] + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > row["size"]:
                raise IsolationUnavailable("Nuclei runtime grew while being staged")
            if not header:
                header = chunk[:4096]
            digest.update(chunk)
            if sink is not None:
                view = memoryview(chunk)
                while view:
                    control.check()
                    count = os.write(sink, view)
                    if count <= 0:
                        raise IsolationUnavailable("Nuclei snapshot write stalled")
                    view = view[count:]
        if total != row["size"] or digest.hexdigest() != row["sha256"]:
            raise IsolationUnavailable("Nuclei runtime differs from its pinned manifest")
        if row["destination"] == DESTINATION:
            validate_elf(header)
        control.check()
    finally:
        os.close(descriptor)


def inspect_runtime(control):
    value = manifest()
    if str(Path(EXECUTABLE).resolve(strict=True)) != EXECUTABLE:
        raise IsolationUnavailable("Nuclei provision path must not contain symlinks")
    row = next(row for row in value["files"] if row["destination"] == DESTINATION)
    _stream_file(EXECUTABLE, row, control)
    return validate_manifest(value)


def snapshot(value, control):
    validate_manifest(value)
    compiled = {source: raw for source, _, raw in COMPILED}
    descriptors = []
    try:
        for row in value["files"]:
            control.check()
            fd = os.memfd_create("recon-nuclei-runtime", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            if row["source"] in compiled:
                raw = compiled[row["source"]]
                if os.write(fd, raw) != len(raw):
                    raise IsolationUnavailable("Nuclei compiled snapshot truncated")
            else:
                _stream_file(row["source"], row, control, sink=fd)
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return descriptors
    except BaseException:
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def verify_mounted(value, control):
    validate_manifest(value)
    for row in value["files"]:
        _stream_file(row["destination"], row, control)


def command(lab, bootstrap, value, descriptors, nonce, commitment):
    from .network_tools_runtime import MODULES
    validate_manifest(value)
    if len(descriptors) != len(value["files"]):
        raise ValueError("nuclei_snapshot_descriptor_count")
    stdlib, files = bootstrap
    paths = {row["destination"] for row in value["files"]}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
        "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
        "--cap-add", "CAP_SETPCAP", "--cap-add", "CAP_SYS_ADMIN", "--die-with-parent", "--new-session",
        "--clearenv", "--setenv", "LC_ALL", "C", "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
        "--dir", SCRATCH, "--ro-bind", stdlib, stdlib]
    for source, destination in files:
        if source != EXECUTABLE and destination not in paths and Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    for name in (*MODULES, "network_tools_nuclei_worker"):
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for row, descriptor in zip(value["files"], descriptors):
        argv += ["--perms", "0555" if row["destination"] == DESTINATION else "0444", "--ro-bind-data",
                 str(descriptor), row["destination"]]
    argv += ["--remount-ro", "/proc", "--remount-ro", "/dev", "--remount-ro", "/",
        "/usr/bin/python3", "-I", "-S", "/app/recon_cockpit/secure_agent/network_tools_nuclei_worker.py", nonce, commitment]
    user_fd, net_fd = lab._namespace_fds
    return [_trusted_program("nsenter"), f"--user=/proc/self/fd/{user_fd}", f"--net=/proc/self/fd/{net_fd}",
        "--preserve-credentials", "--", "/usr/bin/python3", "-I", "-S", "-c", _CLOSE_EXCEPT,
        ",".join(map(str, descriptors)), *argv]
