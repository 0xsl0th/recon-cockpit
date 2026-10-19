"""Key-free fixed native role partitions; metadata never authorizes execution."""

from copy import deepcopy
import hashlib
import json
import re

PROFILE = "owned-name-tls-native-role-v1"
INTERPRETER = "/lib64/ld-linux-x86-64.so.2"
LIBRARY_ROOT = "/usr/lib/x86_64-linux-gnu/"
DATA = "/tool/data/name-tls/"
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 65536
MAX_FILES = 128
ROLES = ("dns_daemon", "web_daemon", "dns_client", "tls_client")
PROGRAMS = {"dns_daemon": ("/tool/dnsmasq", "/usr/sbin/dnsmasq"),
            "web_daemon": ("/tool/nginx", "/usr/sbin/nginx"),
            "dns_client": ("/tool/dig", "/usr/bin/dig"),
            "tls_client": ("/tool/openssl", "/usr/bin/openssl")}
LIBRARIES = {
    "dns_daemon": ("libc.so.6", "libdbus-1.so.3", "libgmp.so.10", "libhogweed.so.6", "libidn2.so.0",
        "libjansson.so.4", "libm.so.6", "libmnl.so.0", "libnetfilter_conntrack.so.3", "libnettle.so.8",
        "libnfnetlink.so.0", "libnftables.so.1", "libnftnl.so.11", "libsystemd.so.0", "libunistring.so.5", "libxtables.so.12"),
    "web_daemon": ("libc.so.6", "libcrypt.so.1", "libcrypto.so.3", "libpcre2-8.so.0", "libssl.so.3", "libz.so.1", "libzstd.so.1"),
    "dns_client": ("libc.so.6", "libcom_err.so.2", "libcrypto.so.3", "libdns-9.20.15-2-Debian.so",
        "libfstrm.so.0", "libgcc_s.so.1", "libgssapi_krb5.so.2", "libidn2.so.0", "libisc-9.20.15-2-Debian.so",
        "libisccfg-9.20.15-2-Debian.so", "libjemalloc.so.2", "libjson-c.so.5", "libk5crypto.so.3", "libkeyutils.so.1",
        "libkrb5.so.3", "libkrb5support.so.0", "liblmdb.so.0", "libm.so.6", "libmaxminddb.so.0", "libnghttp2.so.14",
        "libns-9.20.15-2-Debian.so", "libprotobuf-c.so.1", "libresolv.so.2", "libssl.so.3", "libstdc++.so.6",
        "libunistring.so.5", "liburcu-cds.so.8", "liburcu-common.so.8", "liburcu.so.8", "libuv.so.1", "libxml2.so.16",
        "libz.so.1", "libzstd.so.1"),
    "tls_client": ("libc.so.6", "libcrypto.so.3", "libssl.so.3", "libz.so.1", "libzstd.so.1"),
}
IDENTITY_FILES = ("/etc/passwd", "/etc/group", "/etc/nsswitch.conf")
COMPILED = {
    "dns_daemon": (DATA + "dnsmasq.conf", "/etc/resolv.conf", *IDENTITY_FILES),
    "web_daemon": (DATA + "nginx.conf", DATA + "server.pem", DATA + "server.key", DATA + "openssl.cnf", *IDENTITY_FILES),
    "dns_client": (DATA + "openssl.cnf", "/etc/resolv.conf", *IDENTITY_FILES),
    "tls_client": (DATA + "ca.pem", DATA + "openssl.cnf", "/etc/resolv.conf", *IDENTITY_FILES),
}
COMPILED_SOURCES = dict(zip((DATA + "dnsmasq.conf", DATA + "nginx.conf", DATA + "ca.pem", DATA + "server.pem",
    DATA + "server.key", DATA + "openssl.cnf", "/etc/resolv.conf", *IDENTITY_FILES),
    ("compiled:name-tls-" + suffix for suffix in ("dnsmasq-config", "nginx-config", "public-ca",
        "public-server-certificate", "public-server-key", "openssl-config", "empty-resolv", "passwd", "group", "nsswitch")), strict=True))
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def validate_role(role):
    if type(role) is not str or role not in ROLES:
        raise ValueError("name_tls_runtime_role")
    return role


def dependencies(role):
    validate_role(role)
    return sorted((INTERPRETER, *(LIBRARY_ROOT + name for name in LIBRARIES[role])))


def destinations(role):
    validate_role(role)
    return sorted((PROGRAMS[role][0], *dependencies(role), *COMPILED[role]))


def source_allowed(source, destination, role):
    validate_role(role)
    if type(source) is not str or type(destination) is not str or len(source) > 512:
        return False
    if destination == PROGRAMS[role][0]:
        return source == PROGRAMS[role][1]
    if destination == INTERPRETER:
        return source == LIBRARY_ROOT + "ld-linux-x86-64.so.2"
    if destination in COMPILED[role]:
        return source == COMPILED_SOURCES[destination]
    if destination not in dependencies(role):
        return False
    if source == destination:
        return True
    return ("-9.20.15-2-Debian.so" not in destination
        and re.fullmatch(re.escape(destination) + r"(?:\.[0-9]{1,10}){1,4}", source) is not None)


def validate_manifest(value, *, role=None):
    fields = {"schema_version", "profile", "role", "configuration", "case", "selection_sha256",
              "preflight_sha256", "executable", "interpreter", "files"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("name_tls_role_manifest_shape")
    selected_role = validate_role(value["role"])
    if role is not None and selected_role != validate_role(role):
        raise ValueError("name_tls_role_manifest_swapped")
    if (value["schema_version"] != "1" or value["profile"] != PROFILE
            or type(value["configuration"]) is not str or value["configuration"] not in ("A", "B")
            or type(value["case"]) is not str or value["case"] not in
                ("O1", "O2", "O3", "O4", "O5", "R1", "R2", *("N" + str(n) for n in range(1, 17)))
            or any(type(value[key]) is not str or _DIGEST.fullmatch(value[key]) is None
                   for key in ("selection_sha256", "preflight_sha256"))
            or value["executable"] != PROGRAMS[selected_role][0] or value["interpreter"] != INTERPRETER
            or type(value["files"]) is not list or len(value["files"]) != len(destinations(selected_role))):
        raise ValueError("name_tls_role_manifest_identity")
    seen, sources, total = set(), set(), 0
    for row in value["files"]:
        if (type(row) is not dict or set(row) != {"source", "destination", "size", "sha256"}
                or type(row["size"]) is not int or not 0 < row["size"] <= MAX_FILE_BYTES
                or type(row["sha256"]) is not str or _DIGEST.fullmatch(row["sha256"]) is None
                or not source_allowed(row["source"], row["destination"], selected_role)
                or row["source"] in sources or row["destination"] in seen):
            raise ValueError("name_tls_role_manifest_file")
        sources.add(row["source"])
        seen.add(row["destination"])
        total += row["size"]
    if (seen != set(destinations(selected_role)) or total > MAX_RUNTIME_BYTES
            or value["files"] != sorted(value["files"], key=lambda row: row["destination"])
            or len(encode(value)) > MAX_MANIFEST_BYTES):
        raise ValueError("name_tls_role_manifest_closure")
    return deepcopy(value)


def manifest_digest(value):
    return hashlib.sha256(encode(validate_manifest(value))).hexdigest()
