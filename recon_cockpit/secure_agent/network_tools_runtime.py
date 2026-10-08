"""Pinned network metadata executables for the disconnected single-action lab.

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
DIG_SRV = "dig_dns_srv_v1"
DIG_NSID = "dig_dns_nsid_v1"
DIG_AXFR = "dig_dns_axfr_v1"
OPENSSL = "openssl_tls_handshake_v1"
TLS_CERTIFICATE = "openssl_peer_certificate_v1"
SSH = "ssh_host_keys_v1"
LDAP = "ldap_rootdse_v1"
SMB = "smb_share_list_v1"
RPCINFO = "rpcinfo_dump_v1"
SHOWMOUNT = "showmount_exports_v1"
FTP = "curl_ftp_list_v1"
SMTP = "curl_smtp_capabilities_v1"
DOCKER_PING = "curl_docker_ping_v1"
DOCKER_VERSION = "curl_docker_version_v1"
WINRM = "curl_winrm_metadata_v1"
HTTP_OPTIONS = "curl_http_options_v1"
NMAP_SERVICE = "nmap_service_identify_v1"
KERBRUTE = "kerbrute_userenum_v1"
REDIS = "redis_server_info_v1"
SNMP = "snmp_system_get_v1"
SNMP_NEXT = "snmp_interface_next_v1"
POSTGRESQL_TLS = "postgresql_tls_handshake_v1"
MYSQL_TLS = "mysql_tls_handshake_v1"
WHATWEB = "whatweb_http_fingerprint_v1"
RDP = "rdp_initial_negotiation_v1"
SMB2 = "smb2_negotiate_metadata_v1"
SSH_ALGORITHMS = "ssh_transport_algorithms_v1"
SMTP_TLS = "smtp_starttls_handshake_v1"
LDAP_TLS = "ldap_starttls_handshake_v1"
FTP_TLS = "ftp_starttls_handshake_v1"
KERBRUTE_PRINCIPALS = b"fixture-a\nfixture-b\n"
# A distribution may put a wrapper at /usr/bin/nmap. Only these two ELF
# locations are eligible, and only this new profile resolves the alternative.
NMAP_SERVICE_EXECUTABLES = ("/usr/bin/nmap", "/usr/lib/nmap/nmap")
# The service name deliberately carries no port-derived product guess.
NMAP_SERVICE_SERVICES = b"unknown 8080/tcp 1.0\n"
NMAP_SERVICE_PROTOCOLS = b"tcp 6 TCP\n"
NMAP_SERVICE_PROBES = (
    b"# Reviewed TCP NULL and one fixed metadata GET; no SSL, UDP or RPC probes.\n"
    b"Probe TCP NULL q||\n"
    b"totalwaitms 400\n"
    b"tcpwrappedms 100\n"
    br"match ssh m%^SSH-2\.0-OpenSSH_([0-9]{1,3}(?:\.[0-9]{1,3}){0,2})\r\n$% p/OpenSSH/ v/$1/" + b"\n"
    b"Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|\n"
    b"ports 8080\n"
    b"rarity 1\n"
    b"totalwaitms 700\n"
    br"match http m%^HTTP/1\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\r\nServer: nginx/([0-9]{1,3}(?:\.[0-9]{1,3}){0,2})\r\n% p/nginx/ v/$1/" + b"\n"
    br"match http m%^HTTP/1\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\r\nServer: Apache/([0-9]{1,3}(?:\.[0-9]{1,3}){0,2})\r\n% p/Apache httpd/ v/$1/" + b"\n"
    br"match http m%^HTTP/1\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\r\n%" + b"\n"
)
# -sV initializes NSE even without --script. Replace its entrypoint with a
# byte-pinned, deny-all shim: no script database, modules, IO or callbacks.
# The native engine must expose exactly the reviewed version-only mode.
NMAP_SERVICE_NSE_SHIM = (
    b"local engine, rules = ...\n"
    b"assert(type(engine) == 'table' and engine.scriptversion == true)\n"
    b"assert(engine.default == false and engine.scriptupdatedb == false and engine.scripthelp == false)\n"
    # Nmap validates absent CLI arguments into an empty string before NSE.
    b"assert(engine.scriptargs == '' and engine.scriptargsfile == nil)\n"
    b"assert(type(rules) == 'table' and next(rules) == nil)\n"
    b"return function(hosts, phase)\n"
    b"  assert(type(hosts) == 'table' and #hosts <= 1 and phase == 'NSE_SCAN')\n"
    b"end\n"
)
# No UDP, IPv6, local sockets, host transport defaults or dynamic netids.
RPC_NETCONFIG = b"tcp tpi_cots_ord v inet tcp - -\n"
# The native clients resolve these service names even for a numeric host.
# Only the single preauthorized TCP endpoint exists in this synthetic database.
RPC_SERVICES = b"sunrpc 111/tcp rpcbind portmapper\n"
SMB_PROFILE = "network-tools-smb-runtime-v1"
SMB_MAX_FILES = 160
SMB_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
SMB_MAX_FILE_BYTES = 40 * 1024 * 1024
SMB_MAX_MANIFEST_BYTES = 18432
# Roots are closed distribution-library directories, never caller mount roots.
SMB_ROOTS = ("/lib", "/lib64", "/usr/lib", "/usr/lib64",
    "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu/samba", "/usr/lib/x86_64-linux-gnu/samba",
    "/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
    "/lib/aarch64-linux-gnu/samba", "/usr/lib/aarch64-linux-gnu/samba")
SMB_CONFIG = (b"[global]\nclient min protocol = SMB2_02\nclient max protocol = SMB2_02\n"
    b"client ipc min protocol = SMB2_02\nclient ipc max protocol = SMB2_02\n"
    b"client signing = disabled\nclient ipc signing = disabled\nclient smb encrypt = off\n"
    # The fixed -I address bypasses resolution; no resolver file or UDP socket
    # is available. Explicit IP/mask also avoids interface discovery sockets.
    b"client use kerberos = off\ndisable netbios = yes\nname resolve order = host\n"
    b"interfaces = 127.0.0.1/8\n"
    b"workgroup = WORKGROUP\nnetbios name = RECONLAB\n")
MAX_OUTPUT_BYTES = 8192
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 12288
READY_PREFIX = b"RECON_NETWORK_TOOL_READY_V1 "
LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
EXECUTABLES = {DIG: "/usr/bin/dig", DIG_SRV: "/usr/bin/dig", DIG_NSID: "/usr/bin/dig", DIG_AXFR: "/usr/bin/dig", OPENSSL: "/usr/bin/openssl", TLS_CERTIFICATE: "/usr/bin/openssl",
               SSH: "/usr/bin/ssh-keyscan", LDAP: "/usr/bin/ldapsearch", SMB: "/usr/bin/smbclient",
               RPCINFO: "/usr/bin/rpcinfo", SHOWMOUNT: "/usr/sbin/showmount",
               FTP: "/usr/bin/curl", SMTP: "/usr/bin/curl",
               DOCKER_PING: "/usr/bin/curl", DOCKER_VERSION: "/usr/bin/curl", WINRM: "/usr/bin/curl", HTTP_OPTIONS: "/usr/bin/curl",
               NMAP_SERVICE: "/usr/bin/nmap", KERBRUTE: "/usr/local/bin/kerbrute",
               REDIS: "/usr/bin/redis-cli", SNMP: "/usr/bin/snmpget", SNMP_NEXT: "/usr/bin/snmpgetnext",
               POSTGRESQL_TLS: "/usr/bin/openssl", MYSQL_TLS: "/usr/bin/openssl",
               WHATWEB: "/usr/bin/ruby3.3", RDP: "/usr/bin/ruby3.3", SMB2: "/usr/bin/ruby3.3", SSH_ALGORITHMS: "/usr/bin/ruby3.3",
               SMTP_TLS: "/usr/bin/openssl", LDAP_TLS: "/usr/bin/openssl", FTP_TLS: "/usr/bin/openssl"}
FIXED_ARGV = {
    REDIS: ("/tool/redis-cli", "-2", "-e", "--raw", "-h", "127.0.0.1", "-p", "8080", "INFO", "server"),
    SNMP: ("/tool/snmpget", "-v", "2c", "-c", "recon-fixture-public", "-r", "0", "-t", "2",
           "-Cf", "-On", "-Ot", "-Ox", "-m", "", "-M", "", "--dontLoadHostConfig=true",
           "--noPersistentLoad=true", "--noPersistentSave=true", "tcp:127.0.0.1:8080",
           ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"),
    SNMP_NEXT: ("/tool/snmpgetnext", "-v", "2c", "-c", "recon-fixture-public", "-r", "0", "-t", "2",
           "-Cf", "-On", "-Ot", "-Ox", "-m", "", "-M", "", "--dontLoadHostConfig=true",
           "--noPersistentLoad=true", "--noPersistentSave=true", "tcp:127.0.0.1:8080",
           ".1.3.6.1.2.1.2.2.1.2"),
    KERBRUTE: ("/tool/kerbrute", "userenum", "--dc", "127.0.0.1:8080", "--domain", "harbordesk.test",
          "--threads", "1", "--safe", "--verbose", "/tool/data/principals.txt"),
    NMAP_SERVICE: ("/tool/nmap", "--unprivileged", "-sT", "-sV", "--version-intensity", "0",
          "-Pn", "-n", "-p", "8080", "--max-retries", "0", "--max-parallelism", "1",
          "--host-timeout", "3s", "--datadir", "/tool/data", "--no-stylesheet",
          "-oX", "-", "127.0.0.1"),
    DIG: ("/tool/dig", "-r", "-4", "@127.0.0.1", "-p", "8080", "harbordesk.test.", "A",
          "+tcp", "+norecurse", "+tries=1", "+time=2", "+nosearch", "+noedns",
          "+nobadcookie", "+noadflag", "+nocdflag", "+noall", "+comments", "+question",
          "+answer", "+additional", "+nocmd"),
    DIG_SRV: ("/tool/dig", "-r", "-4", "@127.0.0.1", "-p", "8080", "_ldap._tcp.harbordesk.test.", "SRV",
          "+tcp", "+norecurse", "+tries=1", "+time=2", "+nosearch", "+noedns",
          "+nobadcookie", "+noadflag", "+nocdflag", "+noall", "+comments", "+question",
          "+answer", "+additional", "+nocmd"),
    OPENSSL: ("/tool/openssl", "s_client", "-4", "-connect", "127.0.0.1:8080",
          "-servername", "harbordesk.test", "-verify_hostname", "harbordesk.test",
          "-verify_return_error", "-CAfile", "/tool/data/fixture-ca.pem", "-no-CApath", "-no-CAstore",
          "-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-brief", "-no_ign_eof"),
    # Only a fixed protocol preface precedes the existing verified handshake.
    # The worker supplies EOF, so no login, SQL or TLS application payload is sent.
    POSTGRESQL_TLS: ("/tool/openssl", "s_client", "-4", "-connect", "127.0.0.1:8080",
          "-servername", "harbordesk.test", "-verify_hostname", "harbordesk.test",
          "-verify_return_error", "-CAfile", "/tool/data/fixture-ca.pem", "-no-CApath", "-no-CAstore",
          "-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-brief", "-no_ign_eof", "-starttls", "postgres"),
    MYSQL_TLS: ("/tool/openssl", "s_client", "-4", "-connect", "127.0.0.1:8080",
          "-servername", "harbordesk.test", "-verify_hostname", "harbordesk.test",
          "-verify_return_error", "-CAfile", "/tool/data/fixture-ca.pem", "-no-CApath", "-no-CAstore",
          "-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-brief", "-no_ign_eof", "-starttls", "mysql"),
    SSH: ("/tool/ssh-keyscan", "-4", "-T", "2", "-p", "8080", "-t", "rsa", "127.0.0.1"),
    LDAP: ("/tool/ldapsearch", "-x", "-LLL", "-P", "3", "-H", "ldap://127.0.0.1:8080",
           "-s", "base", "-b", "", "-a", "never", "-l", "2", "-z", "1",
           "-o", "nettimeout=2", "-o", "ldif_wrap=no", "(objectClass=*)",
           "namingContexts", "supportedLDAPVersion", "supportedSASLMechanisms", "vendorName"),
    SMB: ("/tool/smbclient", "-L", "127.0.0.1", "-I", "127.0.0.1", "-p", "8080",
          "-U", "%", "-N", "-g", "-t", "2", "--use-kerberos=off", "-s", "/tool/data/smb.conf"),
    RPCINFO: ("/tool/rpcinfo", "-p", "127.0.0.1"),
    SHOWMOUNT: ("/tool/showmount", "-e", "127.0.0.1"),
    FTP: ("/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
          "--proto", "=ftp", "--proto-redir", "=ftp", "--noproxy", "*", "--proxy", "",
          "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
          "--ftp-pasv", "--disable-epsv", "--no-ftp-skip-pasv-ip", "--ftp-method", "nocwd",
          "--list-only", "--user", "anonymous:anonymous@", "--dump-header", "%",
          "ftp://127.0.0.1:8080/"),
    SMTP: ("/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
           "--proto", "=smtp", "--proto-redir", "=smtp", "--noproxy", "*", "--proxy", "",
           "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
           "--request", "QUIT", "--dump-header", "-", "--output", "/dev/null",
           "smtp://127.0.0.1:8080/reconlab"),
    DOCKER_PING: ("/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
           "--http1.1", "--proto", "=http", "--proto-redir", "=http", "--noproxy", "*", "--proxy", "",
           "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
           "--max-redirs", "0", "--include", "--request", "GET", "--header", "Connection: close",
           "--user-agent", "recon-cockpit-b6/1", "http://127.0.0.1:8080/_ping"),
    DOCKER_VERSION: ("/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
           "--http1.1", "--proto", "=http", "--proto-redir", "=http", "--noproxy", "*", "--proxy", "",
           "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
           "--max-redirs", "0", "--include", "--request", "GET", "--header", "Connection: close",
           "--user-agent", "recon-cockpit-b6/1", "http://127.0.0.1:8080/version"),
    WINRM: ("/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
           "--http1.1", "--proto", "=http", "--proto-redir", "=http", "--noproxy", "*", "--proxy", "",
           "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
           "--max-redirs", "0", "--include", "--request", "GET", "--header", "Connection: close",
           "--user-agent", "recon-cockpit-b6/1", "http://127.0.0.1:8080/wsman"),
    HTTP_OPTIONS: ("/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
           "--http1.1", "--proto", "=http", "--proto-redir", "=http", "--noproxy", "*", "--proxy", "",
           "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
           "--max-redirs", "0", "--include", "--request", "OPTIONS", "--header", "Connection: close",
           "--user-agent", "recon-cockpit-owned-http-options/1", "http://127.0.0.1:8080/harbordesk/portal.html"),
}
from . import network_tools_whatweb_runtime as whatweb_runtime
from . import network_tools_rdp_runtime as rdp_runtime
from . import network_tools_smb2_runtime as smb2_runtime
from . import network_tools_ssh_algorithms_runtime as ssh_algorithms_runtime

FIXED_ARGV[WHATWEB] = whatweb_runtime.FIXED_ARGV
FIXED_ARGV[RDP] = rdp_runtime.FIXED_ARGV
FIXED_ARGV[SMB2] = smb2_runtime.FIXED_ARGV
FIXED_ARGV[SSH_ALGORITHMS] = ssh_algorithms_runtime.FIXED_ARGV
FIXED_ARGV[TLS_CERTIFICATE] = tuple(arg for arg in FIXED_ARGV[OPENSSL] if arg != "-brief") + (
    "-showcerts", "-nameopt", "RFC2253", "-verify_quiet", "-no_ticket")
FIXED_ARGV[SMTP_TLS] = FIXED_ARGV[OPENSSL] + ("-starttls", "smtp", "-name", "harbordesk.test")
FIXED_ARGV[LDAP_TLS] = FIXED_ARGV[OPENSSL] + ("-starttls", "ldap")
FIXED_ARGV[FTP_TLS] = FIXED_ARGV[OPENSSL] + ("-starttls", "ftp")
FIXED_ARGV[DIG_NSID] = tuple(arg for item in FIXED_ARGV[DIG] for arg in (
    ("+edns=0", "+bufsize=1232", "+nsid", "+nocookie", "+noednsnegotiation", "+nobesteffort")
    if item == "+noedns" else (item, "+authority") if item == "+answer" else (item,)))
FIXED_ARGV[DIG_AXFR] = tuple("AXFR" if item == "A" else item for item in FIXED_ARGV[DIG]) + (
    "+noednsnegotiation", "+nobesteffort", "+authority", "+noonesoa", "+nomultiline", "+norrcomments")

MODULES = ("tool_runtime_common", "tool_worker_common", "network_tools_runtime", "network_tools_whatweb_runtime", "network_tools_rdp_runtime", "network_tools_smb2_runtime", "network_tools_ssh_algorithms_runtime", "network_tools_ssh_algorithms_parser", "network_tools_dns_srv_parser", "network_tools_dns_nsid_parser", "network_tools_dns_axfr_parser", "network_tools_http_options_parser", "network_tools_snmp_next_parser", "network_tools_tls_certificate_parser", "network_tools_worker", "network_tools_execution", "network_tools_contract",
           "network_tools_lab_contract", "network_tools_fixture", "models", "worker", "execution",
           "isolation", "owned_lab_executor", "executor_worker", "owned_lab_contract",
           "assessment_contract", "tool_parameters", "tool_adapters")


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def execution_environment(tool_id):
    if tool_id == SSH_ALGORITHMS:
        return dict(ssh_algorithms_runtime.ENVIRONMENT)
    if type(tool_id) is not str or tool_id not in EXECUTABLES:
        raise ValueError("unsupported_network_tool")
    if tool_id == WHATWEB:
        return dict(whatweb_runtime.ENVIRONMENT)
    if tool_id == RDP:
        return dict(rdp_runtime.ENVIRONMENT)
    if tool_id == SMB2:
        return dict(smb2_runtime.ENVIRONMENT)
    value = {"LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"}
    if tool_id in (DIG, DIG_SRV, DIG_NSID, DIG_AXFR):
        value["UV_THREADPOOL_SIZE"] = "1"
    if tool_id == LDAP:
        # Disable every system/user LDAP default before libldap initializes.
        value["LDAPNOINIT"] = "1"
    if tool_id == KERBRUTE:
        # Go reserves virtual address space independently of its live heap.
        # The worker also enforces the reviewed task and address-space caps.
        value.update(GOMAXPROCS="1", GOMEMLIMIT="64MiB")
    if tool_id in (SNMP, SNMP_NEXT):
        # No host MIBs, per-host configuration, persistent engine state or
        # environment-supplied community can enter the numeric v2c request.
        value.update(MIBS="", MIBDIRS="", MIBFILES="", SNMPCONFPATH="/tool/no-snmp-config",
                     SNMP_PERSISTENT_DIR="/tool/no-snmp-state")
    return value


def _compiled(tool_id):
    if tool_id == SSH_ALGORITHMS:
        return ssh_algorithms_runtime.COMPILED[0]
    if tool_id == SMB2:
        return smb2_runtime.COMPILED[0]
    if tool_id == RDP:
        return rdp_runtime.COMPILED[0]
    if tool_id == WHATWEB:
        return whatweb_runtime.COMPILED[0]
    if tool_id == KERBRUTE:
        return "compiled:kerbrute-principals", "/tool/data/principals.txt", KERBRUTE_PRINCIPALS
    if tool_id == NMAP_SERVICE:
        return "compiled:nmap-service-services", "/tool/data/nmap-services", NMAP_SERVICE_SERVICES
    if tool_id == TLS_CERTIFICATE:
        from .network_tools_fixture import TLS_CERTIFICATE_CA_PEM
        return "compiled:fixture-ca", "/tool/data/fixture-ca.pem", TLS_CERTIFICATE_CA_PEM
    if tool_id in (OPENSSL, POSTGRESQL_TLS, MYSQL_TLS, SMTP_TLS, LDAP_TLS, FTP_TLS):
        from .network_tools_fixture import CA_PEM
        return "compiled:fixture-ca", "/tool/data/fixture-ca.pem", CA_PEM
    if tool_id in (DIG, DIG_SRV, DIG_NSID, DIG_AXFR):
        # No host resolver, search list, or user configuration enters the tool.
        return "compiled:resolver", "/etc/resolv.conf", b"# fixed TCP nameserver supplied by reviewed argv\n"
    if tool_id in (SSH, LDAP, FTP, SMTP, DOCKER_PING, DOCKER_VERSION, WINRM, HTTP_OPTIONS, REDIS, SNMP, SNMP_NEXT):
        return None  # These profiles need no configuration, credentials, or trust file.
    if tool_id == SMB:
        return "compiled:smb-config", "/tool/data/smb.conf", SMB_CONFIG
    if tool_id in (RPCINFO, SHOWMOUNT):
        return "compiled:rpc-netconfig", "/etc/netconfig", RPC_NETCONFIG
    raise ValueError("unsupported_network_tool")


def compiled_files(tool_id):
    """Retain existing profiles' bytes and close new profiles over fixed data."""
    if tool_id == WHATWEB:
        return whatweb_runtime.COMPILED
    first = _compiled(tool_id)
    files = () if first is None else (first,)
    if tool_id in (RPCINFO, SHOWMOUNT):
        files += (("compiled:rpc-services", "/etc/services", RPC_SERVICES),)
    if tool_id == NMAP_SERVICE:
        files += (("compiled:nmap-service-protocols", "/tool/data/nmap-protocols", NMAP_SERVICE_PROTOCOLS),
                  ("compiled:nmap-service-probes", "/tool/data/nmap-service-probes", NMAP_SERVICE_PROBES),
                  ("compiled:nmap-service-nse-disabled", "/tool/data/nse_main.lua", NMAP_SERVICE_NSE_SHIM))
    return files


def _compact_files(files):
    roots = sorted({str(Path(row[key]).parent) for row in files for key in ("source", "destination")
                    if LIBRARY.fullmatch(row[key])})
    if any(root not in SMB_ROOTS for root in roots):
        raise ValueError("unsupported_smb_library_root")
    def short(path):
        parent = str(Path(path).parent)
        return str(roots.index(parent)) + ":" + Path(path).name if parent in roots else path
    return roots, [[short(row["source"]), None if row["source"] == row["destination"] else short(row["destination"]),
                    row["size"], row["sha256"]] for row in files]


def compact_manifest(value):
    """Encode SMB's larger pinned closure without enlarging the JSON boundary."""
    if value["tool_id"] == WHATWEB:
        return whatweb_runtime.compact_manifest(value)
    if value["tool_id"] != SMB:
        return value
    roots, rows = _compact_files(value["files"])
    return {**value, "profile": SMB_PROFILE, "roots": roots, "files": rows}


def _expanded_files(value):
    if value.get("tool_id") == WHATWEB:
        return whatweb_runtime.expanded_files(value)
    if value.get("tool_id") != SMB:
        return value["files"]
    roots = value.get("roots")
    if (type(roots) is not list or not roots or len(roots) > len(SMB_ROOTS)
            or any(type(root) is not str or root not in SMB_ROOTS for root in roots)
            or roots != sorted(set(roots))):
        raise ValueError("invalid_smb_manifest_roots")
    def expand(path):
        if type(path) is not str:
            raise ValueError("invalid_smb_runtime_path")
        match = re.fullmatch(r"(0|[1-9][0-9]?):([A-Za-z0-9_.+-]+)", path)
        if match is not None:
            index = int(match[1])
            if index >= len(roots):
                raise ValueError("invalid_smb_runtime_root")
            return roots[index] + "/" + match[2]
        if path not in (EXECUTABLES[SMB], FIXED_ARGV[SMB][0], "compiled:smb-config", "/tool/data/smb.conf"):
            raise ValueError("invalid_smb_runtime_path")
        return path
    files = []
    for row in value["files"]:
        if type(row) is not list or len(row) != 4:
            raise ValueError("invalid_smb_runtime_row")
        source = expand(row[0])
        destination = source if row[1] is None else expand(row[1])
        files.append({"source": source, "destination": destination, "size": row[2], "sha256": row[3]})
    if _compact_files(files) != (roots, value["files"]):
        raise ValueError("noncanonical_smb_runtime_rows")
    return files


def runtime_files(manifest):
    validate_manifest(manifest)
    return _expanded_files(manifest)


def read_runtime_file(path, tool_id):
    return (_read_regular(path, maximum=SMB_MAX_FILE_BYTES) if tool_id == SMB else _read_regular(path))


def validate_manifest(value, *, tool_id=None):
    if type(value) is dict and value.get("tool_id") == SSH_ALGORITHMS:
        return ssh_algorithms_runtime.validate_manifest(value, tool_id=tool_id)
    if type(value) is dict and value.get("tool_id") == SMB2:
        return smb2_runtime.validate_manifest(value, tool_id=tool_id)
    if type(value) is dict and value.get("tool_id") == RDP:
        return rdp_runtime.validate_manifest(value, tool_id=tool_id)
    if type(value) is dict and value.get("tool_id") == WHATWEB:
        return whatweb_runtime.validate_manifest(value, tool_id=tool_id)
    smb = type(value) is dict and value.get("tool_id") == SMB
    if (type(value) is not dict or set(value) != {"version", "profile", "tool_id", "executable", "interpreter", "files"} | ({"roots"} if smb else set())
            or value["version"] != "1" or value["profile"] != (SMB_PROFILE if smb else PROFILE)
            or type(value["tool_id"]) is not str or value["tool_id"] not in EXECUTABLES
            or (tool_id is not None and value["tool_id"] != tool_id)
            or value["executable"] != FIXED_ARGV[value["tool_id"]][0]
            or type(value["interpreter"]) is not str or not LIBRARY.fullmatch(value["interpreter"])
            or type(value["files"]) is not list
            or not 2 + len(compiled_files(value["tool_id"])) <= len(value["files"]) <= (SMB_MAX_FILES if smb else 48)
            or len(encode(value)) > (SMB_MAX_MANIFEST_BYTES if smb else MAX_MANIFEST_BYTES)):
        raise ValueError("invalid_network_tool_manifest")
    compiled = {destination: (source, raw) for source, destination, raw in compiled_files(value["tool_id"])}
    destinations, total = set(), 0
    files = _expanded_files(value)
    for item in files:
        if (type(item) is not dict or set(item) != {"source", "destination", "sha256", "size"}
                or type(item["source"]) is not str or type(item["destination"]) is not str
                or type(item["size"]) is not int or not 1 <= item["size"] <= (SMB_MAX_FILE_BYTES if smb else MAX_FILE_BYTES)
                or type(item["sha256"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
                or any(".." in item[key] or "//" in item[key] for key in ("source", "destination"))):
            raise ValueError("invalid_network_tool_runtime_file")
        source, destination = item["source"], item["destination"]
        if destination == value["executable"]:
            accepted = (source in NMAP_SERVICE_EXECUTABLES if value["tool_id"] == NMAP_SERVICE
                        else source == EXECUTABLES[value["tool_id"]])
        elif destination in compiled:
            source_name, data = compiled[destination]
            accepted = (source == source_name and item["size"] == len(data)
                        and item["sha256"] == hashlib.sha256(data).hexdigest())
        else:
            accepted = bool(LIBRARY.fullmatch(source) and LIBRARY.fullmatch(destination))
        if not accepted or destination in destinations:
            raise ValueError("invalid_network_tool_runtime_path")
        destinations.add(destination)
        total += item["size"]
    required = {value["executable"], value["interpreter"]} | set(compiled)
    if (total > (SMB_MAX_RUNTIME_BYTES if smb else MAX_RUNTIME_BYTES) or not required <= destinations
            or files != sorted(files, key=lambda item: item["destination"])):
        raise ValueError("invalid_network_tool_runtime_closure")
    return value


def manifest_digest(value):
    return hashlib.sha256(encode(validate_manifest(value))).hexdigest()


def inspect_tool_runtime(tool_id, control):
    """Inspect the selected distribution ELF; never execute a tool on the host."""
    if type(tool_id) is not str or tool_id not in EXECUTABLES:
        raise ValueError("unsupported_network_tool")
    control.check()
    if tool_id == SSH_ALGORITHMS:
        return ssh_algorithms_runtime.inspect_runtime(control)
    if tool_id == SMB2:
        return smb2_runtime.inspect_runtime(control)
    if tool_id == RDP:
        return rdp_runtime.inspect_runtime(control)
    if tool_id == WHATWEB:
        return whatweb_runtime.inspect_runtime(control)
    executable = EXECUTABLES[tool_id]
    if tool_id == NMAP_SERVICE:
        executable = None
        for candidate in NMAP_SERVICE_EXECUTABLES:
            control.check()
            if Path(candidate).is_file():
                resolved = str(Path(candidate).resolve(strict=True))
                if resolved not in NMAP_SERVICE_EXECUTABLES:
                    raise IsolationUnavailable("Unreviewed Nmap service executable location")
                if _read_regular(resolved).startswith(b"\x7fELF"):
                    executable = resolved
                    break
        if executable is None:
            raise IsolationUnavailable("A supported distribution Nmap ELF is required; wrappers are refused")
    elif not _read_regular(executable).startswith(b"\x7fELF"):
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
        raw = read_runtime_file(source, tool_id)
        files.append({"source": source, "destination": destination, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    for source, destination, raw in compiled_files(tool_id):
        files.append({"source": source, "destination": destination, "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest()})
    return validate_manifest(compact_manifest({"version": "1", "profile": PROFILE, "tool_id": tool_id,
        "executable": FIXED_ARGV[tool_id][0], "interpreter": interpreters[0],
        "files": sorted(files, key=lambda item: item["destination"])}))


def runtime_source_mounts(manifest):
    return [(path, path) for path in sorted({item["source"] for item in runtime_files(manifest)
                                            if not item["source"].startswith("compiled:")})]


def _snapshot(manifest, control):
    validate_manifest(manifest)
    data = _compiled(manifest["tool_id"])
    source, _, raw = data if data is not None else (None, None, None)
    if manifest["tool_id"] == WHATWEB:
        additional = tuple((source, raw) for source, _, raw in compiled_files(WHATWEB)[1:])
        return sealed_snapshots({**manifest, "files": runtime_files(manifest)}, source, raw, control,
                                additional_compiled=additional)
    if manifest["tool_id"] == SMB:
        return sealed_snapshots({**manifest, "files": runtime_files(manifest)}, source, raw, control,
                                maximum_file_bytes=SMB_MAX_FILE_BYTES)
    if manifest["tool_id"] in (RPCINFO, SHOWMOUNT, NMAP_SERVICE):
        additional = tuple((source, raw) for source, _, raw in compiled_files(manifest["tool_id"])[1:])
        return sealed_snapshots(manifest, source, raw, control, additional_compiled=additional)
    return sealed_snapshots(manifest, source, raw, control)


def _command(lab, bootstrap, manifest, descriptors, nonce, commitment, *, service_web=False):
    stdlib, files = bootstrap
    tool_files = runtime_files(manifest)
    tool_paths = {item["destination"] for item in tool_files}
    argv = [_trusted_program("bwrap"), "--unshare-user", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--unshare-cgroup", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--cap-add", "CAP_SETPCAP", "--die-with-parent", "--new-session", "--clearenv",
            "--setenv", "LC_ALL", "C", "--setenv", "MALLOC_ARENA_MAX", "1",
            "--chdir", "/", "--proc", "/proc", "--dev", "/dev",
            "--ro-bind", stdlib, stdlib]
    if manifest["tool_id"] in (RPCINFO, SHOWMOUNT):
        # AUTH_SYS may contain a machine name; never expose the host identity.
        argv += ["--hostname", "reconlab"]
    for source, destination in files:
        if destination not in tool_paths and Path(destination).name not in {"nft", "bwrap", "nsenter"}:
            argv += ["--ro-bind", source, destination]
    directory = Path(__file__).parent
    extra_modules = (("service_web_execution", "service_web_contract", "service_web_lab_contract",
                      "service_web_fixture", "http_headers_fixture", "web_tools_fixture") if service_web else ())
    for name in (*MODULES, *extra_modules):
        argv += ["--ro-bind", str(directory / (name + ".py")), "/app/recon_cockpit/secure_agent/" + name + ".py"]
    for destination in ("/app/recon_cockpit/__init__.py", "/app/recon_cockpit/secure_agent/__init__.py"):
        argv += ["--ro-bind", str(directory / "__init__.py"), destination]
    for item, fd in zip(tool_files, descriptors):
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
            (_command(lab, bootstrap, manifest, descriptors, launch["launch"]["nonce"], commitment, service_web=True)
             if launch.get("mode") == "owned_service_web_lab" else
             _command(lab, bootstrap, manifest, descriptors, launch["launch"]["nonce"], commitment)), raw,
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
