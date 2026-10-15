"""Fixed stock SSH identification using only Nmap's empty TCP NULL probe.

The optional portable-version suffix is preserved. A bounded printable comment
is untrusted evidence, never a version, target, instruction or source of scope.
This distinct payload does not change accepted synthetic or HTTP probe bytes.
"""

PROFILE = "stock-ssh-nmap-runtime-v1"
PROBE_SOURCE = "compiled:stock-ssh-nmap-probes"
PROBE_DESTINATION = "/tool/data/nmap-service-probes"
RECOGNITION_REVISION = "openssh-portable-suffix-null-only-v1"
VERSION_PATTERN = br"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}(?:p[0-9]{1,3})?"
SSH_PATTERN = (br"^SSH-2\.0-OpenSSH_(" + VERSION_PATTERN
               + br")(?: [\x20-\x7e]{1,200})?\r\n$")
PROBES = (
    b"# Reviewed TCP NULL identification only; no application payload or other probes.\n"
    b"Probe TCP NULL q||\n"
    b"totalwaitms 400\n"
    b"tcpwrappedms 100\n"
    b"match ssh m%" + SSH_PATTERN + b"% p/OpenSSH/ v/$1/\n"
)


def compiled_files():
    from .network_tools_runtime import compiled_files as native_files, NMAP_SERVICE
    return tuple((PROBE_SOURCE, destination, PROBES) if destination == PROBE_DESTINATION
                 else (source, destination, raw)
                 for source, destination, raw in native_files(NMAP_SERVICE))
