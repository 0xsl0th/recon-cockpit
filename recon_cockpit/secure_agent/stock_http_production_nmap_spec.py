"""Fixed production HTTP recognition; no extra requests or execution authority.

The accepted diagnostic's probe bytes remain unchanged. This distinct payload
adds bounded recognition for Apache's Date-before-Server header and optional
parenthesized distribution label. The matched version must still be observed
in the response, and usefulness is graded against the original retained bytes.
"""

PROFILE = "stock-http-production-nmap-runtime-v1"
PROBE_SOURCE = "compiled:stock-http-production-nmap-probes"
PROBE_DESTINATION = "/tool/data/nmap-service-probes"
RECOGNITION_REVISION = "apache-date-and-distribution-v1"
APACHE_PATTERN = (
    br"^HTTP/1\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\r\n"
    br"(?:Date: [\x20-\x7e]{1,64}\r\n)?"
    br"Server: Apache/([0-9]{1,3}(?:\.[0-9]{1,3}){0,2})"
    br"(?: \([A-Za-z0-9 ._+\-]{1,64}\))?\r\n"
)
PROBES = (
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
    b"match http m%" + APACHE_PATTERN + b"% p/Apache httpd/ v/$1/\n"
    br"match http m%^HTTP/1\.[01] [1-5][0-9]{2} [A-Za-z][A-Za-z ]{0,47}\r\n%" + b"\n"
)


def compiled_files():
    # The selection digest imports only pure constants. Runtime construction
    # may import the existing reviewed files after its own launch/preflight gate.
    from .network_tools_runtime import compiled_files as native_files, NMAP_SERVICE
    return tuple((PROBE_SOURCE, destination, PROBES) if destination == PROBE_DESTINATION
                 else (source, destination, raw)
                 for source, destination, raw in native_files(NMAP_SERVICE))
