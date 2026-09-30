"""Strict bounded observation parser; Nmap output never grants authority."""

from __future__ import annotations

PARSER_VERSION = "nmap-tcp-connect-xml-v1"
MAX_XML_BYTES = 16384


def parse_nmap_xml(raw: bytes) -> dict:
    """Accept only a completed singleton IPv4 TCP-connect scan.

    The bare doctype emitted by Nmap is harmless; all entity declarations,
    external identifiers and internal subsets are refused before expansion.
    Service table guesses are deliberately not returned as service identity.
    """
    from xml.parsers import expat

    if type(raw) is not bytes or not raw or len(raw) > MAX_XML_BYTES:
        raise ValueError("invalid_nmap_xml_size")
    try:
        raw.decode("utf-8", "strict")
    except UnicodeError:
        raise ValueError("invalid_nmap_xml_encoding") from None
    parser = expat.ParserCreate("UTF-8")
    stack = []
    nodes = 0
    found = {}
    allowed = {
        (): {"nmaprun"}, ("nmaprun",): {"scaninfo", "verbose", "debugging", "host", "runstats"},
        ("nmaprun", "host"): {"status", "address", "hostnames", "ports", "times"},
        ("nmaprun", "host", "ports"): {"port", "extraports"},
        ("nmaprun", "host", "ports", "extraports"): {"extrareasons"},
        ("nmaprun", "host", "ports", "port"): {"state", "service"},
        ("nmaprun", "runstats"): {"finished", "hosts"},
    }

    def start(name, attributes):
        nonlocal nodes
        nodes += 1
        path = (*stack, name)
        if (nodes > 64 or len(path) > 6 or name not in allowed.get(tuple(stack), set())
                or path in found or len(attributes) > 20
                or any(len(key) > 64 or len(value.encode("utf-8")) > 2048
                       for key, value in attributes.items())):
            raise ValueError("invalid_nmap_xml_structure")
        found[path] = dict(attributes)
        stack.append(name)

    def end(name):
        if not stack or stack.pop() != name:
            raise ValueError("invalid_nmap_xml_structure")

    def text(value):
        if value.strip():
            raise ValueError("unexpected_nmap_xml_text")

    def doctype(name, system_id, public_id, internal_subset):
        if name != "nmaprun" or system_id is not None or public_id is not None or internal_subset:
            raise ValueError("forbidden_nmap_xml_doctype")

    def forbidden(*_):
        raise ValueError("forbidden_nmap_xml_entity")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.ProcessingInstructionHandler = forbidden
    try:
        parser.Parse(raw, True)
    except (expat.ExpatError, UnicodeError, RecursionError):
        raise ValueError("invalid_nmap_xml") from None
    root = found.get(("nmaprun",), {})
    scan = found.get(("nmaprun", "scaninfo"), {})
    host = ("nmaprun", "host")
    address = found.get((*host, "address"), {})
    port = found.get((*host, "ports", "port"), {})
    state = found.get((*host, "ports", "port", "state"), {}).get("state")
    extra = found.get((*host, "ports", "extraports"))
    if extra is not None:
        reasons = found.get((*host, "ports", "extraports", "extrareasons"), {})
        if (port or set(extra) != {"state", "count"} or extra["state"] not in {"closed", "filtered"}
                or extra["count"] != "1" or reasons.get("count") != "1"
                or reasons.get("proto") != "tcp" or reasons.get("ports") != "8080"):
            raise ValueError("nmap_xml_extra_ports_mismatch")
        port = {"protocol": "tcp", "portid": "8080"}
        state = extra["state"]
    finished = found.get(("nmaprun", "runstats", "finished"), {})
    hosts = found.get(("nmaprun", "runstats", "hosts"), {})
    if (root.get("scanner") != "nmap" or scan.get("type") != "connect"
            or scan.get("protocol") != "tcp" or scan.get("numservices") != "1"
            or scan.get("services") != "8080" or address != {"addr": "127.0.0.1", "addrtype": "ipv4"}
            or found.get((*host, "status"), {}).get("state") != "up"
            or port != {"protocol": "tcp", "portid": "8080"}
            or state not in {"open", "closed", "filtered"}
            or finished.get("exit") != "success" or hosts != {"up": "1", "down": "0", "total": "1"}):
        raise ValueError("nmap_xml_scope_or_completion_mismatch")
    return {"parser_version": PARSER_VERSION,
            "results": [{"target": "127.0.0.1", "port": 8080, "state": state}]}
