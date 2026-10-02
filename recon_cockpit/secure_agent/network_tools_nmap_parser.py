"""Strict singleton service-probe observations; native output is never authority."""

from __future__ import annotations

import re


PARSER_VERSION = "nmap-service-xml-v1"
MAX_XML_BYTES = 8192
VERSION = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}")


def validate_result(value):
    """Release only reviewed probe identities, never port-table guesses."""
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "target", "port",
            "state", "identification", "service"} or value["parser_version"] != PARSER_VERSION
            or value["kind"] != "service_identification" or value["target"] != "127.0.0.1"
            or type(value["port"]) is not int or value["port"] != 8080 or value["state"] != "open"
            or type(value["identification"]) is not str
            or value["identification"] not in {"identified", "unidentified"}):
        raise ValueError("invalid_nmap_service_observation")
    service = value["service"]
    if value["identification"] == "unidentified":
        if service is not None:
            raise ValueError("unidentified_nmap_service_has_identity")
        return dict(value)
    if (type(service) is not dict or set(service) != {"name", "product", "version"}
            or type(service["name"]) is not str or service["name"] not in {"http", "ssh"}):
        raise ValueError("invalid_nmap_service_identity")
    product, version = service["product"], service["version"]
    if service["name"] == "http" and product is None and version is None:
        return {**value, "service": dict(service)}
    if (type(product) is not str or type(version) is not str or VERSION.fullmatch(version) is None
            or (service["name"] == "ssh" and product != "OpenSSH")
            or (service["name"] == "http" and product not in {"nginx", "Apache httpd"})):
        raise ValueError("unsupported_nmap_service_product")
    return {**value, "service": dict(service)}


def parse_nmap_service_xml(raw: bytes) -> dict:
    """Require completed, single-host TCP-connect XML and bounded probe matches.

    Only the bare Nmap doctype is allowed. Unmatched fingerprint text and names
    from the port table remain raw evidence and cannot establish service identity.
    """
    from xml.parsers import expat

    if type(raw) is not bytes or not raw or len(raw) > MAX_XML_BYTES:
        raise ValueError("invalid_nmap_service_xml_size")
    try:
        raw.decode("utf-8", "strict")
    except UnicodeError:
        raise ValueError("invalid_nmap_service_xml_encoding") from None
    parser = expat.ParserCreate("UTF-8")
    stack, found = [], {}
    allowed = {
        (): {"nmaprun"}, ("nmaprun",): {"scaninfo", "verbose", "debugging", "host", "runstats"},
        ("nmaprun", "host"): {"status", "address", "hostnames", "ports", "times"},
        ("nmaprun", "host", "ports"): {"port"},
        ("nmaprun", "host", "ports", "port"): {"state", "service"},
        ("nmaprun", "runstats"): {"finished", "hosts"},
    }
    attributes_for = {
        "nmaprun": {"scanner", "args", "start", "startstr", "version", "xmloutputversion"},
        "scaninfo": {"type", "protocol", "numservices", "services"},
        "verbose": {"level"}, "debugging": {"level"}, "host": {"starttime", "endtime"},
        "status": {"state", "reason", "reason_ttl"}, "address": {"addr", "addrtype"},
        "hostnames": set(), "ports": set(), "port": {"protocol", "portid"},
        "state": {"state", "reason", "reason_ttl"},
        "service": {"name", "method", "conf", "product", "version", "servicefp"},
        "times": {"srtt", "rttvar", "to"}, "runstats": set(),
        "finished": {"time", "timestr", "summary", "elapsed", "exit"},
        "hosts": {"up", "down", "total"},
    }

    def start(name, attributes):
        path = (*stack, name)
        if (len(found) >= 32 or len(path) > 6 or name not in allowed.get(tuple(stack), set())
                or path in found or not set(attributes) <= attributes_for[name]
                or any(len(item.encode("utf-8")) > 2048 for item in attributes.values())):
            raise ValueError("invalid_nmap_service_xml_structure")
        found[path] = dict(attributes)
        stack.append(name)

    def end(name):
        if not stack or stack.pop() != name:
            raise ValueError("invalid_nmap_service_xml_structure")

    def text(value):
        if value.strip():
            raise ValueError("unexpected_nmap_service_xml_text")

    def doctype(name, system_id, public_id, internal_subset):
        if name != "nmaprun" or system_id is not None or public_id is not None or internal_subset:
            raise ValueError("forbidden_nmap_service_xml_doctype")

    def forbidden(*_):
        raise ValueError("forbidden_nmap_service_xml_entity")

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler, parser.StartDoctypeDeclHandler = text, doctype
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.ProcessingInstructionHandler = forbidden
    try:
        parser.Parse(raw, True)
    except (expat.ExpatError, UnicodeError, RecursionError):
        raise ValueError("invalid_nmap_service_xml") from None
    root, host = ("nmaprun",), ("nmaprun", "host")
    port = (*host, "ports", "port")
    if (found.get(root, {}).get("scanner") != "nmap"
            or found.get((*root, "scaninfo")) != {"type": "connect", "protocol": "tcp",
                "numservices": "1", "services": "8080"}
            or found.get((*host, "address")) != {"addr": "127.0.0.1", "addrtype": "ipv4"}
            or found.get((*host, "status"), {}).get("state") != "up"
            or found.get(port) != {"protocol": "tcp", "portid": "8080"}
            or found.get((*port, "state"), {}).get("state") != "open"
            or found.get((*root, "runstats", "finished"), {}).get("exit") != "success"
            or found.get((*root, "runstats", "hosts")) != {"up": "1", "down": "0", "total": "1"}):
        raise ValueError("nmap_service_scope_or_completion_mismatch")
    native, service = found.get((*port, "service")), None
    if native is not None:
        if native.get("method") == "table":
            if (not {"name", "method", "conf"} <= set(native)
                    or not set(native) <= {"name", "method", "conf", "servicefp"}
                    or native["conf"] != "3"):
                raise ValueError("unsupported_nmap_table_service")
        elif native.get("method") == "probed":
            if (not {"name", "method", "conf"} <= set(native)
                    or not set(native) <= {"name", "method", "conf", "product", "version"}
                    or native["conf"] != "10"):
                raise ValueError("unsupported_nmap_probe_service")
            service = {"name": native["name"], "product": native.get("product"), "version": native.get("version")}
        else:
            raise ValueError("unsupported_nmap_service_method")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "service_identification",
        "target": "127.0.0.1", "port": 8080, "state": "open",
        "identification": "identified" if service is not None else "unidentified", "service": service})
