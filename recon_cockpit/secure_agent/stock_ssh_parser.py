"""Bounded observations for the two closed stock SSH compatibility endpoints.

The parser never grants authority or authenticates a host. Its separate version
preserves OpenSSH's portable suffix without widening any accepted parser. The
XML mechanics mirror the accepted singleton Nmap parser; only the SSH identity
grammar and this profile's finite endpoint binding differ.
"""

import re

from . import network_tools_parser as native

NMAP = "configurable_nmap_service_v1"
SSH = "configurable_ssh_host_keys_v1"
VERSIONS = {NMAP: "stock-ssh-nmap-service-xml-v1", SSH: "stock-ssh-keyscan-rsa-v1"}
MAX_OUTPUT_BYTES = MAX_XML_BYTES = 8192
VERSION = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}(?:p[0-9]{1,3})?")


def parser_version(tool_id):
    if type(tool_id) is not str or tool_id not in VERSIONS:
        raise ValueError("unsupported_stock_ssh_parser")
    return VERSIONS[tool_id]


def endpoint(configuration):
    if type(configuration) is not str or configuration not in ("A", "B"):
        raise ValueError("invalid_stock_ssh_parser_configuration")
    return {"target": "10.77.0.20", "port": 2222} if configuration == "A" else {
        "target": "172.23.0.20", "port": 12222}


def _validate_nmap(value, target, port, version):
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "target", "port",
            "state", "identification", "service"} or value["parser_version"] != version
            or value["kind"] != "service_identification" or value["target"] != target
            or type(value["port"]) is not int or value["port"] != port or value["state"] != "open"
            or type(value["identification"]) is not str
            or value["identification"] not in {"identified", "unidentified"}):
        raise ValueError("invalid_stock_ssh_nmap_observation")
    service = value["service"]
    if value["identification"] == "unidentified":
        if service is not None:
            raise ValueError("unidentified_stock_ssh_has_identity")
        return dict(value)
    if (type(service) is not dict or set(service) != {"name", "product", "version"}
            or service["name"] != "ssh" or service["product"] != "OpenSSH"
            or type(service["version"]) is not str or VERSION.fullmatch(service["version"]) is None):
        raise ValueError("unsupported_stock_ssh_service_identity")
    return {**value, "service": dict(service)}


def validate_result(tool_id, value, configuration):
    version, selected = parser_version(tool_id), endpoint(configuration)
    if tool_id == NMAP:
        return _validate_nmap(value, selected["target"], selected["port"], version)
    if (type(value) is not dict or value.get("parser_version") != version
            or value.get("target") != selected["target"] or type(value.get("port")) is not int
            or value["port"] != selected["port"]):
        raise ValueError("invalid_stock_ssh_key_observation")
    unscoped = {key: item for key, item in value.items() if key not in {"target", "port"}}
    unscoped["parser_version"] = native.parser_version(native.SSH_TOOL_ID)
    validated = native.validate_result(native.SSH_TOOL_ID, unscoped)
    return {**validated, "parser_version": version, **selected}


def validate_input(tool_id, raw, stderr, configuration, truncated=False):
    parser_version(tool_id)
    selected = endpoint(configuration)
    if (type(raw) is not bytes or type(stderr) is not bytes or not (raw or stderr)
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES or type(truncated) is not bool or truncated):
        raise ValueError("invalid_stock_ssh_output_size")
    return selected


def parse_output(tool_id, raw, stderr=b"", *, configuration, truncated=False):
    selected = validate_input(tool_id, raw, stderr, configuration, truncated)
    if tool_id == NMAP:
        if stderr:
            raise ValueError("unexpected_stock_ssh_nmap_diagnostics")
        return _parse_nmap(raw, selected["target"], selected["port"], parser_version(tool_id))
    banner = re.compile(r"# " + re.escape(selected["target"]) + ":" + str(selected["port"])
                        + r" SSH-2\.0-[\x20-\x7e]{1,200}")
    if stderr:
        diagnostic = native._lines(stderr)
        if len(diagnostic) != 1 or len(stderr.splitlines()) != 1 or banner.fullmatch(diagnostic[0]) is None:
            raise ValueError("unexpected_stock_ssh_keyscan_diagnostics")
    lines = native._lines(raw)
    if len(lines) != len(raw.splitlines()):
        raise ValueError("invalid_stock_ssh_keyscan_output")
    if len(lines) == 2 and banner.fullmatch(lines[0]) is not None:
        if stderr:
            raise ValueError("duplicate_stock_ssh_keyscan_banner")
        lines = lines[1:]
    if len(lines) != 1:
        raise ValueError("invalid_stock_ssh_key_count")
    match = re.fullmatch(r"\[" + re.escape(selected["target"]) + r"\]:" + str(selected["port"])
                         + r" ssh-rsa ([A-Za-z0-9+/=]{1,1024})", lines[0])
    if match is None:
        raise ValueError("invalid_stock_ssh_keyscan_endpoint")
    encoded = match.group(1)
    return validate_result(tool_id, {"parser_version": parser_version(tool_id),
        "kind": "ssh_host_keys", **selected, "key_type": "ssh-rsa", "key_base64": encoded,
        **native._ssh_key_facts(encoded), "trust": "unverified"}, configuration)


def _parse_nmap(raw, target, expected_port, parser_version):
    """Shared XML mechanics; callers validate their own closed endpoint profile."""
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
                "numservices": "1", "services": str(expected_port)}
            or found.get((*host, "address")) != {"addr": target, "addrtype": "ipv4"}
            or found.get((*host, "status"), {}).get("state") != "up"
            or found.get(port) != {"protocol": "tcp", "portid": str(expected_port)}
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
    return _validate_nmap({"parser_version": parser_version, "kind": "service_identification",
        "target": target, "port": expected_port, "state": "open",
        "identification": "identified" if service is not None else "unidentified", "service": service},
        target, expected_port, parser_version)
