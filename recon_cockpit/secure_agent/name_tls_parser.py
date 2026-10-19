"""Strict detached observations; no fixture key, owner state or authority."""

import hashlib
import ipaddress
import json
import re

from . import name_tls_wire as wire
from .http_headers_parser import parse_http_headers

PARSER_VERSION = "owned-name-tls-parser-v1"
MAX_INPUT_BYTES = 131072
MAX_OUTPUT_BYTES = 8192
STREAMS = ("request", "delivered_request", "original_response", "proposed_response",
           "delivered_response", "stdout", "stderr")
BOUNDS = {"dns": (512, 4096, 8192), "http": (256, 2048, 2048), "tls": (8192, 16384, 8192)}
_HEX = re.compile(r"[0-9a-f]{64}")
_DIG_PROBE_DENIED_TEXT = b"net.c:136:try_proto(): socket(): Operation not permitted (1)\n"
_DIG_STDERR_MARKER = "socket_probe_denied_text"


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("name_tls_duplicate_json_key")
        value[key] = item
    return value


def _constant(_):
    raise ValueError("name_tls_json_number")


def load_json(raw, maximum=MAX_OUTPUT_BYTES):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("name_tls_json_size")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique,
                           parse_constant=_constant, parse_float=_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("name_tls_json") from error
    if type(value) is not dict:
        raise ValueError("name_tls_json_object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError("name_tls_json_depth")
        children = item.values() if type(item) is dict else item if type(item) is list else ()
        pending.extend((child, depth + 1) for child in children)
    return value


def encode_input(operation, *, configuration, case, request, delivered_request, original_response,
                 proposed_response, delivered_response, stdout, stderr, exit_code, stop_reason, truncated=False):
    wire.selection(configuration, case)
    if type(operation) is not str or operation not in BOUNDS:
        raise ValueError("name_tls_parser_operation")
    if (type(exit_code) is not int or not -255 <= exit_code <= 255 or type(truncated) is not bool
            or stop_reason not in (None, "timeout", "output_limit", "cancelled")):
        raise ValueError("name_tls_native_status")
    values = (request, delivered_request, original_response, proposed_response, delivered_response, stdout, stderr)
    request_cap, response_cap, output_cap = BOUNDS[operation]
    caps = (request_cap, request_cap, response_cap, response_cap, response_cap, output_cap, output_cap)
    if any(type(raw) is not bytes or len(raw) > cap for raw, cap in zip(values, caps)) or len(stdout) + len(stderr) > output_cap:
        raise ValueError("name_tls_stream_bound")
    header = {"schema_version": "1", "operation": operation, "configuration": configuration, "case": case,
              "lengths": dict(zip(STREAMS, map(len, values))), "exit_code": exit_code,
              "stop_reason": stop_reason, "truncated": truncated}
    encoded = json.dumps(header, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    raw = len(encoded).to_bytes(4, "big") + encoded + b"".join(values)
    if len(encoded) > 2048 or len(raw) > MAX_INPUT_BYTES:
        raise ValueError("name_tls_parser_input_limit")
    return raw


def decode_input(raw):
    if type(raw) is not bytes or not 4 < len(raw) <= MAX_INPUT_BYTES:
        raise ValueError("name_tls_parser_input_limit")
    size = int.from_bytes(raw[:4], "big")
    if not 0 < size <= 2048 or size + 4 > len(raw):
        raise ValueError("name_tls_parser_header")
    header = load_json(raw[4:4 + size], 2048)
    if (set(header) != {"schema_version", "operation", "configuration", "case", "lengths", "exit_code", "stop_reason", "truncated"}
            or header["schema_version"] != "1" or type(header["lengths"]) is not dict
            or set(header["lengths"]) != set(STREAMS)):
        raise ValueError("name_tls_parser_header")
    position, streams = 4 + size, {}
    for name in STREAMS:
        length = header["lengths"][name]
        if type(length) is not int or length < 0 or position + length > len(raw):
            raise ValueError("name_tls_parser_stream_length")
        streams[name] = raw[position:position + length]
        position += length
    if position != len(raw):
        raise ValueError("name_tls_parser_trailing")
    reproduced = encode_input(header["operation"], configuration=header["configuration"], case=header["case"],
                              exit_code=header["exit_code"], stop_reason=header["stop_reason"],
                              truncated=header["truncated"], **streams)
    if reproduced != raw:
        raise ValueError("name_tls_parser_noncanonical_frame")
    return header, streams


def _lines(raw):
    if type(raw) is not bytes or not raw or len(raw) > 8192 or b"\0" in raw or b"\r" in raw:
        raise ValueError("name_tls_text_output")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("name_tls_text_output") from error
    if len(lines) > 128 or any(len(line) > 1024 or any(ord(c) < 32 and c != "\t" for c in line) for line in lines):
        raise ValueError("name_tls_text_output")
    return [line for line in lines if line]


def _dig_stderr(stderr):
    if type(stderr) is not bytes or stderr not in (b"", _DIG_PROBE_DENIED_TEXT):
        raise ValueError("name_tls_dig_stderr")
    return _DIG_STDERR_MARKER if stderr else None


def parse_dig_output(stdout, stderr, *, configuration, case):
    row = wire.selection(configuration, case)
    diagnostic = _dig_stderr(stderr)
    lines = _lines(stdout)
    if len(lines) < 8 or lines.pop(0) != ";; Got answer:":
        raise ValueError("name_tls_dig_header")
    header = re.fullmatch(r";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ([0-9]{1,5})", lines.pop(0))
    flags = re.fullmatch(r";; flags: (qr(?: aa)?(?: ra)?); QUERY: 1, ANSWER: ([0-8]), AUTHORITY: ([0-8]), ADDITIONAL: ([0-8])", lines.pop(0))
    if header is None or flags is None or int(header[1]) > 65535:
        raise ValueError("name_tls_dig_header")
    count = list(map(int, flags.groups()[1:]))
    if sum(count) > 8 or lines.pop(0) != ";; QUESTION SECTION:":
        raise ValueError("name_tls_dig_question")
    if not re.fullmatch(r";harbordesk\.test\.[ \t]+IN[ \t]+A", lines.pop(0)):
        raise ValueError("name_tls_dig_question")
    records = []
    types = {"A": 1, "NS": 2, "CNAME": 5, "AAAA": 28}
    for section, total in zip(("answer", "authority", "additional"), count):
        if total:
            if not lines or lines.pop(0) != f";; {section.upper()} SECTION:":
                raise ValueError("name_tls_dig_section")
        for _ in range(total):
            if not lines:
                raise ValueError("name_tls_dig_record")
            match = re.fullmatch(r"([A-Za-z0-9_.-]{1,254}\.)[ \t]+([0-9]{1,10})[ \t]+IN[ \t]+(A|AAAA|CNAME|NS)[ \t]+([A-Za-z0-9_.:-]{1,255})", lines.pop(0))
            if match is None or int(match[2]) > 0xffffffff:
                raise ValueError("name_tls_dig_record")
            kind, data = types[match[3]], match[4]
            if kind in (1, 28):
                address = ipaddress.ip_address(data)
                if address.version != (4 if kind == 1 else 6):
                    raise ValueError("name_tls_dig_address")
                data = str(address)
            elif not data.endswith("."):
                raise ValueError("name_tls_dig_name")
            records.append({"section": section, "name": match[1].lower(), "type": kind, "class": 1,
                            "ttl": int(match[2]), "data": data.lower()})
    if len(lines) != 4 or not re.fullmatch(r";; Query time: [0-9]{1,6} msec", lines[0]):
        raise ValueError("name_tls_dig_statistics")
    server = rf";; SERVER: {re.escape(row[0])}#{row[1]}\({re.escape(row[0])}\) ?\(TCP\)"
    size = re.fullmatch(r";; MSG SIZE  rcvd: ([0-9]{1,4})", lines[3])
    if (not re.fullmatch(server, lines[1]) or not re.fullmatch(r";; WHEN: [ -~]{1,128}", lines[2])
            or size is None or not 12 <= int(size[1]) <= 4094):
        raise ValueError("name_tls_dig_statistics")
    flag_value = 0x8000 | (0x400 if "aa" in flags[1].split() else 0) | (0x80 if "ra" in flags[1].split() else 0)
    semantic = {"schema_version": "1", "question": {"name": wire.NAME, "class": 1, "type": 1},
                "transaction_id": int(header[1]), "flags": flag_value, "records": records}
    return {"semantic": semantic, "response_message_bytes": int(size[1]), "transport": "tcp",
            "resolver_address": row[0], "resolver_port": row[1], "stderr_diagnostic": diagnostic}


def _http(raw):
    facts = parse_http_headers(raw)
    header, _, body = raw.partition(b"\r\n\r\n")
    if len(header) + 4 > 1024:
        raise ValueError("name_tls_http_header_limit")
    locations = [line.split(b":", 1)[1].strip() for line in header.split(b"\r\n")[1:]
                 if line.split(b":", 1)[0].lower() == b"location"]
    if len(locations) > 1:
        raise ValueError("name_tls_http_location_duplicate")
    return {"status_code": facts["status_code"], "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "location_sha256": hashlib.sha256(locations[0]).hexdigest() if locations else None,
            "response_sha256": hashlib.sha256(raw).hexdigest()}


def _tls_native(stdout, stderr, configuration, case, exit_code):
    row = wire.selection(configuration, case)
    if stdout:
        raise ValueError("name_tls_openssl_stdout")
    lines = _lines(stderr)
    if lines and lines[0] == "Connecting to " + row[2]:
        lines.pop(0)
    if case in ("N11", "N12", "N13", "N16"):
        expected = {"N11": (62, "hostname mismatch"), "N12": (20, "unable to get local issuer certificate"),
                    "N13": (10, "certificate has expired")}
        if exit_code == 0 or any("Verification: OK" in line or "Verified peername:" in line for line in lines):
            raise ValueError("name_tls_expected_native_tls_refusal")
        if case == "N16":
            if not any("tlsv1 alert protocol version" in line for line in lines):
                raise ValueError("name_tls_protocol_refusal_missing")
            failure = "protocol_version"
        else:
            code, message = expected[case]
            if f"verify error:num={code}:{message}" not in lines:
                raise ValueError("name_tls_verification_refusal_missing")
            failure = {"N11": "certificate_name", "N12": "certificate_issuer", "N13": "certificate_expired"}[case]
        # All error output stays inert. A particular native error is evidence,
        # not a substitute for the independent fixed-runtime and wire checks.
        return {"verification": "failed", "failure": failure, "protocol": None, "cipher": None, "peer_name": None}
    if exit_code != 0 or not lines or lines.pop(0) != "CONNECTION ESTABLISHED":
        raise ValueError("name_tls_native_handshake_incomplete")
    if lines and lines[-1] == "DONE":
        lines.pop()
    fields = {}
    required = {"Protocol version", "Ciphersuite", "Peer certificate", "Verification", "Verified peername"}
    optional = {"Hash used", "Signature type", "Server Temp Key", "Peer Temp Key", "Peer signing digest",
                "Peer signature type", "Negotiated TLS1.3 group"}
    for line in lines:
        key, separator, value = line.partition(": ")
        if not separator or key not in required | optional or key in fields or not value:
            raise ValueError("name_tls_openssl_brief")
        fields[key] = value
    if (not required <= fields.keys() or fields["Protocol version"] != "TLSv1.3"
            or fields["Ciphersuite"] != "TLS_AES_256_GCM_SHA384" or fields["Verification"] != "OK"
            or fields["Verified peername"] != "harbordesk.test"
            or fields["Peer certificate"] not in ("CN=harbordesk.test", "CN = harbordesk.test")):
        raise ValueError("name_tls_openssl_verification")
    groups = [fields[k] for k in ("Server Temp Key", "Peer Temp Key", "Negotiated TLS1.3 group") if k in fields]
    if not groups or any(value not in ("ECDH, prime256v1, 256 bits", "prime256v1", "P-256", "secp256r1") for value in groups):
        raise ValueError("name_tls_openssl_group")
    return {"verification": "verified", "failure": None, "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384", "peer_name": "harbordesk.test"}


def parse_input(raw):
    header, streams = decode_input(raw)
    operation, configuration, case = header["operation"], header["configuration"], header["case"]
    if header["truncated"] or header["stop_reason"] is not None and not (operation == "dns" and case == "N8" and header["stop_reason"] == "timeout"):
        raise ValueError("name_tls_native_incomplete")
    request, delivered = streams["request"], streams["delivered_request"]
    original, proposed, response = (streams[k] for k in ("original_response", "proposed_response", "delivered_response"))
    if request != delivered or proposed != response or not request or not response:
        raise ValueError("name_tls_wire_delivery_incomplete")
    useful, expected_negative = False, False
    if operation == "dns":
        _dig_stderr(streams["stderr"])
        if case == "N8":
            expected = wire.transformed_dns_response(configuration, case, request, original)
            if response != expected or header["exit_code"] == 0:
                raise ValueError("name_tls_truncated_dns_evidence")
            observation = {"kind": "truncated_dns_frame", "declared_message_bytes": int.from_bytes(response[:2], "big"),
                           "delivered_message_bytes": len(response) - 2}
            native, expected_negative = None, True
        else:
            if header["exit_code"] != 0:
                raise ValueError("name_tls_dig_execution_failed")
            exchange = wire.parse_dns_exchange(request, original, response, configuration=configuration, case=case)
            native = parse_dig_output(streams["stdout"], streams["stderr"], configuration=configuration, case=case)
            observation = exchange["delivered"]
            if native["semantic"] != observation or native["response_message_bytes"] != len(response) - 2:
                raise ValueError("name_tls_dns_native_wire_disagreement")
            useful = exchange["binding_candidate"]
            expected_negative = not useful and case in ("N1", "N2", "N3", "N5", "N6", "N7")
    elif operation == "http":
        if (request != wire.http_request(configuration, case) or original != response or streams["stdout"] != response
                or streams["stderr"] or header["exit_code"] != 0):
            raise ValueError("name_tls_http_native_wire_disagreement")
        observation, native, useful = _http(response), None, True
    else:
        if original != response:
            raise ValueError("name_tls_tls_response_changed")
        observation = wire.parse_tls_wire(request, response, configuration=configuration, case=case)
        native = _tls_native(streams["stdout"], streams["stderr"], configuration, case, header["exit_code"])
        useful = native["verification"] == "verified"
        expected_negative = not useful and case in ("N11", "N12", "N13", "N16")
        if useful and observation["protocol_rejection"] or case == "N16" and not observation["protocol_rejection"]:
            raise ValueError("name_tls_tls_native_wire_disagreement")
    result = {"parser_version": PARSER_VERSION, "operation": operation, "configuration": configuration, "case": case,
              "input_sha256": hashlib.sha256(raw).hexdigest(), "exit_code": header["exit_code"],
              "stop_reason": header["stop_reason"], "observation": observation,
              "observation_sha256": wire.semantic_digest(observation), "native": native,
              "binding_candidate": bool(operation == "dns" and useful), "useful_task_completed": useful,
              "expected_negative": expected_negative,
              "streams": {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()} for name, value in streams.items()}}
    return validate_result(result)


def validate_result(value):
    keys = {"parser_version", "operation", "configuration", "case", "input_sha256", "exit_code", "stop_reason",
            "observation", "observation_sha256", "native", "binding_candidate", "useful_task_completed", "expected_negative", "streams"}
    if type(value) is not dict or set(value) != keys or value["parser_version"] != PARSER_VERSION:
        raise ValueError("name_tls_parser_result")
    wire.selection(value["configuration"], value["case"])
    if (value["operation"] not in BOUNDS or type(value["exit_code"]) is not int or not -255 <= value["exit_code"] <= 255
            or value["stop_reason"] not in (None, "timeout") or type(value["observation"]) is not dict
            or type(value["streams"]) is not dict or set(value["streams"]) != set(STREAMS)
            or any(type(value[k]) is not bool for k in ("binding_candidate", "useful_task_completed", "expected_negative"))
            or any(type(value[k]) is not str or not _HEX.fullmatch(value[k]) for k in ("input_sha256", "observation_sha256"))
            or value["observation_sha256"] != wire.semantic_digest(value["observation"])):
        raise ValueError("name_tls_parser_result")
    for item in value["streams"].values():
        if (type(item) is not dict or set(item) != {"bytes", "sha256"} or type(item["bytes"]) is not int
                or not 0 <= item["bytes"] <= 16384 or type(item["sha256"]) is not str or not _HEX.fullmatch(item["sha256"])):
            raise ValueError("name_tls_parser_result_stream")
    request_cap, response_cap, output_cap = BOUNDS[value["operation"]]
    caps = dict(zip(STREAMS, (request_cap, request_cap, response_cap, response_cap, response_cap, output_cap, output_cap)))
    if (any(value["streams"][key]["bytes"] > maximum for key, maximum in caps.items())
            or sum(value["streams"][key]["bytes"] for key in ("stdout", "stderr")) > output_cap):
        raise ValueError("name_tls_parser_result_stream_bound")
    observation, native, case = value["observation"], value["native"], value["case"]
    expected_negative = False
    if value["operation"] == "dns":
        stderr = value["streams"]["stderr"]
        stderr_variants = [{"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                           for raw in (b"", _DIG_PROBE_DENIED_TEXT)]
        if stderr not in stderr_variants:
            raise ValueError("name_tls_parser_dns_stderr")
        if case == "N8":
            if (set(observation) != {"kind", "declared_message_bytes", "delivered_message_bytes"}
                    or observation["kind"] != "truncated_dns_frame" or native is not None or value["exit_code"] == 0
                    or type(observation["declared_message_bytes"]) is not int
                    or type(observation["delivered_message_bytes"]) is not int
                    or observation["declared_message_bytes"] != observation["delivered_message_bytes"] + 1
                    or not 12 <= observation["declared_message_bytes"] <= 4094):
                raise ValueError("name_tls_parser_truncation_result")
            useful, expected_negative = False, True
        else:
            wire.validate_dns_semantic(observation)
            row = wire.selection(value["configuration"], case)
            if (type(native) is not dict or set(native) != {"semantic", "response_message_bytes", "transport", "resolver_address", "resolver_port", "stderr_diagnostic"}
                    or native["semantic"] != observation or native["transport"] != "tcp"
                    or native["resolver_address"] != row[0] or type(native["resolver_port"]) is not int or native["resolver_port"] != row[1]
                    or type(native["response_message_bytes"]) is not int or native["response_message_bytes"] != value["streams"]["delivered_response"]["bytes"] - 2
                    or native["stderr_diagnostic"] != (None if stderr == stderr_variants[0] else _DIG_STDERR_MARKER)
                    or value["exit_code"] != 0 or value["stop_reason"] is not None):
                raise ValueError("name_tls_parser_dns_result")
            useful = wire.binding_candidate(observation, value["configuration"], case)
            expected_negative = not useful and case in ("N1", "N2", "N3", "N5", "N6", "N7")
    elif value["operation"] == "http":
        if (set(observation) != {"status_code", "body_bytes", "body_sha256", "location_sha256", "response_sha256"}
                or type(observation["status_code"]) is not int or not 200 <= observation["status_code"] <= 599
                or type(observation["body_bytes"]) is not int or not 0 <= observation["body_bytes"] <= 2048
                or any(type(observation[k]) is not str or not _HEX.fullmatch(observation[k]) for k in ("body_sha256", "response_sha256"))
                or observation["location_sha256"] is not None and (type(observation["location_sha256"]) is not str or not _HEX.fullmatch(observation["location_sha256"]))
                or native is not None or value["exit_code"] != 0 or value["stop_reason"] is not None):
            raise ValueError("name_tls_parser_http_result")
        useful = True
    else:
        if (set(observation) != {"client_hello", "server_hello", "protocol_rejection", "client_records", "server_records", "encrypted_contents_verified"}
                or observation["encrypted_contents_verified"] is not False or type(observation["protocol_rejection"]) is not bool
                or any(type(observation[k]) is not int or not 1 <= observation[k] <= 32 for k in ("client_records", "server_records"))
                or type(native) is not dict or set(native) != {"verification", "failure", "protocol", "cipher", "peer_name"}):
            raise ValueError("name_tls_parser_tls_result")
        hello = observation["client_hello"]
        if (type(hello) is not dict or set(hello) != {"version", "session_id_hex", "cipher", "random_hex", "extension_types", "sha256", "sni", "group"}
                or hello["version"] != "tls1_3" or type(hello["cipher"]) is not int or hello["cipher"] != 0x1302
                or hello["sni"] != "harbordesk.test" or type(hello["group"]) is not int or hello["group"] != 23
                or type(hello["sha256"]) is not str or not _HEX.fullmatch(hello["sha256"])
                or type(hello["random_hex"]) is not str or not _HEX.fullmatch(hello["random_hex"])
                or type(hello["session_id_hex"]) is not str or not re.fullmatch(r"(?:[0-9a-f]{2}){0,32}", hello["session_id_hex"])
                or type(hello["extension_types"]) is not list or any(type(n) is not int for n in hello["extension_types"])
                or hello["extension_types"] != sorted(set(hello["extension_types"]))):
            raise ValueError("name_tls_parser_client_hello_result")
        chosen = observation["server_hello"]
        if chosen is not None and (type(chosen) is not dict or set(chosen) != {"protocol", "cipher", "group", "session_id_hex", "sha256"}
                or chosen["protocol"] != "TLSv1.3" or chosen["cipher"] != "TLS_AES_256_GCM_SHA384"
                or type(chosen["group"]) is not int or chosen["group"] != 23 or chosen["session_id_hex"] != hello["session_id_hex"]
                or type(chosen["sha256"]) is not str or not _HEX.fullmatch(chosen["sha256"])):
            raise ValueError("name_tls_parser_server_hello_result")
        useful = native["verification"] == "verified"
        if useful:
            if (native != {"verification": "verified", "failure": None, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "peer_name": "harbordesk.test"}
                    or chosen is None or observation["protocol_rejection"] or value["exit_code"] != 0 or value["stop_reason"] is not None):
                raise ValueError("name_tls_parser_tls_verified_result")
        else:
            failure = {"N11": "certificate_name", "N12": "certificate_issuer", "N13": "certificate_expired", "N16": "protocol_version"}.get(case)
            if (failure is None or native != {"verification": "failed", "failure": failure, "protocol": None, "cipher": None, "peer_name": None}
                    or value["exit_code"] == 0 or value["stop_reason"] is not None or (case == "N16") != observation["protocol_rejection"]
                    or (case == "N16") != (chosen is None)):
                raise ValueError("name_tls_parser_tls_refusal_result")
            expected_negative = True
    if (value["useful_task_completed"] is not useful or value["expected_negative"] is not expected_negative
            or value["binding_candidate"] is not bool(value["operation"] == "dns" and useful)):
        raise ValueError("name_tls_parser_verdict_changed")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > MAX_OUTPUT_BYTES - 1024:
        raise ValueError("name_tls_parser_result_limit")
    return load_json(encoded)
