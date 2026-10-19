"""Finite, key-free protocol observations for the owned name/TLS candidate.

These functions interpret bytes, never contact an advertised address or create
authority. Original daemon and delivered bytes remain distinct provenance.
"""

import hashlib
import ipaddress
import json
import re
import struct

from .tls_posture_hello import _Reader

NAME = "harbordesk.test."
CASES = ("O1", "O2", "O3", "O4", "O5", "R1", "R2", *(f"N{i}" for i in range(1, 17)))
ROWS = {
    "A": ("10.77.0.53", 5353, "10.77.0.10", 8080, "/harbordesk/portal.html", 8443, "10.77.0.99"),
    "B": ("172.23.0.53", 15353, "172.23.0.10", 18080, "/portal/index.html", 18443, "172.23.0.99"),
}
QUESTION = b"\x0aharbordesk\x04test\0\0\1\0\1"


def selection(configuration, case):
    if type(configuration) is not str or configuration not in ROWS or type(case) is not str or case not in CASES:
        raise ValueError("invalid_name_tls_selection")
    return ROWS[configuration]


def semantic_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                     allow_nan=False).encode("ascii")).hexdigest()


def validate_dns_semantic(value):
    if (type(value) is not dict or set(value) != {"schema_version", "question", "transaction_id", "flags", "records"}
            or value["schema_version"] != "1" or type(value["question"]) is not dict
            or set(value["question"]) != {"name", "class", "type"}
            or value["question"]["name"] != NAME or type(value["question"]["class"]) is not int
            or value["question"]["class"] != 1 or type(value["question"]["type"]) is not int
            or value["question"]["type"] != 1 or type(value["transaction_id"]) is not int
            or not 0 <= value["transaction_id"] <= 65535 or type(value["flags"]) is not int
            or value["flags"] not in (0, 0x8000, 0x8080, 0x8400, 0x8480)
            or type(value["records"]) is not list or len(value["records"]) > 8
            or value["flags"] == 0 and value["records"]):
        raise ValueError("name_tls_dns_semantic")
    last_section = 0
    def name(item):
        if type(item) is not str or not 1 <= len(item) <= 254 or not item.endswith("."):
            raise ValueError("name_tls_dns_semantic_name")
        labels = item[:-1].split(".")
        if any(not re.fullmatch(r"[a-z0-9_-]{1,63}", part) for part in labels) or sum(len(x) + 1 for x in labels) + 1 > 255:
            raise ValueError("name_tls_dns_semantic_name")
    for record in value["records"]:
        if (type(record) is not dict or set(record) != {"section", "name", "type", "class", "ttl", "data"}
                or type(record["section"]) is not str or record["section"] not in ("answer", "authority", "additional")
                or type(record["type"]) is not int or record["type"] not in (1, 2, 5, 28)
                or type(record["class"]) is not int or record["class"] != 1
                or type(record["ttl"]) is not int or not 0 <= record["ttl"] <= 0xffffffff):
            raise ValueError("name_tls_dns_semantic_record")
        current = ("answer", "authority", "additional").index(record["section"])
        if current < last_section:
            raise ValueError("name_tls_dns_semantic_order")
        last_section = current
        name(record["name"])
        if record["type"] in (1, 28):
            if type(record["data"]) is not str:
                raise ValueError("name_tls_dns_semantic_address")
            address = ipaddress.ip_address(record["data"])
            if address.version != (4 if record["type"] == 1 else 6) or str(address) != record["data"]:
                raise ValueError("name_tls_dns_semantic_address")
        else:
            name(record["data"])
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


class _DNS:
    def __init__(self, raw):
        self.raw = raw
        self.boundaries = set()

    def name(self, start):
        position, end, labels, seen, hops = start, None, [], set(), 0
        while True:
            if position >= len(self.raw) or position in seen:
                raise ValueError("name_tls_dns_name")
            seen.add(position)
            size = self.raw[position]
            if size & 0xc0 == 0xc0:
                if position + 1 >= len(self.raw):
                    raise ValueError("name_tls_dns_pointer")
                pointer = ((size & 63) << 8) | self.raw[position + 1]
                if pointer >= position or pointer not in self.boundaries or hops >= 8:
                    raise ValueError("name_tls_dns_pointer")
                self.boundaries.add(position)
                end = position + 2 if end is None else end
                position, hops = pointer, hops + 1
                continue
            if size & 0xc0 or size > 63 or position + 1 + size > len(self.raw):
                raise ValueError("name_tls_dns_label")
            self.boundaries.add(position)
            position += 1
            if not size:
                end = position if end is None else end
                break
            label = self.raw[position:position + size]
            if any(c not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in label):
                raise ValueError("name_tls_dns_label")
            labels.append(label.decode("ascii").lower())
            if sum(len(x) + 1 for x in labels) + 1 > 255:
                raise ValueError("name_tls_dns_expanded_name")
            position += size
        return ".".join(labels) + ".", end


def parse_dns_frame(frame, *, response=True):
    maximum = 4096 if response else 512
    if (type(response) is not bool or type(frame) is not bytes or not 14 <= len(frame) <= maximum
            or int.from_bytes(frame[:2], "big") != len(frame) - 2):
        raise ValueError("name_tls_dns_frame")
    raw = frame[2:]
    transaction, flags, questions, answers, authorities, additional = struct.unpack("!6H", raw[:12])
    if (questions != 1 or answers + authorities + additional > 8
            or flags not in ((0x8000, 0x8080, 0x8400, 0x8480) if response else (0,))
            or (not response and answers + authorities + additional)):
        raise ValueError("name_tls_dns_header")
    parser = _DNS(raw)
    name, end = parser.name(12)
    if name != NAME or raw[12:end + 4] != QUESTION:
        raise ValueError("name_tls_dns_question")
    position, records = end + 4, []
    for section, count in (("answer", answers), ("authority", authorities), ("additional", additional)):
        for _ in range(count):
            name, position = parser.name(position)
            if position + 10 > len(raw):
                raise ValueError("name_tls_dns_record")
            kind, klass, ttl, length = struct.unpack("!HHIH", raw[position:position + 10])
            position += 10
            limit = position + length
            if klass != 1 or kind not in (1, 2, 5, 28) or limit > len(raw):
                raise ValueError("name_tls_dns_record")
            if kind in (1, 28):
                if length != (4 if kind == 1 else 16):
                    raise ValueError("name_tls_dns_address")
                data = str(ipaddress.ip_address(raw[position:limit]))
            else:
                data, consumed = parser.name(position)
                if consumed != limit:
                    raise ValueError("name_tls_dns_rdata")
            records.append({"section": section, "name": name, "type": kind, "class": klass,
                            "ttl": ttl, "data": data})
            position = limit
    if position != len(raw):
        raise ValueError("name_tls_dns_trailing")
    return {"schema_version": "1", "question": {"name": NAME, "class": 1, "type": 1},
            "transaction_id": transaction, "flags": flags, "records": records}


def parse_dns_query(raw):
    return parse_dns_frame(raw, response=False)


def parse_dns_response(raw, request):
    query = parse_dns_query(request)
    response = parse_dns_frame(raw)
    if response["transaction_id"] != query["transaction_id"]:
        raise ValueError("name_tls_dns_transaction")
    return response


validate_dns_query = parse_dns_query
validate_dns_response = parse_dns_response


def binding_candidate(semantic, configuration, case):
    row = selection(configuration, case)
    semantic = validate_dns_semantic(semantic)
    return (semantic.get("flags") in (0x8400, 0x8480)
            and semantic.get("question") == {"name": NAME, "class": 1, "type": 1}
            and semantic.get("records") == [{"section": "answer", "name": NAME, "type": 1, "class": 1,
                                             "ttl": 1 if case == "N14" else 60, "data": row[2]}])


def _name(name):
    return b"".join(bytes((len(p),)) + p.encode("ascii") for p in name.rstrip(".").split(".")) + b"\0"


def transformed_dns_response(configuration, case, request, original, *, second_observation=False):
    row = selection(configuration, case)
    query = parse_dns_query(request)
    parse_dns_response(original, request)
    if type(second_observation) is not bool or second_observation and case != "N1":
        raise ValueError("name_tls_dns_driver")
    if case not in ("N6", "N7", "N8") and not second_observation:
        return original
    def record(owner, kind, data):
        return owner + struct.pack("!HHIH", kind, 1, 60, len(data)) + data
    if case == "N6":
        ns = _name("ns.harbordesk.test.")
        counts = (0x8000, 1, 0, 1, 1)
        records = record(b"\xc0\x0c", 2, ns) + record(ns, 1, ipaddress.IPv4Address(row[6]).packed)
    elif case == "N7":
        counts = (0x8400, 1, 1, 0, 0)
        records = record(b"\xc0\x0c", 28, ipaddress.IPv6Address("2001:db8::99").packed)
    else:
        counts = (0x8400, 1, 1, 0, 0)
        records = record(b"\xc0\x0c", 1, ipaddress.IPv4Address(row[6] if second_observation else row[2]).packed)
    raw = struct.pack("!6H", query["transaction_id"], *counts) + QUESTION + records
    frame = len(raw).to_bytes(2, "big") + raw
    return frame[:-1] if case == "N8" else frame


def parse_dns_exchange(request, original, delivered, *, configuration, case):
    selection(configuration, case)
    query = parse_dns_query(request)
    original_semantic = parse_dns_response(original, request)
    delivered_semantic = parse_dns_response(delivered, request)
    if original != delivered or case in ("N6", "N7"):
        expected = transformed_dns_response(configuration, case, request, original,
                                            second_observation=case == "N1")
        if delivered != expected:
            raise ValueError("name_tls_dns_transformation")
    return {"request": query, "original": original_semantic, "delivered": delivered_semantic,
            "binding_candidate": binding_candidate(delivered_semantic, configuration, case),
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "original_sha256": hashlib.sha256(original).hexdigest(),
            "delivered_sha256": hashlib.sha256(delivered).hexdigest()}


def http_request(configuration, case):
    row = selection(configuration, case)
    return (f"GET {row[4]} HTTP/1.1\r\nHost: harbordesk.test:{row[3]}\r\nConnection: close\r\n\r\n").encode("ascii")


def tls_client_hello_length(prefix):
    if type(prefix) is not bytes or len(prefix) > 4096:
        raise ValueError("name_tls_client_hello_size")
    if len(prefix) < 5:
        return None
    length = 5 + int.from_bytes(prefix[3:5], "big")
    if prefix[0] != 22 or prefix[1:3] not in (b"\3\1", b"\3\2", b"\3\3") or not 50 <= length <= 4096:
        raise ValueError("name_tls_client_hello_record")
    return length


def validate_tls_client_hello(raw):
    """Validate this profile's complete TLS1.3 hello without rewriting bytes.

    The accepted shared posture grammar remains unchanged. This specialization
    additionally permits only the pinned certificate-compression advertisement.
    """
    if (tls_client_hello_length(raw) != len(raw) or raw[5] != 1
            or int.from_bytes(raw[6:9], "big") != len(raw) - 9):
        raise ValueError("name_tls_client_hello_record")
    reader = _Reader(raw[9:])
    if reader.take(2) != b"\3\3":
        raise ValueError("name_tls_client_hello_version")
    random = reader.take(32)
    session = reader.vector(1)
    if len(session) > 32:
        raise ValueError("name_tls_client_hello_session")
    suites = reader.vector(2)
    if not suites or len(suites) % 2:
        raise ValueError("name_tls_client_hello_ciphers")
    ciphers = [int.from_bytes(suites[i:i + 2], "big") for i in range(0, len(suites), 2)]
    if len(ciphers) != len(set(ciphers)) or 0x1302 not in ciphers or not set(ciphers) <= {0x1302, 0x00FF}:
        raise ValueError("name_tls_client_hello_ciphers")
    if reader.vector(1) != b"\0":
        raise ValueError("name_tls_client_hello_compression")
    extension_reader = _Reader(reader.vector(2))
    reader.done()
    extensions = {}
    while extension_reader.position < len(extension_reader.raw):
        kind = int.from_bytes(extension_reader.take(2), "big")
        value = extension_reader.vector(2)
        if kind in extensions or kind not in {0, 10, 11, 13, 22, 23, 27, 43, 44, 45, 51, 0xFF01}:
            raise ValueError("name_tls_client_hello_extension")
        extensions[kind] = value
    name = b"harbordesk.test"
    sni = (len(name) + 3).to_bytes(2, "big") + b"\0" + len(name).to_bytes(2, "big") + name
    if extensions.get(0) != sni or extensions.get(10) != b"\0\2\0\x17":
        raise ValueError("name_tls_client_hello_name_group")
    for kind in (22, 23):
        if kind in extensions and extensions[kind] != b"":
            raise ValueError("name_tls_client_hello_empty_extension")
    if 0xFF01 in extensions and extensions[0xFF01] != b"\0":
        raise ValueError("name_tls_client_hello_renegotiation")
    if 11 in extensions:
        formats = _Reader(extensions[11])
        points = formats.vector(1)
        formats.done()
        if not points or points[0] != 0 or len(points) != len(set(points)) or not set(points) <= {0, 1, 2}:
            raise ValueError("name_tls_client_hello_point_formats")
    if 13 in extensions:
        signatures = _Reader(extensions[13])
        algorithms = signatures.vector(2)
        signatures.done()
        if not algorithms or len(algorithms) % 2:
            raise ValueError("name_tls_client_hello_signatures")
    if extensions.get(43) != b"\2\3\4" or 51 not in extensions or 13 not in extensions:
        raise ValueError("name_tls_client_hello_supported_version")
    shares = _Reader(extensions[51])
    entries = _Reader(shares.vector(2))
    shares.done()
    if entries.take(2) != b"\0\x17":
        raise ValueError("name_tls_client_hello_key_share")
    key = entries.vector(2)
    entries.done()
    if len(key) != 65 or key[0] != 4:
        raise ValueError("name_tls_client_hello_key_share")
    if 44 in extensions:
        raise ValueError("name_tls_client_hello_cookie")
    if 45 in extensions and extensions[45] != b"\1\1":
        raise ValueError("name_tls_client_hello_psk_modes")
    if 27 in extensions and extensions[27] != b"\4\0\1\0\3":
        raise ValueError("name_tls_client_hello_certificate_compression")
    return {"version": "tls1_3", "session_id_hex": session.hex(), "cipher": 0x1302,
            "random_hex": random.hex(), "extension_types": sorted(extensions),
            "sha256": hashlib.sha256(raw).hexdigest(), "sni": "harbordesk.test", "group": 23}


def _tls_records(raw, maximum):
    if type(raw) is not bytes or not 5 <= len(raw) <= maximum:
        raise ValueError("name_tls_record_bytes")
    records, position = [], 0
    while position < len(raw):
        if position + 5 > len(raw) or len(records) >= 32:
            raise ValueError("name_tls_record_count")
        kind, version, length = struct.unpack("!BHH", raw[position:position + 5])
        end = position + 5 + length
        if kind not in (20, 21, 22, 23) or version not in (0x0301, 0x0303) or not 0 < length <= 18432 or end > len(raw):
            raise ValueError("name_tls_record_header")
        records.append((kind, raw[position + 5:end], raw[position:end]))
        position = end
    return records


def _server_hello(raw, session):
    if len(raw) < 4 or raw[0] != 2 or int.from_bytes(raw[1:4], "big") != len(raw) - 4:
        raise ValueError("name_tls_server_hello")
    body = raw[4:]
    if len(body) < 38 or body[:2] != b"\3\3" or body[2:34].hex() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c":
        raise ValueError("name_tls_server_hello_version")
    length = body[34]
    end = 35 + length
    if length > 32 or end + 5 > len(body) or body[35:end].hex() != session or body[end:end + 3] != b"\x13\2\0":
        raise ValueError("name_tls_server_hello_selection")
    size = int.from_bytes(body[end + 3:end + 5], "big")
    position = end + 5
    if position + size != len(body):
        raise ValueError("name_tls_server_hello_extensions")
    extensions = {}
    while position < len(body):
        if position + 4 > len(body):
            raise ValueError("name_tls_server_hello_extensions")
        kind, length = struct.unpack("!HH", body[position:position + 4])
        position += 4
        if kind in extensions or kind not in (43, 51) or position + length > len(body):
            raise ValueError("name_tls_server_hello_extensions")
        extensions[kind] = body[position:position + length]
        position += length
    key = extensions.get(51, b"")
    if extensions.get(43) != b"\3\4" or len(key) != 69 or key[:5] != b"\0\x17\0A\4":
        raise ValueError("name_tls_server_hello_key_share")
    return {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "group": 23,
            "session_id_hex": session, "sha256": hashlib.sha256(raw).hexdigest()}


def validate_tls_server_hello(raw, client_hello):
    """Validate one assembled plaintext handshake against the recorded client."""
    hello = validate_tls_client_hello(client_hello)
    return _server_hello(raw, hello["session_id_hex"])


def tls_verification_alert(case):
    """The observed terminal client record for each fixed certificate refusal."""
    description = {"N11": 42, "N12": 48, "N13": 45}.get(case)
    return None if description is None else b"\x15\3\3\0\2\2" + bytes((description,))


def _tls_remaining(records, *, terminal_alert=None):
    ccs, encrypted, alerted = False, False, False
    for kind, body, raw in records:
        if alerted:
            raise ValueError("name_tls_record_after_alert")
        if kind == 20 and body == b"\1" and not ccs and not encrypted:
            ccs = True
        elif terminal_alert is not None and raw == terminal_alert and not encrypted:
            alerted = True
        elif kind == 23 and len(body) >= 17 and terminal_alert is None:
            encrypted = True
        else:
            raise ValueError("name_tls_extra_handshake_or_record")
    if terminal_alert is not None and not alerted:
        raise ValueError("name_tls_verification_alert_missing")
    return encrypted


def parse_tls_wire(client_bytes, server_bytes, *, configuration, case):
    selection(configuration, case)
    client = _tls_records(client_bytes, 8192)
    hello = validate_tls_client_hello(client[0][2])
    server = _tls_records(server_bytes, 16384)
    if case == "N16" and len(server) == 1 and server[0][0] == 21 and server[0][1] == b"\2F":
        _tls_remaining(client[1:])
        return {"client_hello": hello, "server_hello": None, "protocol_rejection": True,
                "client_records": len(client), "server_records": 1, "encrypted_contents_verified": False}
    plaintext, position = bytearray(), 0
    while position < len(server) and server[position][0] == 22:
        plaintext.extend(server[position][1])
        position += 1
        if len(plaintext) >= 4 and len(plaintext) >= 4 + int.from_bytes(plaintext[1:4], "big"):
            break
    chosen = _server_hello(bytes(plaintext), hello["session_id_hex"])
    server_encrypted = _tls_remaining(server[position:])
    alert = tls_verification_alert(case)
    if alert is not None and not server_encrypted:
        raise ValueError("name_tls_verification_server_flight_missing")
    # Separate directional streams establish record order within each stream.
    # The live recorder additionally proves delivery before the client's alert.
    _tls_remaining(client[1:], terminal_alert=alert)
    return {"client_hello": hello, "server_hello": chosen, "protocol_rejection": False,
            "client_records": len(client), "server_records": len(server), "encrypted_contents_verified": False}
