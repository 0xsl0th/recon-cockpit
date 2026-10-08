"""Bounded first SSH KEXINIT advertisements, without completing key exchange."""

import json


TOOL_ID = "ssh_transport_algorithms_v1"
PARSER_VERSION = "ssh-kexinit-wire-v1"
SEMANTICS = "untrusted_ssh_algorithm_advertisements"
MAX_OUTPUT_BYTES = 8192
MAX_IDENTIFICATION_BYTES = 255
MAX_PACKET_LENGTH = 4096
MAX_NAMES = 32
MAX_NAME_BYTES = 64
MAX_LIST_BYTES = 1024
MAX_SUMMARY_BYTES = 3072
ALGORITHM_FIELDS = (
    "kex_algorithms", "server_host_key_algorithms",
    "encryption_algorithms_client_to_server", "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server", "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server", "compression_algorithms_server_to_client")


def _identification(value):
    if (type(value) is not str or not value.startswith("SSH-2.0-")
            or not 9 <= len(value) <= MAX_IDENTIFICATION_BYTES - 2
            or any(not 33 <= ord(char) <= 126 or char == "-" for char in value[8:])):
        raise ValueError("invalid_ssh_algorithm_identification")
    return value


def _banner(raw):
    if len(raw) > MAX_IDENTIFICATION_BYTES or not raw.endswith(b"\r\n"):
        raise ValueError("invalid_ssh_algorithm_banner")
    try:
        line = raw[:-2].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("invalid_ssh_algorithm_banner") from None
    if any(not 32 <= ord(char) <= 126 for char in line):
        raise ValueError("invalid_ssh_algorithm_banner")
    identification = line.partition(" ")[0]
    # The optional printable comment is checked above and deliberately omitted.
    return _identification(identification)


def _names(value):
    if (type(value) is not list or not 1 <= len(value) <= MAX_NAMES
            or any(type(name) is not str or not 1 <= len(name) <= MAX_NAME_BYTES
                or any(not 33 <= ord(char) <= 126 or char == "," for char in name) for name in value)):
        raise ValueError("invalid_ssh_algorithm_names")
    if len(set(value)) != len(value) or len(",".join(value)) > MAX_LIST_BYTES:
        raise ValueError("duplicate_or_excess_ssh_algorithm_names")
    return list(value)


def validate_result(value):
    """Validate and detach the complete summary without asserting negotiation."""
    if (type(value) is not dict or set(value) != {"parser_version", "kind", "semantics",
            "server_identification", "algorithms", "first_kex_packet_follows", "key_exchange_completed",
            "authenticated_session", "service_identity_verified"}
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "ssh_algorithm_metadata"
            or value["semantics"] != SEMANTICS or type(value["first_kex_packet_follows"]) is not bool
            or any(value[field] is not False for field in (
                "key_exchange_completed", "authenticated_session", "service_identity_verified"))
            or type(value["algorithms"]) is not dict or set(value["algorithms"]) != set(ALGORITHM_FIELDS)):
        raise ValueError("invalid_ssh_algorithm_observation")
    _identification(value["server_identification"])
    algorithms = {field: _names(value["algorithms"][field]) for field in ALGORITHM_FIELDS}
    # Message byte, cookie, ten string lengths, boolean and reserved uint32.
    payload_size = 62 + sum(len(",".join(names)) for names in algorithms.values())
    padding = 4 + (-(4 + 1 + payload_size + 4) % 8)
    if 1 + payload_size + padding > MAX_PACKET_LENGTH:
        raise ValueError("excess_ssh_algorithm_packet")
    result = {**value, "algorithms": algorithms}
    # Match the isolated worker's JSON encoding and leave space for its fixed
    # envelope and confinement witnesses beneath the unchanged 4096-byte cap.
    if len(json.dumps(result, separators=(",", ":"), ensure_ascii=True).encode("ascii")) > MAX_SUMMARY_BYTES:
        raise ValueError("excess_ssh_algorithm_summary")
    return result


def parse_output(raw, stderr=b""):
    if (type(raw) is not bytes or type(stderr) is not bytes or not raw or stderr
            or len(raw) + len(stderr) > MAX_OUTPUT_BYTES):
        raise ValueError("invalid_ssh_algorithm_output")
    banner_end = raw.find(b"\r\n")
    if banner_end < 0:
        raise ValueError("incomplete_ssh_algorithm_banner")
    identification = _banner(raw[:banner_end + 2])
    packet = raw[banner_end + 2:]
    if len(packet) < 5:
        raise ValueError("incomplete_ssh_algorithm_packet")
    packet_length, padding = int.from_bytes(packet[:4], "big"), packet[4]
    if (not 12 <= packet_length <= MAX_PACKET_LENGTH or len(packet) != packet_length + 4
            or len(packet) % 8 or not 4 <= padding <= 255 or padding >= packet_length - 1):
        raise ValueError("invalid_ssh_algorithm_packet")
    payload = packet[5:len(packet) - padding]
    if len(payload) < 17 or payload[0] != 20:
        raise ValueError("unsupported_ssh_algorithm_message")
    offset, algorithms = 17, {}
    for field in (*ALGORITHM_FIELDS, "languages_client_to_server", "languages_server_to_client"):
        if offset + 4 > len(payload):
            raise ValueError("incomplete_ssh_algorithm_list")
        size = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        if size > MAX_LIST_BYTES or offset + size > len(payload):
            raise ValueError("invalid_ssh_algorithm_list_size")
        names = payload[offset:offset + size]
        offset += size
        if field in ALGORITHM_FIELDS:
            try:
                algorithms[field] = _names(names.decode("ascii").split(","))
            except UnicodeDecodeError:
                raise ValueError("invalid_ssh_algorithm_list_encoding") from None
        elif size:
            raise ValueError("unsupported_ssh_algorithm_languages")
    if offset + 5 != len(payload) or payload[offset] not in (0, 1) or payload[offset + 1:] != b"\0" * 4:
        raise ValueError("invalid_ssh_algorithm_payload_tail")
    return validate_result({"parser_version": PARSER_VERSION, "kind": "ssh_algorithm_metadata",
        "semantics": SEMANTICS, "server_identification": identification, "algorithms": algorithms,
        "first_kex_packet_follows": bool(payload[offset]), "key_exchange_completed": False,
        "authenticated_session": False, "service_identity_verified": False})
