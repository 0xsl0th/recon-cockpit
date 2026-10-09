"""One bounded SMB2 NEGOTIATE response, without any session or authentication.

The fixed offer contains SMB 2.1 and 3.0.2 with client capabilities zero.
Server fields are untrusted reports; opaque security/error bytes are never
decoded, released as metadata, or used to select another operation.
"""

import struct


TOOL_ID = "smb2_negotiate_metadata_v1"
PARSER_VERSION = "smb2-negotiate-metadata-v1"
SEMANTICS = "untrusted_smb2_negotiation_metadata"
MAX_OUTPUT_BYTES = 4100
MAX_OPAQUE_BYTES = 256
DIALECTS = {0x0210: "SMB 2.1", 0x0302: "SMB 3.0.2"}
CAPABILITY_MASKS = {0x0210: 0x07, 0x0302: 0x7f}
FAILURES = {0xc000000d: "STATUS_INVALID_PARAMETER", 0xc0000022: "STATUS_ACCESS_DENIED",
    0xc00000bb: "STATUS_NOT_SUPPORTED"}
_FIELDS = {"parser_version", "kind", "semantics", "response_type", "status_code", "status_name",
    "dialect_revision", "security_mode", "signing_required", "capabilities", "security_buffer_length",
    "session_setup_performed", "authenticated_session", "service_identity_verified"}
_SELECTION_FIELDS = ("dialect_revision", "security_mode", "signing_required", "capabilities",
    "security_buffer_length")


def validate_result(value):
    """Return detached metadata; neither signing nor identity is verified."""
    if (type(value) is not dict or set(value) != _FIELDS
            or value["parser_version"] != PARSER_VERSION or value["kind"] != "smb2_negotiate_metadata"
            or value["semantics"] != SEMANTICS
            or value["session_setup_performed"] is not False
            or value["authenticated_session"] is not False
            or value["service_identity_verified"] is not False
            or type(value["status_code"]) is not int):
        raise ValueError("invalid_smb2_negotiation_observation")
    code = value["status_code"]
    if value["response_type"] == "selection":
        dialect, mode, caps = value["dialect_revision"], value["security_mode"], value["capabilities"]
        valid = (code == 0 and value["status_name"] == "STATUS_SUCCESS"
            and type(dialect) is int and dialect in DIALECTS
            and type(mode) is int and mode in (1, 3)
            and value["signing_required"] is bool(mode & 2)
            and type(caps) is int and 0 <= caps <= CAPABILITY_MASKS[dialect]
            and type(value["security_buffer_length"]) is int
            and 0 <= value["security_buffer_length"] <= MAX_OPAQUE_BYTES)
    elif value["response_type"] == "failure":
        valid = (code in FAILURES and value["status_name"] == FAILURES[code]
            and all(value[field] is None for field in _SELECTION_FIELDS))
    else:
        valid = False
    if not valid:
        raise ValueError("invalid_smb2_negotiation_fields")
    return dict(value)


def parse_output(raw, stderr=b""):
    """Parse one exact Direct TCP frame within the finite pre-session profile."""
    if (type(raw) is not bytes or type(stderr) is not bytes or stderr
            or not 76 <= len(raw) <= MAX_OUTPUT_BYTES or raw[0] != 0
            or int.from_bytes(raw[1:4], "big") != len(raw) - 4):
        raise ValueError("invalid_smb2_negotiation_capture")
    message = raw[4:]
    protocol, size, _, status, command, _, flags, next_command, message_id, _, tree_id, session_id, _ = (
        struct.unpack("<4sHHIHHIIQIIQ16s", message[:64]))
    if (protocol != b"\xfeSMB" or size != 64 or command != 0 or flags != 1
            or next_command != 0 or message_id != 0 or tree_id != 0 or session_id != 0):
        raise ValueError("unsupported_smb2_negotiation_header")
    # Credit values, header reserved bytes and signature bytes confer no
    # authority. This profile never processes a signed or asynchronous frame.
    result = {"parser_version": PARSER_VERSION, "kind": "smb2_negotiate_metadata", "semantics": SEMANTICS,
        "response_type": "failure", "status_code": status, "status_name": FAILURES.get(status),
        **dict.fromkeys(_SELECTION_FIELDS), "session_setup_performed": False,
        "authenticated_session": False, "service_identity_verified": False}
    if status:
        structure, contexts, _, count = struct.unpack("<HBBI", message[64:72])
        if (status not in FAILURES or structure != 9 or contexts != 0 or count > MAX_OPAQUE_BYTES
                or (len(message) != 72 + count and not (count == 0 and len(message) == 73))):
            raise ValueError("unsupported_smb2_negotiation_error")
        # MS-SMB2 Appendix A note 5 documents one undefined ErrorData byte in
        # older Windows responses when ByteCount is zero. No error data is decoded.
    else:
        if len(message) < 128:
            raise ValueError("incomplete_smb2_negotiation_response")
        structure, mode, dialect, _, _, caps, _, _, _, _, _, offset, length, _ = struct.unpack(
            "<HHHH16sIIIIQQHHI", message[64:128])
        if (structure != 65 or length > MAX_OPAQUE_BYTES
                or (offset != 128 and not (length == 0 and offset == 0))
                or len(message) != 128 + length):
            raise ValueError("invalid_smb2_negotiation_buffer")
        # For the offered pre-3.1.1 dialects, the context count/offset fields
        # are reserved and ignored per MS-SMB2 2.2.4. No context is followed.
        result.update(response_type="selection", status_name="STATUS_SUCCESS", dialect_revision=dialect,
            security_mode=mode, signing_required=bool(mode & 2), capabilities=caps, security_buffer_length=length)
    return validate_result(result)
