"""Read bounded T02 development traces; never authorize or accept an adapter.

The caller retains the original trial and execution verdict. These findings are
diagnostic corroboration only, not production inspector results or proof that a
late-detected forbidden message was prevented.
"""

import base64
import binascii
import hashlib
import re

MAX_OUTPUT_BYTES = 8192
MAX_OWNER_BYTES = 32768
MAX_RECORDS = 32
CONFINEMENT_WITNESSES = (
    "worker_ready", "private_namespaces_and_firewall", "read_only_pinned_runtime",
    "landlock_and_seccomp", "no_inherited_descriptors",
)
VERSIONS = {
    "tls1": ("TLSv1", "ECDHE-ECDSA-AES128-SHA", b"\x03\x01", b"\xc0\x09"),
    "tls1_1": ("TLSv1.1", "ECDHE-ECDSA-AES128-SHA", b"\x03\x02", b"\xc0\x09"),
    "tls1_2": ("TLSv1.2", "ECDHE-ECDSA-AES128-GCM-SHA256", b"\x03\x03", b"\xc0\x2b"),
    "tls1_3": ("TLSv1.3", "TLS_AES_256_GCM_SHA384", b"\x03\x04", b"\x13\x02"),
}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
HEADER = re.compile(
    r"(>>>|<<<) (TLS 1\.[0-3]|SSL 3\.0), "
    r"(RecordHeader|InnerContent|Handshake|Alert|ChangeCipherSpec) "
    r"\[length ([0-9a-fA-F]{4})\](?:, ([A-Za-z0-9_ ]+))?"
)
HEX = re.compile(r"    (?:[0-9a-fA-F]{2})(?: [0-9a-fA-F]{2})*\s*")
HANDSHAKES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
              8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
              13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
              16: "ClientKeyExchange", 20: "Finished", 24: "KeyUpdate"}


def _decode(value):
    if type(value) is not str or len(value) > ((MAX_OUTPUT_BYTES + 2) // 3) * 4:
        raise ValueError("invalid_output_encoding_or_size")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid_output_encoding_or_size") from None
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ValueError("output_limit")
    return raw


def _messages(raw):
    """Parse each complete -msg hex block, including its own length prefix."""
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        raise ValueError("non_ascii_trace") from None
    messages, text, offset = [], [], 0
    while offset < len(lines):
        line = lines[offset]
        offset += 1
        match = HEADER.fullmatch(line)
        if not match:
            if line.startswith((">>>", "<<<")) or HEX.fullmatch(line):
                raise ValueError("unrecognized_trace_message")
            if line:
                text.append(line)
            continue
        direction, protocol, kind, size, name = match.groups()
        size = int(size, 16)
        chunks = []
        while offset < len(lines) and HEX.fullmatch(lines[offset]):
            chunks.append(bytes.fromhex(lines[offset]))
            offset += 1
        data = b"".join(chunks)
        if len(data) != size or not data:
            raise ValueError("incomplete_or_excess_trace_hex")
        if kind == "RecordHeader":
            if (size != 5 or data[0] not in (20, 21, 22, 23)
                    or data[1:3] not in (b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03")
                    or not 1 <= int.from_bytes(data[3:], "big") <= 18432):
                raise ValueError("invalid_record_header")
        elif kind == "InnerContent":
            if size != 1 or data[0] not in (20, 21, 22, 23):
                raise ValueError("invalid_inner_content")
        elif kind == "ChangeCipherSpec":
            if data != b"\x01":
                raise ValueError("invalid_change_cipher_spec")
        elif kind == "Alert":
            if size != 2 or data[0] not in (1, 2):
                raise ValueError("invalid_alert")
            if (data == b"\x02\x46" and name != "fatal protocol_version"
                    or data == b"\x01\x00" and name != "warning close_notify"):
                raise ValueError("inconsistent_alert_label")
        elif kind == "Handshake":
            if size < 4 or int.from_bytes(data[1:4], "big") != size - 4 or HANDSHAKES.get(data[0]) != name:
                raise ValueError("invalid_handshake_message")
        messages.append({"direction": "write" if direction == ">>>" else "read",
                         "protocol": protocol, "kind": kind, "name": name, "data": data})
        if len(messages) > 96:
            raise ValueError("excess_trace_messages")
    return messages, text


def _server_hello(data):
    body = data[4:]
    if len(body) < 38:
        raise ValueError("incomplete_server_hello")
    session_length = body[34]
    at = 35 + session_length
    if session_length > 32 or at + 3 > len(body) or body[at + 2] != 0:
        raise ValueError("invalid_server_hello")
    cipher, version = body[at:at + 2], body[:2]
    at += 3
    extensions = {}
    if at != len(body):
        if at + 2 > len(body) or int.from_bytes(body[at:at + 2], "big") != len(body) - at - 2:
            raise ValueError("incomplete_server_extensions")
        at += 2
        while at < len(body):
            if at + 4 > len(body):
                raise ValueError("incomplete_server_extension")
            code, size = int.from_bytes(body[at:at + 2], "big"), int.from_bytes(body[at + 2:at + 4], "big")
            at += 4
            if at + size > len(body) or code in extensions:
                raise ValueError("invalid_server_extension")
            extensions[code] = body[at:at + size]
            at += size
    if 43 in extensions:
        if version != b"\x03\x03" or extensions[43] != b"\x03\x04":
            raise ValueError("invalid_server_selected_version")
        version = extensions[43]
    return version, cipher, body[2:34] == HRR_RANDOM


def _owner_records(diagnostic, name):
    rows = diagnostic.get(name)
    if type(rows) is not list or len(rows) > MAX_RECORDS:
        raise ValueError("invalid_owner_record_ledger")
    total, values = 0, []
    for row in rows:
        if type(row) is not dict or type(row.get("raw_hex")) is not str or len(row["raw_hex"]) > MAX_OWNER_BYTES * 2:
            raise ValueError("invalid_owner_record")
        try:
            raw = bytes.fromhex(row["raw_hex"])
        except ValueError:
            raise ValueError("invalid_owner_record") from None
        if (len(raw) < 5 or int.from_bytes(raw[3:5], "big") != len(raw) - 5
                or row.get("type") != raw[0] or row.get("version") != raw[1:3].hex()
                or row.get("payload_length") != len(raw) - 5):
            raise ValueError("inconsistent_owner_record")
        total += len(raw)
        values.append(raw)
    if total > MAX_OWNER_BYTES:
        raise ValueError("owner_byte_limit")
    if diagnostic.get("received_bytes" if name == "received_records" else "sent_bytes") != total:
        raise ValueError("inconsistent_owner_byte_count")
    return values


def _unread_server_close(diagnostic, version, rows, headers):
    """Allow only the owner's associated final shutdown record to be unread.

    The client observation is still false. This does not interpret arbitrary
    ciphertext as an alert or excuse a missing handshake/application record.
    """
    if (not rows or headers != [raw[:5] for raw in rows[:-1]]
            or diagnostic.get("handshake_completed") is not True
            or diagnostic.get("clean_close") is not True):
        return False
    association = diagnostic.get("server_close_notify_record")
    if type(association) is not dict:
        return False
    last = rows[-1]
    # Fixed cipher: TLS1.3 AEAD; TLS1.2 explicit-nonce GCM; legacy CBC
    # with MAC-then-encrypt or negotiated encrypt-then-MAC, no padding growth.
    payload_lengths = {"tls1_3": {19}, "tls1_2": {26}, "tls1_1": {48, 52}, "tls1": {32, 36}}
    expected_type = 23 if version == "tls1_3" else 21
    expected_record_version = b"\x03\x03" if version == "tls1_3" else VERSIONS[version][2]
    return (len(last) - 5 in payload_lengths[version] and last[0] == expected_type
            and last[1:3] == expected_record_version
            and type(association.get("sent_record_index")) is int
            and type(association.get("payload_length")) is int
            and association.get("sent_record_index") == len(rows) - 1
            and association.get("raw_sha256") == hashlib.sha256(last).hexdigest()
            and association.get("payload_length") == len(last) - 5
            and diagnostic.get("alerts") == [
                {"direction": "read", "type": 1, "description": 0},
                {"direction": "write", "type": 1, "description": 0}])


def _known_text(line, rejection=False, version=None):
    # This finite diagnostic grammar deliberately rejects unfamiliar CLI output.
    exact = {"Connecting to 127.0.0.1", "CONNECTION ESTABLISHED", "DONE", "Verification: OK",
             "Verified peername: harbordesk.test", "verify depth is 1", "verify return:1",
             "Peer certificate: CN=harbordesk.test", "Hash used: SHA256",
             "Signature type: ECDSA", "Signature type: ecdsa_secp256r1_sha256",
             "Server Temp Key: ECDH, prime256v1, 256 bits", "Negotiated TLS1.3 group: P-256",
             "Peer Temp Key: ECDH, prime256v1, 256 bits"}
    if version in {"tls1", "tls1_1"}:
        exact |= {"Hash used: SHA1", "Signature type: ecdsa_sha1"}
    if version in {"tls1", "tls1_1", "tls1_2"}:
        exact.add("Supported Elliptic Curve Point Formats: uncompressed")
    if line in exact or line in {"Protocol version: " + row[0] for row in VERSIONS.values()} or line in {"Ciphersuite: " + row[1] for row in VERSIONS.values()}:
        return True
    if re.fullmatch(r"depth=[01] CN=(?:harbordesk\.test|HarborDesk PUBLIC TEST CA)", line):
        return True
    if re.fullmatch(r"SSL_connect:(?:before SSL initialization|SSLv3/TLS (?:write client hello|read server hello|read server certificate|read server key exchange|read server done|write client key exchange|write change cipher spec|write finished|read change cipher spec|read finished)|TLSv1\.3 (?:read encrypted extensions|read server certificate verify|write client certificate))", line):
        return True
    if line in {"SSL3 alert write:warning:close notify", "SSL3 alert read:warning:close notify"}:
        return True
    if rejection and (line in {"SSL3 alert read:fatal:protocol version", "SSL_connect:error in error"}
            or re.fullmatch(r"[0-9A-Fa-f]+:error:[0-9A-Fa-f]+:SSL routines:[A-Za-z0-9_]+:tlsv1 alert protocol version:[A-Za-z0-9_./-]+:[0-9]+:SSL alert number 70", line)):
        return True
    return False


def analyze_trial(trial):
    """Return a non-authoritative finding while preserving the process verdict."""
    finding = {"diagnostic_only": True, "outcome": "inconclusive", "issues": [], "evidence": {}}
    issues, evidence = finding["issues"], finding["evidence"]
    if type(trial) is not dict or trial.get("diagnostic_only") is not True:
        issues.append("not_a_diagnostic_trial")
        return finding
    execution = trial.get("execution", {})
    if type(execution) is not dict:
        issues.append("invalid_execution")
        return finding
    finding["execution"] = {key: execution.get(key) for key in ("exit_code", "stop_reason", "elapsed_ms", "truncated")}
    confinement = trial.get("confinement")
    if (type(confinement) is not dict
            or any(confinement.get(name) is not True for name in CONFINEMENT_WITNESSES)):
        issues.append("confinement_not_confirmed")
    version = VERSIONS.get(trial.get("version")) if type(trial.get("version")) is str else None
    if version is None:
        issues.append("unsupported_declared_version")
        return finding
    owner = trial.get("owner", {})
    diagnostic = owner.get("diagnostic", {}) if type(owner) is dict else {}
    if type(diagnostic) is not dict:
        diagnostic = {}
    boundary = []
    if type(owner) is dict and type(owner.get("connection_count")) is int and owner["connection_count"] > 1:
        boundary.append("extra_connection_observed_not_prevented")
    if type(diagnostic.get("client_hellos")) is int and diagnostic["client_hellos"] > 1:
        boundary.append("extra_client_hello_observed_not_prevented")
    if type(diagnostic.get("application_bytes")) is int and diagnostic["application_bytes"] > 0:
        boundary.append("application_data_observed_not_prevented")
    try:
        stdout, stderr = _decode(execution.get("raw_stdout_base64")), _decode(execution.get("raw_stderr_base64"))
        if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
            raise ValueError("combined_output_limit")
        evidence.update(output_bytes=len(stdout) + len(stderr), stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
        out_messages, out_text = _messages(stdout)
        err_messages, err_text = _messages(stderr)
        if err_messages:
            raise ValueError("trace_messages_on_unexpected_stream")
        messages, text = out_messages, out_text + err_text
        hellos = [m for m in messages if m["kind"] == "Handshake" and m["name"] == "ClientHello" and m["direction"] == "write"]
        evidence["client_hellos"] = len(hellos)
        if len(hellos) > 1:
            boundary.append("extra_client_hello_observed_not_prevented")
        if any(m["direction"] == "write" and (m["kind"] == "InnerContent" and m["data"] == b"\x17" or m["kind"] == "Handshake" and m["name"] in {"Certificate", "CertificateVerify", "KeyUpdate"}) for m in messages):
            boundary.append("unexpected_client_message_observed_not_prevented")
        servers = [m for m in messages if m["kind"] == "Handshake" and m["name"] == "ServerHello" and m["direction"] == "read"]
        selected = [_server_hello(m["data"]) for m in servers]
        evidence["hello_retry_request"] = any(row[2] for row in selected)
        alerts = [m for m in messages if m["kind"] == "Alert"]
        received_rejection = any(m["direction"] == "read" and m["data"] == b"\x02\x46" for m in alerts)
        evidence["received_protocol_version_alert"] = received_rejection
        evidence["server_close_notify_observed_by_client"] = any(m["direction"] == "read" and m["data"] == b"\x01\x00" for m in alerts)
        rejection = received_rejection and not servers and len(hellos) == 1
        if any(not _known_text(line, rejection, trial["version"]) for line in text):
            issues.append("unknown_cli_output")
        if any(m["kind"] == "Handshake" and m["name"] in {"NewSessionTicket", "CertificateRequest", "KeyUpdate"} for m in messages):
            issues.append("unexpected_handshake_message")
        if len(hellos) != 1:
            issues.append("expected_one_client_hello")
        if evidence["hello_retry_request"]:
            issues.append("hello_retry_request_outside_contract")
        if execution.get("truncated") is not False or execution.get("stop_reason") is not None or type(execution.get("exit_code")) is not int:
            issues.append("incomplete_execution")
        if trial.get("cleanup", {}).get("closed") is not True:
            issues.append("cleanup_not_confirmed")
        if (owner.get("connection_count") != 1 or owner.get("request_count") != 1
                or diagnostic.get("client_hellos") != 1 or diagnostic.get("application_bytes") != 0
                or diagnostic.get("completed") is not True or diagnostic.get("error") is not None
                or diagnostic.get("expected_version") != trial["version"]):
            issues.append("incomplete_or_mismatched_owner")
        received_records = _owner_records(diagnostic, "received_records")
        sent_records = _owner_records(diagnostic, "sent_records")
        evidence["owner_received_records"] = len(received_records)
        evidence["owner_sent_records"] = len(sent_records)
        for direction, rows in (("write", received_records), ("read", sent_records)):
            headers = [m["data"] for m in messages if m["kind"] == "RecordHeader" and m["direction"] == direction]
            if headers != [raw[:5] for raw in rows]:
                if (direction == "read" and not evidence["server_close_notify_observed_by_client"]
                        and _unread_server_close(diagnostic, trial["version"], rows, headers)):
                    evidence["owner_final_close_notify_unread"] = True
                else:
                    issues.append("client_owner_record_headers_mismatch")
        owner_messages = diagnostic.get("handshake_messages")
        if type(owner_messages) is not list or len(owner_messages) > 32:
            issues.append("invalid_owner_handshake_ledger")
        else:
            for message in messages:
                if message["kind"] != "Handshake" or message["name"] not in {"ClientHello", "ServerHello", "Finished"}:
                    continue
                required = {"direction": "read" if message["direction"] == "write" else "write",
                            "type": message["data"][0], "length": len(message["data"]),
                            "sha256": hashlib.sha256(message["data"]).hexdigest()}
                if sum(type(row) is dict and all(row.get(key) == value for key, value in required.items()) for row in owner_messages) != 1:
                    issues.append("client_owner_handshake_mismatch")
        if rejection:
            if len(alerts) != 1 or not any(raw[0] == 21 and raw[5:] == b"\x02\x46" for raw in sent_records):
                issues.append("rejection_not_corroborated")
            if diagnostic.get("handshake_completed") is not False:
                issues.append("conflicting_owner_handshake")
            if not issues:
                finding["outcome"] = "explicit_protocol_rejection"
        else:
            sequence = [(m["direction"], m["name"]) for m in messages if m["kind"] == "Handshake"]
            expected_sequence = [("write", "ClientHello"), ("read", "ServerHello")]
            if trial["version"] == "tls1_3":
                expected_sequence += [("read", name) for name in ("EncryptedExtensions", "Certificate", "CertificateVerify", "Finished")]
                expected_sequence += [("write", "Finished")]
            else:
                expected_sequence += [("read", name) for name in ("Certificate", "ServerKeyExchange", "ServerHelloDone")]
                expected_sequence += [("write", "ClientKeyExchange"), ("write", "Finished"), ("read", "Finished")]
            if sequence != expected_sequence:
                issues.append("unexpected_handshake_sequence")
            finished = [m for m in messages if m["kind"] == "Handshake" and m["name"] == "Finished"]
            expected_size = 48 if trial["version"] == "tls1_3" else 12
            finish_directions = [m["direction"] for m in finished]
            expected_directions = ["read", "write"] if trial["version"] == "tls1_3" else ["write", "read"]
            if (selected != [(version[2], version[3], False)] or finish_directions != expected_directions
                    or any(len(m["data"]) != expected_size + 4 for m in finished)):
                issues.append("incomplete_or_mismatched_handshake")
            if (text.count("Protocol version: " + version[0]) != 1 or text.count("Ciphersuite: " + version[1]) != 1
                    or text.count("Verification: OK") != 1 or text.count("Verified peername: harbordesk.test") != 1):
                issues.append("missing_or_conflicting_client_verification")
            if any(m["data"] != b"\x01\x00" for m in alerts) or not any(m["direction"] == "write" and m["data"] == b"\x01\x00" for m in alerts):
                issues.append("missing_or_unexpected_close_alert")
            if ([(m["direction"], m["data"]) for m in alerts] not in
                    [[("write", b"\x01\x00")], [("write", b"\x01\x00"), ("read", b"\x01\x00")]]
                    or diagnostic.get("alerts") != [
                        {"direction": "read", "type": 1, "description": 0},
                        {"direction": "write", "type": 1, "description": 0}]):
                issues.append("shutdown_alerts_not_corroborated")
            if (diagnostic.get("handshake_completed") is not True or diagnostic.get("clean_close") is not True
                    or diagnostic.get("negotiated_version") != version[0] or diagnostic.get("cipher") != version[1]
                    or execution.get("exit_code") != 0):
                issues.append("handshake_not_independently_corroborated")
            if not issues:
                finding["outcome"] = "handshake_completed"
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        issues.append(str(error) if isinstance(error, ValueError) else "invalid_trial_structure")
    if boundary:
        finding["outcome"] = "boundary_failure"
        issues.extend(boundary)
    finding["issues"] = list(dict.fromkeys(issues))
    return finding
