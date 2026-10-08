"""Closed, bounded replay contract for *claimed diagnostic* TLS captures.

This module reads no files and grants no execution authority. Shape validation,
input commitments and corroborated observations do not authenticate a capture's
origin or turn private diagnostic JSON into product-authorized evidence. The
four identifiers below are deliberately absent from the production registry.
"""

import base64
import binascii
import hashlib
import json
import re
from types import MappingProxyType

from .tls_posture_mediated_trace import analyze_trial


CONTRACT_VERSION = "1"
PROVENANCE = "owned_tls_mediated_diagnostic_v1"
MAX_OWNER_BYTES = 262144
MAX_INPUT_BYTES = MAX_OWNER_BYTES + 32768
MAX_RESULT_BYTES = 4096
PROFILE_IDS = MappingProxyType({version: "tls_posture_" + version + "_v1"
    for version in ("tls1", "tls1_1", "tls1_2", "tls1_3")})
CASES = ("modern", "legacy", "reject", "hrr")
_HEX = re.compile(r"[0-9a-f]*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CODE = re.compile(r"[a-zA-Z][a-zA-Z0-9_]{0,95}\Z")
_LIBRARY = re.compile(r"/(?:usr/)?lib(?:64)?/[A-Za-z0-9_./+-]+\.so(?:\.[0-9]+)*\.?\Z")
_COMMON_ARGV = ("/tool/openssl", "s_client", "-4", "-connect", "127.0.0.1:8080",
    "-servername", "harbordesk.test", "-verify_hostname", "harbordesk.test",
    "-verify_return_error", "-verify", "1", "-auth_level", "2", "-CAfile",
    "/tool/data/fixture-ca.pem", "-no-CApath", "-no-CAstore", "-groups", "P-256",
    "-no_comp", "-no_ticket", "-no_renegotiation", "-no_legacy_server_connect",
    "-no_tx_cert_comp", "-no_rx_cert_comp", "-brief", "-state", "-msg",
    "-nocommands", "-no_ign_eof")
_FIXED_ARGV = {version: _COMMON_ARGV + ("-" + version, "-cipher",
    "ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0" if version in ("tls1", "tls1_1") else
    "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=2") + (
    ("-ciphersuites", "TLS_AES_256_GCM_SHA384") if version == "tls1_3" else ())
    for version in PROFILE_IDS}
_WITNESSES = {"worker_ready", "private_namespaces_and_firewall", "read_only_pinned_runtime",
    "landlock_and_seccomp", "no_inherited_descriptors", "unix_socket_and_socketpair_denied"}


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _fail():
    raise ValueError("invalid_tls_observation")


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail()
    return value


def _integer(value, minimum=0, maximum=32768):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail()


def _boolean(value):
    if type(value) is not bool:
        _fail()


def _string(value, maximum=128, pattern=None):
    if (type(value) is not str or not 1 <= len(value) <= maximum
            or not value.isascii() or any(ord(c) < 32 or ord(c) > 126 for c in value)
            or pattern is not None and pattern.fullmatch(value) is None):
        _fail()


def _choice(value, choices):
    if type(value) is not str or value not in choices:
        _fail()


def _nullable(value, validator):
    if value is not None:
        validator(value)


def _digest(value):
    _string(value, 64, _DIGEST)


def _rows(value, limit):
    if type(value) is not list or len(value) > limit:
        _fail()
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _not_number(value):
    _fail()


def encode_input(raw_trial, version):
    """Frame bounded bytes without parsing untrusted capture JSON in the host.

    The confined parser alone checks JSON, duplicates, metadata and semantics.
    Whitespace and original capture bytes remain part of the exact commitment.
    """
    _choice(version, PROFILE_IDS)
    if type(raw_trial) is not bytes or not 1 <= len(raw_trial) <= MAX_INPUT_BYTES:
        _fail()
    prefix = _encode({"contract_version": CONTRACT_VERSION, "provenance": PROVENANCE,
                      "profile_id": PROFILE_IDS[version]})[:-1] + b',"trial":'
    if len(prefix) + len(raw_trial) + 1 > MAX_INPUT_BYTES:
        _fail()
    return prefix + raw_trial + b"}"


def _manifest(value, digest):
    _object(value, {"version", "profile", "executable", "interpreter", "files"})
    if (value["version"] != "1" or value["profile"] != "tls-posture-development-runtime-v1"
            or value["executable"] != "/tool/openssl" or len(_encode(value)) > 12288):
        _fail()
    _string(value["interpreter"], 256,
            re.compile(r"/(?:usr/)?lib(?:64)?/(?:[^/]+/)?ld-linux[^/]*\.so\.[0-9]+\Z"))
    rows = _rows(value["files"], 48)
    if len(rows) < 3:
        _fail()
    destinations, total = set(), 0
    for row in rows:
        _object(row, {"source", "destination", "size", "sha256"})
        for key in ("source", "destination"):
            _string(row[key], 256)
            if ".." in row[key] or "//" in row[key]:
                _fail()
        _integer(row["size"], 1, 16 * 1024 * 1024)
        _digest(row["sha256"])
        source, destination = row["source"], row["destination"]
        if destination == "/tool/openssl":
            valid = source == "/usr/bin/openssl"
        elif destination == "/tool/data/fixture-ca.pem":
            valid = (source == "compiled:fixture-ca" and row["size"] == 591
                and row["sha256"] == "617015dc0014927cacb2c334ed861b091ea4846b2461540aa4aac3fa2138b84d")
        else:
            valid = bool(_LIBRARY.fullmatch(source) and _LIBRARY.fullmatch(destination))
        if not valid or destination in destinations:
            _fail()
        destinations.add(destination)
        total += row["size"]
    if (not {"/tool/openssl", "/tool/data/fixture-ca.pem", value["interpreter"]} <= destinations
            or total > 64 * 1024 * 1024 or rows != sorted(rows, key=lambda r: r["destination"])
            or hashlib.sha256(_encode(value)).hexdigest() != digest):
        _fail()


def _records(value, limit, hashed=False):
    field = "raw_sha256" if hashed else "raw_hex"
    for row in _rows(value, limit):
        _object(row, {"type", "version", "payload_length", field})
        _integer(row["type"], 0, 255)
        _string(row["version"], 4, re.compile(r"[0-9a-f]{4}\Z"))
        _integer(row["payload_length"], 0, 18432)
        if hashed:
            _digest(row[field])
        elif (type(row[field]) is not str or len(row[field]) > 2 * (18432 + 5)
                or len(row[field]) % 2 or _HEX.fullmatch(row[field]) is None):
            _fail()


def _peer(value):
    _object(value, {"case", "expected_version", "completed", "handshake_completed", "clean_close",
        "hrr_sent", "client_hellos", "application_bytes", "received_bytes", "sent_bytes", "error",
        "cipher", "negotiated_version", "handshake_messages", "alerts", "received_records",
        "sent_records", "server_close_notify_record"})
    _choice(value["case"], CASES)
    _choice(value["expected_version"], PROFILE_IDS)
    for key in ("completed", "handshake_completed", "clean_close", "hrr_sent"):
        _boolean(value[key])
    for key in ("client_hellos", "application_bytes", "received_bytes", "sent_bytes"):
        _integer(value[key])
    _nullable(value["error"], lambda v: _string(v, 96, _CODE))
    for key in ("cipher", "negotiated_version"):
        _nullable(value[key], _string)
    _records(value["received_records"], 8)
    _records(value["sent_records"], 32)
    for row in _rows(value["handshake_messages"], 32):
        _object(row, {"direction", "type", "length", "sha256"})
        _choice(row["direction"], ("read", "write"))
        _integer(row["type"], 0, 255)
        _integer(row["length"], 0, 18432)
        _digest(row["sha256"])
    for row in _rows(value["alerts"], 32):
        _object(row, {"direction", "type", "description"})
        _choice(row["direction"], ("read", "write"))
        _integer(row["type"], 0, 255)
        _integer(row["description"], 0, 255)
    close = value["server_close_notify_record"]
    if close is not None:
        _object(close, {"sent_record_index", "raw_sha256", "payload_length"})
        _integer(close["sent_record_index"], 0, 31)
        _digest(close["raw_sha256"])
        _integer(close["payload_length"], 0, 18432)


def _mediation(value):
    counters = {"client_ingress_bytes", "client_forwarded_bytes", "client_transmitted_bytes",
        "server_ingress_bytes", "server_forwarded_bytes", "server_transmitted_bytes",
        "server_ingress_record_count", "frontend_connections_admitted", "peer_streams_admitted",
        "extra_frontend_connections_refused", "forwarded_client_hellos"}
    booleans = {"completed", "blocked", "client_eof", "backend_eof", "connection_deadline_expired", "threads_joined"}
    _object(value, counters | booleans | {"version", "error", "block_reason", "blocked_record_index",
        "client_ingress_records", "client_forwarded_records", "server_ingress_records",
        "server_forwarded_records", "server_pending_record", "gate_state"})
    if value["version"] != "1":
        _fail()
    for key in counters:
        _integer(value[key])
    for key in booleans:
        _boolean(value[key])
    for key in ("error", "block_reason"):
        _nullable(value[key], lambda v: _string(v, 96, _CODE))
    _nullable(value["blocked_record_index"], lambda v: _integer(v, 0, 8))
    _string(value["gate_state"], 96, _CODE)
    for key in ("client_ingress_records", "client_forwarded_records"):
        _records(value[key], 8)
    for key in ("server_ingress_records", "server_forwarded_records"):
        _records(value[key], 32, True)
    if value["server_pending_record"] is not None:
        _records([value["server_pending_record"]], 1, True)


def _execution(value):
    _object(value, {"exit_code", "stop_reason", "elapsed_ms", "truncated", "raw_stdout_base64", "raw_stderr_base64"})
    _nullable(value["exit_code"], lambda v: _integer(v, -255, 255))
    _nullable(value["stop_reason"], lambda v: _string(v, 96, _CODE))
    _integer(value["elapsed_ms"], 0, 30000)
    _boolean(value["truncated"])
    streams = []
    for key in ("raw_stdout_base64", "raw_stderr_base64"):
        encoded = value[key]
        if type(encoded) is not str or len(encoded) > 10924:
            _fail()
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            _fail()
        if base64.b64encode(raw).decode("ascii") != encoded:
            _fail()
        streams.append(raw)
    if sum(map(len, streams)) > 8192:
        _fail()
    return streams


def _trial(value, profile):
    _object(value, {"schema_version", "diagnostic_only", "mediated", "version", "case", "argv",
        "runtime_manifest", "runtime_sha256", "execution", "owner", "confinement", "cleanup",
        "actual_provider_calls", "actual_cost_microusd"})
    if value["schema_version"] != "1" or value["diagnostic_only"] is not True or value["mediated"] is not True:
        _fail()
    _choice(value["version"], PROFILE_IDS)
    _choice(value["case"], CASES)
    if (PROFILE_IDS[value["version"]] != profile or type(value["argv"]) is not list
            or value["argv"] != list(_FIXED_ARGV[value["version"]])
            or value["case"] == "hrr" and value["version"] != "tls1_3"):
        _fail()
    for key in ("actual_provider_calls", "actual_cost_microusd"):
        _integer(value[key], 0, 0)
    _digest(value["runtime_sha256"])
    _manifest(value["runtime_manifest"], value["runtime_sha256"])
    streams = _execution(value["execution"])
    owner = _object(value["owner"], {"connection_count", "request_count", "diagnostic", "mediation"})
    if len(_encode(owner)) > MAX_OWNER_BYTES:
        _fail()
    for key in ("connection_count", "request_count"):
        _integer(owner[key], 0, 2)
    _peer(owner["diagnostic"])
    _mediation(owner["mediation"])
    _object(value["confinement"], _WITNESSES)
    for witness in value["confinement"].values():
        _boolean(witness)
    _object(value["cleanup"], {"closed"})
    _boolean(value["cleanup"]["closed"])
    return streams


def _execution_outcome(value):
    if value["stop_reason"] is not None or value["truncated"] or value["exit_code"] is None:
        return "incomplete"
    return "succeeded" if value["exit_code"] == 0 else "failed"


def parse_observation(raw):
    """Validate closed input and report observations; never infer authorization."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_INPUT_BYTES:
        _fail()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=_not_number, parse_float=_not_number)
        _object(value, {"contract_version", "provenance", "profile_id", "trial"})
        if value["contract_version"] != CONTRACT_VERSION or value["provenance"] != PROVENANCE:
            _fail()
        _choice(value["profile_id"], PROFILE_IDS.values())
        trial = value["trial"]
        stdout, stderr = _trial(trial, value["profile_id"])
        finding = analyze_trial(trial)
        execution = {key: trial["execution"][key] for key in ("exit_code", "stop_reason", "elapsed_ms", "truncated")}
        execution["outcome"] = _execution_outcome(execution)
        issues = finding["issues"]
        if any(type(code) is not str or _CODE.fullmatch(code) is None for code in issues):
            issues = ["inconclusive_diagnostic_analysis"]
        result = {"contract_version": CONTRACT_VERSION, "provenance": PROVENANCE,
            "diagnostic_only": True, "execution_authority": False, "product_accepted": False,
            "input_sha256": hashlib.sha256(raw).hexdigest(), "profile_id": value["profile_id"],
            "tls_version": trial["version"], "fixture_case": trial["case"], "execution": execution,
            "observation": {key: finding[key] for key in ("outcome", "useful_task_completed", "extra_client_hello_prevented")},
            "issues": issues, "evidence": {"stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "client_ingress_bytes": trial["owner"]["mediation"]["client_ingress_bytes"],
                "client_forwarded_bytes": trial["owner"]["mediation"]["client_forwarded_bytes"],
                "peer_client_hellos": trial["owner"]["diagnostic"]["client_hellos"]},
            "actual_provider_calls": 0, "actual_cost_microusd": 0}
        return validate_observation(result)
    except (UnicodeError, RecursionError, OverflowError, KeyError, TypeError, AttributeError):
        _fail()


def validate_observation(value):
    """Validate/return a normalized result, including verdict consistency."""
    _object(value, {"contract_version", "provenance", "diagnostic_only", "execution_authority",
        "product_accepted", "input_sha256", "profile_id", "tls_version", "fixture_case", "execution",
        "observation", "issues", "evidence", "actual_provider_calls", "actual_cost_microusd"})
    if (value["contract_version"] != CONTRACT_VERSION or value["provenance"] != PROVENANCE
            or value["diagnostic_only"] is not True or value["execution_authority"] is not False
            or value["product_accepted"] is not False):
        _fail()
    _choice(value["tls_version"], PROFILE_IDS)
    _choice(value["fixture_case"], CASES)
    if (value["profile_id"] != PROFILE_IDS[value["tls_version"]]
            or value["fixture_case"] == "hrr" and value["tls_version"] != "tls1_3"):
        _fail()
    _digest(value["input_sha256"])
    for key in ("actual_provider_calls", "actual_cost_microusd"):
        _integer(value[key], 0, 0)
    execution = _object(value["execution"], {"outcome", "exit_code", "stop_reason", "elapsed_ms", "truncated"})
    _nullable(execution["exit_code"], lambda v: _integer(v, -255, 255))
    _nullable(execution["stop_reason"], lambda v: _string(v, 96, _CODE))
    _integer(execution["elapsed_ms"], 0, 30000)
    _boolean(execution["truncated"])
    if execution["outcome"] != _execution_outcome(execution):
        _fail()
    observation = _object(value["observation"], {"outcome", "useful_task_completed", "extra_client_hello_prevented"})
    flags = {"handshake_completed": (True, False), "explicit_protocol_rejection": (True, False),
             "extra_client_hello_prevented": (False, True), "inconclusive": (False, False)}
    _choice(observation["outcome"], flags)
    for key in ("useful_task_completed", "extra_client_hello_prevented"):
        _boolean(observation[key])
    if (observation["useful_task_completed"], observation["extra_client_hello_prevented"]) != flags[observation["outcome"]]:
        _fail()
    if observation["outcome"] != "inconclusive":
        expected_exit = 0 if observation["outcome"] == "handshake_completed" else 1
        if (execution["exit_code"] != expected_exit or execution["outcome"] == "incomplete"
                or observation["outcome"] == "extra_client_hello_prevented"
                and (value["fixture_case"] != "hrr" or value["tls_version"] != "tls1_3")):
            _fail()
    issues = _rows(value["issues"], 16)
    for issue in issues:
        _string(issue, 96, _CODE)
    if len(set(issues)) != len(issues) or bool(issues) != (observation["outcome"] == "inconclusive"):
        _fail()
    evidence = _object(value["evidence"], {"stdout_sha256", "stderr_sha256", "client_ingress_bytes",
        "client_forwarded_bytes", "peer_client_hellos"})
    for key in ("stdout_sha256", "stderr_sha256"):
        _digest(evidence[key])
    for key in ("client_ingress_bytes", "client_forwarded_bytes", "peer_client_hellos"):
        _integer(evidence[key])
    if observation["outcome"] != "inconclusive":
        ingress, forwarded = evidence["client_ingress_bytes"], evidence["client_forwarded_bytes"]
        if (evidence["peer_client_hellos"] != 1 or not 6 <= forwarded <= ingress <= 8192
                or observation["useful_task_completed"] and ingress != forwarded
                or observation["extra_client_hello_prevented"] and ingress == forwarded):
            _fail()
    if len(_encode(value)) > MAX_RESULT_BYTES:
        _fail()
    return value
