"""Production parser framing, canonical conclusions and networkless custody."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import network_tools_web_hierarchy_parser as parser
from recon_cockpit.secure_agent import network_tools_web_hierarchy_parser_runtime as runtime
from recon_cockpit.secure_agent.network_tools_web_hierarchy_spec import TOOL_ID, PARSER_VERSION
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from test_web_hierarchy_observation import _evidence, _raw


def sample(variant="nested"):
    statuses = {} if variant == "empty" else {"/harbordesk/index.html": 200,
        "/harbordesk/docs/index.html": 200, "/harbordesk/api/status": 200}
    if variant == "wildcard":
        from recon_cockpit.secure_agent.web_hierarchy_spec import PATHS
        statuses = dict.fromkeys(PATHS, 200)
    if variant == "mixed-controls": statuses["/harbordesk/docs/missing-control-b"] = 200
    if variant == "redirect": statuses["/harbordesk/docs/index.html"] = 302
    rows, owner = _evidence(statuses)
    owner["diagnostic"]["case"] = variant
    owner = {"sequence": 1, **owner}
    raw = (json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    return TOOL_ID, _raw(rows), b"", {"owner_raw": raw, "exit_code": 0, "stop_reason": None, "truncated": False}


@pytest.mark.parametrize("variant,outcome,useful", [("nested", "observed_responses", True),
    ("empty", "empty", True), ("hostile", "observed_responses", True),
    ("wildcard", "ambiguous", False), ("mixed-controls", "ambiguous", False),
    ("redirect", "ambiguous", False)])
def test_complete_corroborated_client_and_owner_bytes_have_distinct_production_identity(variant, outcome, useful):
    tool, stdout, stderr, extra = sample(variant)
    value = parser.parse(tool, stdout, stderr, **extra)
    assert value["kind"] == "web_hierarchy" and value["parser_version"] == PARSER_VERSION
    assert value["outcome"] == outcome and value["useful_task_completed"] is useful
    assert value["owner_sha256"] == hashlib.sha256(extra["owner_raw"]).hexdigest()
    assert value["stdout_sha256"] == hashlib.sha256(stdout).hexdigest()
    assert value["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
    assert "production_evidence" not in value and "diagnostic" not in value


def test_native_ffuf_progress_erasure_is_bounded_and_preserved_in_stderr_commitment():
    tool, stdout, _, extra = sample()
    stderr = b"\r\x1b[2K" * 12
    result = parser.parse(tool, stdout, stderr, **extra)
    assert result["useful_task_completed"]
    assert result["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()


@pytest.mark.parametrize("stderr", [b"\r\x1b[2K" * 13, b"\r\x1b[2Kwarning", b"\x1b[2K",
    b"\r\x1b[2J", b"\r\x1b[2K\n", b"\r\x1b[2K\x00"])
def test_nonrecipe_stderr_cannot_become_useful_work(stderr):
    tool, stdout, _, extra = sample()
    with pytest.raises(ValueError):
        parser.parse(tool, stdout, stderr, **extra)


@pytest.mark.parametrize("change", ["owner_sequence", "owner_case", "no_newline", "owner_duplicate", "owner_float",
    "incomplete_owner", "parallel_owner", "missing_client", "stderr", "exit", "timeout", "truncated"])
def test_partial_failed_ambiguous_custody_cannot_become_complete_work(change):
    tool, stdout, stderr, extra = sample()
    owner = json.loads(extra["owner_raw"])
    if change == "owner_sequence": owner["sequence"] = 2
    elif change == "owner_case": owner["diagnostic"]["case"] = "external"
    elif change == "incomplete_owner": owner["diagnostic"]["ledger"][0]["completed"] = False
    elif change == "parallel_owner": owner["diagnostic"]["max_active_requests"] = 2
    elif change == "missing_client": stdout = stdout[:len(stdout) // 2]
    elif change == "stderr": stderr = b"unexpected warning"
    elif change == "exit": extra["exit_code"] = 1
    elif change == "timeout": extra["stop_reason"] = "timeout"
    elif change == "truncated": extra["truncated"] = True
    extra["owner_raw"] = (json.dumps(owner) + "\n").encode()
    if change == "no_newline": extra["owner_raw"] = extra["owner_raw"][:-1]
    elif change == "owner_duplicate": extra["owner_raw"] = extra["owner_raw"].replace(b'"sequence": 1', b'"sequence": 1, "sequence": 1')
    elif change == "owner_float": extra["owner_raw"] = extra["owner_raw"].replace(b'"sequence": 1', b'"sequence": 1.0')
    with pytest.raises(ValueError): parser.parse(tool, stdout, stderr, **extra)


@pytest.mark.parametrize("field,value", [("kind", "web_hierarchy_diagnostic"), ("parser_version", "old"),
    ("tool_id", "ffuf_content_discovery_v1"), ("outcome", "empty"), ("useful_task_completed", False),
    ("owner_sha256", "bad"), ("stdout_sha256", "A" * 64), ("stderr_sha256", None),
    ("rows", []), ("prefixes", []), ("extra", True)])
def test_normalized_result_cannot_forge_version_commitment_or_conclusions(field, value):
    tool, stdout, stderr, extra = sample()
    result = parser.parse(tool, stdout, stderr, **extra)
    result[field] = value
    with pytest.raises(ValueError): parser.validate_result(tool, result)


@pytest.mark.parametrize("fault", ["path", "status", "bytes", "classification", "control", "observed", "prefix_outcome"])
def test_normalized_row_and_prefix_claims_are_independently_recomputed(fault):
    tool, stdout, stderr, extra = sample()
    result = parser.parse(tool, stdout, stderr, **extra)
    if fault == "path": result["rows"][0]["path"] = "/outside"
    elif fault == "status": result["rows"][0]["status_code"] = True
    elif fault == "bytes": result["rows"][0]["bytes"] = 1025
    elif fault == "classification": result["rows"][0]["classification"] = "not_found"
    elif fault == "control": result["prefixes"][0]["control_statuses"][0] = 200
    elif fault == "observed": result["prefixes"][0]["observed_paths"] = ["/outside"]
    else: result["prefixes"][0]["outcome"] = "empty"
    with pytest.raises(ValueError): parser.validate_result(tool, result)


@pytest.mark.parametrize("change", ["size", "short", "duplicate", "extra", "negative", "boolean", "overflow"])
def test_binary_framing_rejects_truncated_or_recommitted_untrusted_lengths(change):
    tool, stdout, stderr, extra = sample()
    raw = parser.encode_input(tool, stdout, stderr, **extra)
    size = int.from_bytes(raw[:4], "big")
    header = json.loads(raw[4:4 + size])
    if change == "size": raw = (1025).to_bytes(4, "big") + raw[4:]
    elif change == "short": raw = raw[:3]
    elif change == "overflow": raw = b"x" * (parser.MAX_INPUT_BYTES + 1)
    else:
        if change == "extra": header["authority"] = True
        elif change == "negative": header["stdout_bytes"] = -1
        elif change == "boolean": header["exit_code"] = False
        encoded = json.dumps(header).encode()
        if change == "duplicate": encoded = encoded[:-1] + b',"tool_id":"ffuf_web_hierarchy_v1"}'
        raw = len(encoded).to_bytes(4, "big") + encoded + raw[4 + size:]
    with pytest.raises(ValueError): parser.parse_input(raw)


def test_networkless_parser_mount_set_can_import_without_owner_fixture_or_executable(tmp_path):
    package = tmp_path / "recon_cockpit" / "secure_agent"
    package.mkdir(parents=True)
    (package.parent / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = Path(parser.__file__).parent
    for name in runtime.PARSER_MODULES:
        (package / (name + ".py")).write_bytes((source / (name + ".py")).read_bytes())
    tool, stdout, stderr, extra = sample()
    code = """
import sys
sys.path.insert(0, sys.argv[1])
from recon_cockpit.secure_agent.network_tools_web_hierarchy_parser import parse_input
assert parse_input(sys.stdin.buffer.read())["useful_task_completed"]
assert not any(name.endswith("fixture") or name.endswith("owner") for name in sys.modules)
"""
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path)],
        input=parser.encode_input(tool, stdout, stderr, **extra), capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


def _reply(raw, result):
    return {"contract_version": PARSER_VERSION, "boundary_checks": dict.fromkeys(runtime.BOUNDARY_NAMES, True),
        "status": "parsed", "result": {"input_sha256": hashlib.sha256(raw).hexdigest(), "observation": result}}


@pytest.mark.parametrize("fault", [None, "boundary", "commitment", "status", "stderr", "exit", "truncated", "invalid"])
def test_isolated_reply_requires_all_witnesses_exact_input_and_valid_observation(monkeypatch, fault):
    tool, stdout, stderr, extra = sample()
    raw = parser.encode_input(tool, stdout, stderr, **extra)
    expected = parser.parse_input(raw)
    reply = _reply(raw, expected)
    if fault == "boundary": reply["boundary_checks"][next(iter(runtime.BOUNDARY_NAMES))] = False
    elif fault == "commitment": reply["result"]["input_sha256"] = "0" * 64
    elif fault == "status": reply["status"] = "granted"
    elif fault == "invalid": reply.update(status="invalid", result=None)
    monkeypatch.setattr(runtime, "_command", lambda *_: ["fixed-networkless-parser"])
    monkeypatch.setattr(runtime, "_capture_bounded", lambda *a, **kw: (
        1 if fault == "exit" else 0, json.dumps(reply).encode(), b"bad" if fault == "stderr" else b"",
        "output_limit" if fault == "truncated" else None))
    control = ExecutionControl(10, clock=lambda: 0)
    if fault == "invalid":
        with pytest.raises(ValueError): runtime._parse_isolated(tool, raw, control, None)
    elif fault is not None:
        with pytest.raises(IsolationUnavailable): runtime._parse_isolated(tool, raw, control, None)
    else:
        assert runtime._parse_isolated(tool, raw, control, None) == expected


def test_parser_command_never_mounts_native_ffuf_or_network_owner(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(runtime, "_namespaces", lambda: dict.fromkeys(runtime.NAMESPACE_NAMES, "private"))
    argv = runtime._command(("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]))
    assert "--unshare-net" in argv and "--clearenv" in argv
    assert not any("/tool/" in value or value.endswith("owner.py") or value.endswith("fixture.py") for value in argv)
    with pytest.raises(IsolationUnavailable):
        runtime._command(("/usr/lib/python3.13", [("/usr/bin/ffuf", "/usr/bin/ffuf")]))
