import importlib.util
import json
import os
from pathlib import Path
import time

import pytest

from recon_cockpit.secure_agent import tls_posture_observation_inspection as inspection
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.tls_posture_observation_contract import MAX_INPUT_BYTES, encode_input


def _cli():
    path = Path(__file__).parents[1] / "scripts" / "inspect_tls_posture_diagnostic.py"
    spec = importlib.util.spec_from_file_location("inspect_tls_diagnostic_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_inspection_passes_uninterpreted_bytes_and_preserves_file(tmp_path, monkeypatch):
    capture = tmp_path / "capture.json"
    raw = b'{"untrusted":"not decoded on the host"}'
    capture.write_bytes(raw)
    capture.chmod(0o600)
    before = capture.stat()
    observed = []
    monkeypatch.setattr(inspection, "parse_isolated_observation",
                        lambda data, **kw: observed.append((data, kw)) or {"diagnostic_only": True})
    assert inspection.inspect_saved_diagnostic(capture, "tls1_3") == {"diagnostic_only": True}
    assert observed == [(encode_input(raw, "tls1_3"), {"control": None})]
    after = capture.stat()
    assert capture.read_bytes() == raw
    assert (before.st_ino, before.st_mtime_ns, before.st_mode, before.st_size) == (
        after.st_ino, after.st_mtime_ns, after.st_mode, after.st_size)


def test_input_descriptor_is_closed_before_parser_launch(tmp_path, monkeypatch):
    path = tmp_path / "capture.json"
    path.write_bytes(b"{}")
    original, descriptors = inspection.os.open, []

    def track(*args):
        fd = original(*args)
        descriptors.append(fd)
        return fd

    def parse(*args, **kwargs):
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
        return {"diagnostic_only": True}

    monkeypatch.setattr(inspection.os, "open", track)
    monkeypatch.setattr(inspection, "parse_isolated_observation", parse)
    inspection.inspect_saved_diagnostic(path, "tls1")


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo", "empty", "oversize"])
def test_nonregular_unbounded_or_symlink_inputs_never_reach_parser(tmp_path, monkeypatch, kind):
    path = tmp_path / "capture"
    if kind == "symlink":
        target = tmp_path / "target"
        target.write_bytes(b"{}")
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(b"" if kind == "empty" else b"x" * (MAX_INPUT_BYTES + 1))
    monkeypatch.setattr(inspection, "parse_isolated_observation", lambda *a, **k: pytest.fail("parser invoked"))
    with pytest.raises((ValueError, OSError)):
        inspection.inspect_saved_diagnostic(path, "tls1_2")


def test_mutating_capture_refused(tmp_path, monkeypatch):
    path = tmp_path / "capture.json"
    path.write_bytes(b"{}")
    original, calls = os.read, []

    def changing(fd, size):
        chunk = original(fd, size)
        if not calls:
            calls.append(True)
            path.write_bytes(b"{} ")
        return chunk

    monkeypatch.setattr(inspection.os, "read", changing)
    monkeypatch.setattr(inspection, "parse_isolated_observation", lambda *a, **k: pytest.fail("parser invoked"))
    with pytest.raises(ValueError, match="changed"):
        inspection.inspect_saved_diagnostic(path, "tls1_1")


def test_bad_version_refused_before_open(monkeypatch):
    monkeypatch.setattr(inspection.os, "open", lambda *a: pytest.fail("input opened"))
    with pytest.raises(ValueError):
        inspection.inspect_saved_diagnostic("/never/open", "tls1_4")


def test_expired_control_refused_before_open(monkeypatch):
    monkeypatch.setattr(inspection.os, "open", lambda *a: pytest.fail("input opened"))
    control = ExecutionControl(time.monotonic() - 1)
    with pytest.raises(ExecutionStopped, match="session_timeout"):
        inspection.inspect_saved_diagnostic("/never/open", "tls1_3", control=control)


def test_cli_read_success_is_not_execution_success(tmp_path, monkeypatch, capsys):
    cli = _cli()
    report = {"diagnostic_only": True, "execution_authority": False,
              "execution": {"status": "failed", "exit_code": 1}, "useful_task_completed": True}
    monkeypatch.setattr(cli, "inspect_saved_diagnostic", lambda *a: report)
    assert cli.main([str(tmp_path / "capture.json"), "--version", "tls1"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "parsed" and out["execution_authority"] is False
    assert out["observation"] == report


@pytest.mark.parametrize("error", [ValueError("hostile raw content"), OSError("private path"), IsolationUnavailable("boundary")])
def test_cli_invalid_or_unavailable_has_no_observation(monkeypatch, capsys, error):
    cli = _cli()

    def reject(*args):
        raise error

    monkeypatch.setattr(cli, "inspect_saved_diagnostic", reject)
    assert cli.main(["capture.json", "--version", "tls1_3"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "diagnostic_only": True, "execution_authority": False, "status": "unavailable_or_invalid"}


def test_cli_requires_explicit_version():
    with pytest.raises(SystemExit) as raised:
        _cli().main(["capture.json"])
    assert raised.value.code == 2


@pytest.mark.parametrize("reason", ["session_timeout", "session_cancelled"])
def test_cli_bounded_stop_returns_explicit_json(monkeypatch, capsys, reason):
    cli = _cli()

    def stop(*args):
        raise ExecutionStopped(reason)

    monkeypatch.setattr(cli, "inspect_saved_diagnostic", stop)
    assert cli.main(["capture.json", "--version", "tls1_3"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "diagnostic_only": True, "execution_authority": False, "status": "stopped", "reason": reason}
