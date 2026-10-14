"""The preparation CLI cannot become a service/authority entry point."""

import importlib.util
import json
from pathlib import Path
import socket
import stat

import pytest


@pytest.fixture
def cli(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/inspect_stock_http_runtime.py"
    entry = importlib.util.spec_from_file_location("stock_http_preflight_cli", path)
    module = importlib.util.module_from_spec(entry)
    entry.loader.exec_module(module)
    monkeypatch.setattr(socket, "socket", lambda *_a, **_k: pytest.fail("preflight created a socket"))
    return module


def arguments(tmp_path, *extra):
    tmp_path.chmod(0o700)
    return ["--configuration", "A", "--case", "O1", "--output", str(tmp_path / "receipt.json"), *extra]


def test_success_is_static_inspection_never_service_readiness(cli, tmp_path, monkeypatch, capsys):
    seen = []
    manifest = {"test_manifest": True}
    monkeypatch.setattr(cli.runtime, "inspect_runtime", lambda config, case, control:
                        seen.append((config, case, control)) or manifest)
    monkeypatch.setattr(cli.runtime, "verify_current", lambda value, control:
                        seen.append((value, control)))
    monkeypatch.setattr(cli.runtime, "manifest_digest", lambda value: "a" * 64)
    assert cli.main(arguments(tmp_path)) == 0
    receipt = tmp_path / "receipt.json"
    value = json.loads(receipt.read_text())
    assert value["status"] == "runtime_inspected" and value["preflight_only"] is True
    assert value["service_execution_verified"] is value["authority_issued"] is False
    assert value["native_services_started"] == value["tool_actions_executed"] == 0
    assert value["actual_provider_calls"] == value["actual_cost_microusd"] == 0
    assert value["runtime_sha256"] == "a" * 64
    assert seen[0][:2] == ("A", "O1") and seen[1] == (manifest, seen[0][2])
    assert 0 < seen[0][2].remaining() <= 15
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert json.loads(capsys.readouterr().out)["service_execution_verified"] is False


@pytest.mark.parametrize("extra", [
    ["--execute"], ["--target", "10.77.0.10"], ["--nginx", "/tmp/nginx"],
    ["--approval", "yes"], ["--model", "anything"], ["--config", "B"],
    ["--case", "O1;touch injected"], ["--configuration", "127.0.0.1"],
])
def test_runtime_and_execution_overrides_are_rejected_before_inspection(cli, tmp_path, monkeypatch, extra):
    monkeypatch.setattr(cli.runtime, "inspect_runtime", lambda *_: pytest.fail("invalid CLI inspected runtime"))
    with pytest.raises(SystemExit) as error:
        cli.main(arguments(tmp_path, *extra))
    assert error.value.code == 2 and not list(tmp_path.iterdir())


def test_changed_runtime_keeps_explicit_failure_without_ready_claim(cli, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.runtime, "inspect_runtime", lambda *_: {"test_manifest": True})
    def changed(*_):
        raise ValueError("runtime changed")
    monkeypatch.setattr(cli.runtime, "verify_current", changed)
    assert cli.main(arguments(tmp_path)) == 2
    value = json.loads((tmp_path / "receipt.json").read_text())
    assert value["status"] == "inspection_failed" and value["failure_type"] == "ValueError"
    assert "runtime_manifest" not in value and "runtime_sha256" not in value
    assert value["service_execution_verified"] is False


@pytest.mark.parametrize("kind", ["existing", "file_symlink", "parent_symlink", "public_parent"])
def test_output_refusal_precedes_runtime_work_and_preserves_existing_files(cli, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(cli.runtime, "inspect_runtime", lambda *_: pytest.fail("unsafe output inspected runtime"))
    args = arguments(tmp_path)
    output = tmp_path / "receipt.json"
    original = tmp_path / "original"
    original.write_bytes(b"preserve")
    if kind == "existing":
        output.write_bytes(b"preserve")
    elif kind == "file_symlink":
        output.symlink_to(original)
    elif kind == "parent_symlink":
        link = tmp_path / "link"
        link.symlink_to(tmp_path, target_is_directory=True)
        args[-1] = str(link / "receipt.json")
    else:
        tmp_path.chmod(0o755)
    assert cli.main(args) == 2
    assert original.read_bytes() == b"preserve"
    if kind in ("existing", "file_symlink"):
        assert output.read_bytes() == b"preserve"
    else:
        assert not output.exists()
