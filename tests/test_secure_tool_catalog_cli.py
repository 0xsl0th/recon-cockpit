"""Catalog discovery has no policy, authority, filesystem or native-runtime effects."""

import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import cli
from recon_cockpit.secure_agent.tool_adapters import ADAPTERS


ROOT = Path(__file__).resolve().parents[1]
CATALOG_COMMANDS = (["--list-tools"], ["--describe-tool", "kerbrute_userenum_v1"])


@pytest.fixture
def inert_cli(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("catalog command attempted policy, authority, filesystem, process or network work")

    monkeypatch.chdir(tmp_path)
    for name in ("_read_bounded", "AuditSink", "Controller", "MockProvider", "_approval_context",
                 "_admission_context", "_planning_context", "_run_http_assessment"):
        monkeypatch.setattr(cli, name, forbidden)
    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    yield tmp_path
    assert not list(tmp_path.iterdir())


def test_list_tools_emits_the_catalog_without_execution(inert_cli, capsys):
    from recon_cockpit.secure_agent.tool_catalog import list_tools

    assert cli.main(["--list-tools"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert result == list_tools()
    assert result["read_only"] is True and result["live_calls_enabled"] is False
    assert result["capability_count"] == 25 and result["external_program_count"] == 13
    assert {row["tool_id"] for row in result["tools"]} == set(ADAPTERS)
    assert captured.err == ""


@pytest.mark.parametrize("tool_id", sorted(ADAPTERS))
def test_every_listed_tool_can_be_described_without_execution(inert_cli, capsys, tool_id):
    from recon_cockpit.secure_agent.tool_catalog import describe_tool

    assert cli.main(["--describe-tool", tool_id]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == describe_tool(tool_id)
    assert captured.err == ""


@pytest.mark.parametrize("command", CATALOG_COMMANDS)
def test_catalog_does_not_require_linux(inert_cli, monkeypatch, capsys, command):
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    assert cli.main(command) == 0
    assert json.loads(capsys.readouterr().out)["read_only"] is True


@pytest.mark.parametrize("command", CATALOG_COMMANDS)
@pytest.mark.parametrize("extra", [
    ["--execute"], ["--dry-run"], ["--fixture"], ["--routed"], ["--owned-lab"],
    ["--policy", "examples/secure-agent-policy.json"], ["--policy=/missing/private-policy.json"],
    ["--audit", ".secure-agent/audit.jsonl"], ["--audit=/missing/audit.jsonl"],
    ["--isolated-audit"], ["--isolated-approvals"], ["--isolated-launch-admission"],
    ["--isolated-launcher"], ["--require-launch-audit"], ["--require-launch-approval"],
    ["--assessment-dir", "evidence"], ["--evaluation-dir", "evaluation"],
    ["--evaluation-repeats", "3"], ["--evaluation-max-seconds", "600"],
    ["--planning-ledger", "ledger"], ["--planning-budget-microusd", "0"],
    ["--assessment-planning-offline", "success"], ["--assessment-planning-owned-tls", "success"],
    ["--openai-model", "unused-model"], ["--openai-max-output-tokens", "1024"],
    ["--broker-max-calls", "3"], ["--broker-max-output-tokens", "3072"],
    ["--broker-max-request-bytes", "49152"], ["--session-max-steps", "3"],
    ["--session-max-seconds", "60"], ["--session-max-output-bytes", "3072"],
    ["--mock"], ["--proposal", "proposal.json"], ["--session-mock", "three_step"],
    ["--isolated-session-mock", "three_step"], ["--openai-offline", "three_step"],
    ["--control-plane-mock", "three_step"], ["--control-plane-openai-offline", "three_step"],
    ["--http-assessment", "a"], ["--discovery-assessment", "a"], ["--nmap-assessment", "a"],
    ["--web-assessment", "vulnerable"], ["--web-tool-assessment", "curl-ok"],
    ["--network-tool-assessment", "kerberos-ok"], ["--http-headers-assessment", "vulnerable"],
    ["--workflow-assessment", "a"], ["--inspect-assessment", "existing-evidence"],
    ["--evaluate-owned-lab"], ["--inspect-evaluation", "existing-evaluation"],
    ["--evaluate-owned-planning"], ["--inspect-planning-evaluation", "existing-planning"],
    ["--evaluate-web-comparison"], ["--inspect-web-comparison", "existing-comparison"],
    ["--exec"], ["--pol", "examples/secure-agent-policy.json"], ["unexpected-positional"],
])
def test_catalog_rejects_other_cli_options_even_explicit_defaults(inert_cli, capsys, command, extra):
    with pytest.raises(SystemExit) as error:
        cli.main([*command, *extra])
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "error:" in captured.err


@pytest.mark.parametrize("arguments", [
    ["--list-tools", "--describe-tool", "tcp_connect"], ["--describe-tool"],
    ["--list-tools=anything"], ["--describe-tool", "unknown"],
    ["--describe-tool="], ["--describe-tool", "not-a-tool\n\x1b[31m"],
    ["--list-t"], ["--describe-t", "tcp_connect"],
])
def test_invalid_catalog_selection_is_inert(inert_cli, capsys, arguments):
    with pytest.raises(SystemExit) as error:
        cli.main(arguments)
    assert error.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "error:" in captured.err
    assert "\x1b" not in captured.err


def test_catalog_accepts_equals_syntax_and_process_arguments(inert_cli, monkeypatch, capsys):
    from recon_cockpit.secure_agent.tool_catalog import describe_tool

    monkeypatch.setattr(sys, "argv", ["recon-secure-agent", "--describe-tool=kerbrute_userenum_v1"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out) == describe_tool("kerbrute_userenum_v1")


def test_cli_help_exposes_both_read_only_commands(inert_cli, capsys):
    with pytest.raises(SystemExit) as result:
        cli.main(["--help"])
    assert result.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--list-tools" in help_text and "--describe-tool TOOL_ID" in help_text
    assert "without execution" in help_text and "without reading policy" in help_text


@pytest.mark.parametrize("command", CATALOG_COMMANDS)
def test_module_entrypoint_works_outside_repo_without_installed_tools(tmp_path, command):
    result = subprocess.run([sys.executable, "-m", "recon_cockpit.secure_agent", *command],
        cwd=tmp_path, env={"PATH": str(tmp_path), "PYTHONPATH": str(ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["read_only"] is True
    assert result.stderr == "" and not list(tmp_path.iterdir())
