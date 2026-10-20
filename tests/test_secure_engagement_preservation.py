"""Additive import and source-inventory checks; no native closure execution."""

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "engagement_records.py"
GATES = ROOT / "docs" / "stage4-engagement-records-gates.json"
EXAMPLE = ROOT / "examples" / "secure-agent-engagement-roe.json"


def _id(number):
    return str(uuid.UUID(int=number, version=4))


def test_additive_import_boundary():
    gates = json.loads(GATES.read_text())
    local = {"engagement_contract", "engagement_store", "engagement_inspection", "configurable_scope"}
    for name in gates["implementation_allowlist"]["new_modules"] + gates["implementation_allowlist"]["new_scripts"]:
        tree = ast.parse((ROOT / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] in sys.stdlib_module_names, (name, alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    assert node.level == 1 and module in local, (name, module)
                elif module == "recon_cockpit.secure_agent":
                    assert {a.name for a in node.names} <= local
                elif module.startswith("recon_cockpit.secure_agent."):
                    assert module.rsplit(".", 1)[-1] in local
                else:
                    assert module.split(".")[0] in sys.stdlib_module_names, (name, module)
    # The only reused production validator has not been widened for this slice.
    assert hashlib.sha256((ROOT / "recon_cockpit/secure_agent/configurable_scope.py").read_bytes()).hexdigest() == (
        "d990c6614a561fbf1240d640636983773a0b46a984d0188b8ad00e3a498f4bbd")
    child = '''import sys
from recon_cockpit.secure_agent import engagement_contract, engagement_inspection, engagement_store
for name in sys.modules:
    if name.startswith("recon_cockpit.secure_agent."):
        assert name.rsplit(".", 1)[-1] in {"engagement_contract", "engagement_inspection", "engagement_store", "configurable_scope"}, name
print("additive")
'''
    result = subprocess.run([sys.executable, "-B", "-c", child], cwd=ROOT,
                            capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stdout == b"additive\n" and result.stderr == b""


def test_legacy_credentials_not_read(tmp_path):
    from recon_cockpit.secure_agent.engagement_store import EngagementStore
    from recon_cockpit.secure_agent.engagement_inspection import write_export
    legacy = tmp_path / "legacy-case.json"
    sentinel = b'{"credentials":[{"secret":"synthetic-legacy-sentinel-not-an-input"}]}'
    legacy.write_bytes(sentinel)
    legacy.chmod(0o600)
    with EngagementStore.create(tmp_path / "store", engagement_id=_id(1),
                                roe=json.loads(EXAMPLE.read_text()), event_id=_id(2)) as store:
        export = tmp_path / "export.json"
        expected = write_export(export, store.snapshot())
    before = legacy.read_bytes(), legacy.stat().st_mode, legacy.stat().st_mtime_ns
    child = '''import os, runpy, sys
legacy = os.path.abspath(sys.argv[3])
def audit(event, args):
    if event == "open" and isinstance(args[0], (str, bytes)):
        if os.path.abspath(os.fsdecode(args[0])) == legacy:
            raise RuntimeError("legacy file access forbidden")
    if event.startswith(("socket.", "subprocess.")):
        raise RuntimeError("execution forbidden")
sys.addaudithook(audit)
sys.argv = [sys.argv[1], "inspect", "--export", sys.argv[2]]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
    result = subprocess.run([sys.executable, "-B", "-c", child, str(CLI), str(export), str(legacy)],
                            cwd=tmp_path, capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stderr == b"" and json.loads(result.stdout) == expected
    assert (legacy.read_bytes(), legacy.stat().st_mode, legacy.stat().st_mtime_ns) == before


def test_documented_example_is_valid():
    from recon_cockpit.secure_agent.engagement_contract import validate_roe
    value = json.loads(EXAMPLE.read_text())
    assert validate_roe(value) == value and value["mode"] == "disconnected_owned"
    spec = importlib.util.spec_from_file_location("engagement_documented_cli", CLI)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    gates = json.loads(GATES.read_text())
    values = {"--store": "/not-opened/store", "--roe-file": "/not-opened/roe",
              "--output": "/not-opened/output", "--export": "/not-opened/export",
              "--engagement-id": _id(1), "--event-id": _id(2),
              "--expected-revision": "1", "--expected-generation": "0"}
    for command, flags in gates["api"]["cli_flags"].items():
        argv = [command]
        for flag in flags:
            argv.extend((flag, values[flag]))
        args = vars(cli._arguments(argv))
        assert args["command"] == command
        assert set(args) == {"command", *(f[2:].replace("-", "_") for f in flags)}
        for flag in flags:
            expected = int(values[flag]) if flag.startswith("--expected-") else values[flag]
            assert args[flag[2:].replace("-", "_")] == expected


def test_case_inventory_exact_mapping():
    gates = json.loads(GATES.read_text())
    cases = gates["cases"]
    declared = [row["node_id"] for row in cases]
    actual = []
    for name in gates["implementation_allowlist"]["new_tests"]:
        tree = ast.parse((ROOT / name).read_text())
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                actual.append(name + "::" + node.name)
                # These exact inventory nodes are not parameterized into unnamed variants.
                assert not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                               and d.func.attr == "parametrize" for d in node.decorator_list)
    assert len(declared) == len(set(declared)) == len(actual) == len(set(actual)) == 68
    assert set(actual) == set(declared)
    assert all(row["status"] == "pending" and row["execution"] == "portable_offline_only" for row in cases)
    assert set(gates["coverage_claims"]["direct_offline"]) == {"S4-E01", "S4-E02"}
    assert set(gates["coverage_claims"]["partial_preparation_only"]) == {
        "S4-E06", "S4-R04", "S4-D05", "S4-D06", "S4-V01", "S4-P01"}
    assert not gates["stage4_acceptance"] and not gates["authorization"]["execution_authority"]
    assert not gates["implementation_allowlist"]["shared_code_or_native_closure_changes"]
