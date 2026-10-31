"""S4.2b preservation gates: accepted code stays fixed; records grant no authority."""

import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest


ROOT = Path(__file__).resolve().parents[1]
GATES = ROOT / "docs/stage4-engagement-dispatch-ledger-gates.json"
EXAMPLE = ROOT / "examples/secure-agent-engagement-roe.json"


def _gates():
    return json.loads(GATES.read_text())


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _pin(paths):
    manifest = {r["path"]: r for r in _gates()["source_baseline"]["complete_tracked_manifest"]}
    for name in paths:
        path, expected = ROOT / name, manifest[name]
        assert path.is_file() and not path.is_symlink(), name
        raw = path.read_bytes()
        exact_dependency_changes = {'pyproject.toml': ('3989fe11357acb3144ea7c5e0dc87aebe970e325f32e1a9fbbb1f82954574832',
                            b'test = ["pytest>=8"]\n',
                            b'test = ["pytest==9.1.1"]\n'),
         'uv.lock': ('51eb36224d55e0b365af284f76933350082f184f23a12d53b4c4dff3e3a62eb8',
                     b'    { name = "pytest", marker = "extra == \'test\'", specifier = ">=8" },\n',
                     b'    { name = "pytest", marker = "extra == \'test\'", specifier = "==9.1.1" },\n')}
        if name in exact_dependency_changes:
            after_sha256, before, after = exact_dependency_changes[name]
            assert hashlib.sha256(raw).hexdigest() == after_sha256
            assert raw.count(after) == 1 and before not in raw
            restored = raw.replace(after, before)
            assert restored.count(before) == 1 and after not in restored
            assert restored.replace(before, after) == raw
            raw = restored
        assert hashlib.sha256(raw).hexdigest() == expected["sha256"], name
        assert bool(path.stat().st_mode & 0o111) == (expected["mode"] == "100755"), name


def test_preserves_all_accepted_catalog_entries():
    from recon_cockpit.secure_agent import tool_catalog
    from recon_cockpit.secure_agent import configurable_contract
    from recon_cockpit.secure_agent import engagement_dispatch_contract as dispatch
    from recon_cockpit.secure_agent.models import parse_action, parse_policy

    # These digests were recorded from accepted main before ledger implementation.
    catalog = tool_catalog.list_tools()
    descriptions = {row["tool_id"]: tool_catalog.describe_tool(row["tool_id"])
                    for row in catalog["tools"]}
    assert _digest(catalog) == "c34decba40109f2a9f6c22133199bb5d62c4704ada70cda38e4e9060441d610d"
    assert _digest(descriptions) == "257a4c64ff5504096cc29547880f2ade1b37e5e72a0b4a2a36bdd627ee10112d"
    assert catalog["accepted_capability_count"] == len(descriptions) == 55
    assert catalog["candidate_capability_count"] == 0
    assert catalog["external_program_count"] == 17
    assert catalog["read_only"] and not catalog["live_calls_enabled"]
    _pin(["recon_cockpit/secure_agent/tool_catalog.py",
          "recon_cockpit/secure_agent/tool_adapters.py",
          "recon_cockpit/secure_agent/models.py",
          "recon_cockpit/secure_agent/configurable_contract.py"])
    roe = json.loads(EXAMPLE.read_text())
    policy = dispatch.policy_for_roe(roe)
    assert set(policy) == {"schema_version", "policy_version", "allowed_targets", "allowed_ports",
                           "allowed_tools", "allowed_methods", "max_timeout_seconds", "max_output_bytes",
                           "max_targets", "require_approval", "approval_ttl_seconds"}
    assert parse_policy(policy).to_dict() == policy
    for step in (1, 2):
        action = configurable_contract.action(roe["scope"], step)
        assert set(action) == {"schema_version", "action_id", "tool_id", "target", "parameters", "rationale"}
        assert parse_action(action).to_dict() == action


def test_preserves_v1_records_and_cross_version_refusal(tmp_path):
    from recon_cockpit.secure_agent.engagement_contract import EngagementError
    from recon_cockpit.secure_agent.engagement_store import EngagementStore
    from recon_cockpit.secure_agent.engagement_dispatch_contract import DispatchLedgerError
    from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger

    names = [r["path"] for r in _gates()["source_baseline"]["complete_tracked_manifest"]
             if (r["path"].startswith("recon_cockpit/secure_agent/engagement_")
                 or r["path"].startswith("tests/test_secure_engagement_")
                 or r["path"] in {"scripts/engagement_records.py",
                                  "examples/secure-agent-engagement-roe.json"})]
    assert len(names) == 9
    _pin(names)
    tmp_path.chmod(0o700)
    roe = json.loads(EXAMPLE.read_text())
    for creator, opener, error, code, name in (
        (EngagementStore, DispatchLedger, DispatchLedgerError,
         "engagement_dispatch_store_invalid", "v1"),
        (DispatchLedger, EngagementStore, EngagementError, "engagement_store_invalid", "v2"),
    ):
        directory = tmp_path / name
        with creator.create(directory, engagement_id=str(uuid4()), roe=roe, event_id=str(uuid4())):
            pass
        database = directory / "records.sqlite3"
        before = database.read_bytes(), database.stat()
        entries = sorted(p.name for p in directory.iterdir())
        for read_only in (True, False):
            with pytest.raises(error) as caught:
                opener.open(directory, read_only=read_only)
            assert caught.value.code == code
            after = database.stat()
            assert database.read_bytes() == before[0]
            for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns"):
                assert getattr(after, field) == getattr(before[1], field), field
            assert sorted(p.name for p in directory.iterdir()) == entries
        with creator.open(directory, read_only=True) as original:
            assert original.snapshot()["engagement_id"]


def test_preserves_source_and_native_closures():
    gates = _gates()
    baseline = gates["source_baseline"]["complete_tracked_manifest"]
    assert len(baseline) == len({r["path"] for r in baseline}) == 1091
    exceptions = set(gates["change_allowlist"]["existing_status_only"])
    assert len(exceptions) == 8
    fixed = [r["path"] for r in baseline if r["path"] not in exceptions]
    assert len(fixed) == 1083
    _pin(fixed)
    # Historical contracts, runtime declarations, native fixtures and executable
    # closures are all covered by the complete accepted source manifest above.
    for name, expected in gates["source_baseline"]["sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    assert hashlib.sha256(GATES.read_bytes()).hexdigest() == (
        "ea0092a40cfd99ed299b3e51c43316708a58289fe07f9f7c067a1b86b9c6dac8")
    assert hashlib.sha256((ROOT / gates["contract"]).read_bytes()).hexdigest() == (
        "416f82759c29a8669208d6acea01d5b77998ae42cd956c75d6f1da57d939c68e")
    declared = [c["nodeid"] for c in gates["cases"]]
    actual = []
    for name in gates["change_allowlist"]["new_tests"]:
        for node in ast.parse((ROOT / name).read_text()).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                actual.append(name + "::" + node.name)
                assert not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                               and d.func.attr == "parametrize" for d in node.decorator_list)
    assert len(actual) == len(set(actual)) == len(declared) == len(set(declared)) == 80
    assert set(actual) == set(declared)


def test_preserves_roadmap_and_no_authority_boundary(tmp_path):
    gates = _gates()
    assert gates["forecast"]["current"] == {
        "stage4": [6, 7], "professional_v1": [49, 66], "broader_product": [89, 136]}
    for name in ("docs/product-roadmap.md", "docs/roadmap.md", "docs/continue-here.md"):
        text = (ROOT / name).read_text()
        assert "6–7" in text and "49–66" in text and "89–136" in text
        assert "S4.2c" in text and "43869cb" in text
    assert len(gates["parent_mapping"]) == len({r["parent_id"] for r in gates["parent_mapping"]}) == 26
    physical = {r["parent_id"] for r in gates["parent_mapping"] if r["physical_gate_required"]}
    assert physical == set(gates["physical_parent_case_ids"]) and len(physical) == 18
    assert all(r["current_closure"] == "open" for r in gates["parent_mapping"])
    assert all(not c["physical_execution"] and c["status"] == "pending" for c in gates["cases"])
    assert not gates["s42_accepted"] and not gates["stage4_accepted"]
    assert not gates["native_execution_authorized"] and not gates["credential_access_authorized"]

    allowed = {"engagement_contract", "engagement_dispatch_contract", "engagement_dispatch_store",
               "engagement_dispatch_inspection", "configurable_scope", "configurable_contract", "models"}
    forbidden = {"socket", "subprocess", "ctypes", "pickle", "multiprocessing", "http", "ftplib"}
    for name in gates["new_production_paths"]:
        for node in ast.walk(ast.parse((ROOT / name).read_text())):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top in sys.stdlib_module_names and top not in forbidden, (name, alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    assert node.level == 1, (name, module)
                    if module:
                        assert module in allowed, (name, module)
                    else:
                        assert {a.name for a in node.names} <= allowed
                elif module == "recon_cockpit.secure_agent":
                    assert {a.name for a in node.names} <= allowed
                elif module.startswith("recon_cockpit.secure_agent."):
                    assert module.rsplit(".", 1)[-1] in allowed
                else:
                    top = module.split(".")[0]
                    assert top in sys.stdlib_module_names and top not in forbidden, (name, module)
    legacy = tmp_path / "legacy-credentials.json"
    legacy.write_bytes(b'{"secret":"synthetic-preservation-canary"}')
    legacy.chmod(0o600)
    before = legacy.read_bytes(), legacy.stat().st_mtime_ns
    child = '''import os, sys
legacy = os.path.abspath(sys.argv[1])
def audit(event, args):
    if event == "open" and isinstance(args[0], (str, bytes)):
        if os.path.abspath(os.fsdecode(args[0])) == legacy:
            raise RuntimeError("legacy access forbidden")
    if event.startswith(("socket.", "subprocess.", "ctypes.")) or event in {"os.system", "os.fork"}:
        raise RuntimeError("execution forbidden")
sys.addaudithook(audit)
from recon_cockpit.secure_agent import engagement_dispatch_contract as c
from recon_cockpit.secure_agent import engagement_dispatch_inspection, engagement_dispatch_store
assert c.canonical({"record": True}) == b'{"record":true}'
for module in sys.modules:
    if module.startswith("recon_cockpit.secure_agent."):
        assert module.rsplit(".", 1)[-1] in {
            "engagement_contract", "engagement_dispatch_contract", "engagement_dispatch_store",
            "engagement_dispatch_inspection", "configurable_scope", "configurable_contract", "models",
            "tool_adapters", "tool_parameters"}, module
print("data-only imports")
'''
    result = subprocess.run([sys.executable, "-B", "-c", child, str(legacy)], cwd=ROOT,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == b"data-only imports\n" and result.stderr == b""
    assert (legacy.read_bytes(), legacy.stat().st_mtime_ns) == before
