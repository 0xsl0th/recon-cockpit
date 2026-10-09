"""T03 keeps the accepted collector bytes while separating policy authority."""

from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_ssh_algorithms_runtime as legacy
from recon_cockpit.secure_agent import network_tools_ssh_policy_runtime as policy


def manifest():
    compiled = {source: raw for source, _, raw in legacy.COMPILED}
    return {"version": "1", "profile": policy.PROFILE, "tool_id": policy.TOOL_ID,
        "executable": legacy.DESTINATION, "interpreter": legacy.INTERPRETER,
        "files": sorted([{"source": source, "destination": destination,
            "size": len(compiled.get(source, b"data")),
            "sha256": hashlib.sha256(compiled.get(source, b"data")).hexdigest()}
            for source, destination in policy.fixed_entries()], key=lambda row: row["destination"])}


def test_policy_uses_exact_accepted_collector_without_extra_runtime_data():
    candidate = manifest()
    before = deepcopy(candidate)
    assert runtime.validate_manifest(candidate, tool_id=policy.TOOL_ID) == candidate == before
    assert runtime.runtime_files(candidate) == candidate["files"]
    assert runtime.compiled_files(policy.TOOL_ID) == legacy.COMPILED
    assert runtime.FIXED_ARGV[policy.TOOL_ID] == runtime.FIXED_ARGV[legacy.TOOL_ID]
    assert runtime.execution_environment(policy.TOOL_ID) == runtime.execution_environment(legacy.TOOL_ID)
    assert policy.fixed_entries() == legacy.fixed_entries()
    assert not any("policy" in row["destination"] for row in candidate["files"])


def test_client_closure_excludes_both_owned_peer_implementations(monkeypatch):
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = runtime._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        manifest(), list(range(20, 33)), "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == 13
    assert "CAP_NET_ADMIN" not in argv and "--unshare-net" not in argv
    assert not any("network_tools_ssh_algorithms_fixture" in item
        or "network_tools_ssh_policy_fixture" in item for item in argv)


@pytest.mark.parametrize("identity", [legacy.TOOL_ID, "ssh_host_keys_v1", "ssh-audit", "", True])
def test_new_profile_cannot_be_validated_as_accepted_collection_authority(identity):
    with pytest.raises(ValueError):
        runtime.validate_manifest(manifest(), tool_id=identity)


@pytest.mark.parametrize("change", [
    lambda r: r.update(profile=legacy.PROFILE),
    lambda r: r.update(tool_id=legacy.TOOL_ID),
    lambda r: r.update(executable="/usr/bin/ssh-audit"),
    lambda r: r.update(policy_path="/tmp/untrusted-policy"),
    lambda r: r["files"].pop(),
    lambda r: r["files"].reverse(),
    lambda r: next(row for row in r["files"] if row["source"].startswith("compiled:")).update(sha256="f" * 64),
    lambda r: r["files"][0].update(size=True),
    lambda r: r["files"][0].update(source="/tmp/replacement.rb"),
])
def test_rehashed_runtime_cannot_replace_the_collector_or_policy(change):
    candidate = manifest()
    change(candidate)
    with pytest.raises(ValueError):
        runtime.validate_manifest(candidate, tool_id=policy.TOOL_ID)
