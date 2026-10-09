"""Portable isolation and compatibility checks; no native tool is invoked."""

from copy import deepcopy
import hashlib
import io
import json
import re
import stat
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import launcher_protocol
from recon_cockpit.secure_agent.launcher_isolation import NETWORK_TOOLS_MODULES
from recon_cockpit.secure_agent import network_tools_nuclei_git_runtime as git
from recon_cockpit.secure_agent import network_tools_nuclei_runtime as directory
from recon_cockpit.secure_agent import network_tools_nuclei_worker as worker
from recon_cockpit.secure_agent import network_tools_runtime as shared


def test_c16_manifest_compiled_bytes_argv_and_environment_keep_independent_snapshot():
    # Recorded from main 1cfbf8b before this profile was introduced.
    value = {"manifest": directory.manifest(),
        "compiled": [(source, destination, raw.hex()) for source, destination, raw in directory.COMPILED],
        "argv": directory.FIXED_ARGV, "environment": directory.ENVIRONMENT}
    assert hashlib.sha256(shared.encode(value)).hexdigest() == (
        "47f21bc4020e22d8e65fb866132ec946e2a38c51ec24c467b66cf94e379ee370")
    assert shared.manifest_digest(directory.manifest()) == (
        "8421b4ea42054f15d8e88794c4733e5e9c02f4607e9944454c0cff04d9b7a5c6")


def test_git_profile_is_distinct_but_retains_all_sealed_runtime_and_resource_bounds():
    value = git.manifest()
    assert shared.validate_manifest(value, tool_id=shared.NUCLEI_GIT) == value
    assert value["profile"] == "network-tools-nuclei-git-static-runtime-v1"
    assert value["tool_id"] == "nuclei_git_head_v1"
    assert len(value["files"]) == 8 and "interpreter" not in value
    assert git.COMPILED[1:] == directory.COMPILED[1:]
    assert shared.compiled_files(shared.NUCLEI_GIT) == git.COMPILED
    for name in ("BOUNDARY_FIELDS", "CHUNK_BYTES", "CONFIG_SEEDS", "DESTINATION", "EXECUTABLE",
            "EXECUTABLE_SHA256", "EXECUTABLE_SIZE", "MAX_FILE_BYTES", "MAX_MANIFEST_BYTES",
            "MAX_RUNTIME_BYTES", "MAX_WRITE_BYTES", "SCRATCH", "SCRATCH_BYTES", "SCRATCH_INODES"):
        assert getattr(git, name) == getattr(directory, name)
    assert shared.MAX_FILE_BYTES == 16 * 1024 * 1024
    assert shared.MAX_RUNTIME_BYTES == 64 * 1024 * 1024
    assert shared.MAX_OUTPUT_BYTES == 8192
    assert shared.manifest_digest(value) != shared.manifest_digest(directory.manifest())


def test_git_command_changes_only_the_fixed_template_and_fixed_request_url(monkeypatch):
    for name in ("NUCLEI_CONFIG_DIR", "NUCLEI_TEMPLATES_DIR", "HTTP_PROXY", "HTTPS_PROXY",
            "HOME", "AWS_ACCESS_KEY_ID", "GITHUB_TOKEN", "LD_PRELOAD"):
        monkeypatch.setenv(name, "caller-controlled")
    assert shared.FIXED_ARGV[shared.NUCLEI_GIT] == git.FIXED_ARGV
    differences = [(old, new) for old, new in zip(directory.FIXED_ARGV, git.FIXED_ARGV) if old != new]
    assert differences == [("/tool/data/directory-listing.yaml", "/tool/data/git-head.yaml"),
        ("http://127.0.0.1:8080/public/", "http://127.0.0.1:8080/.git/HEAD")]
    assert len(directory.FIXED_ARGV) == len(git.FIXED_ARGV)
    environment = shared.execution_environment(shared.NUCLEI_GIT)
    assert environment == git.ENVIRONMENT == directory.ENVIRONMENT
    environment["HOME"] = "mutated"
    assert git.ENVIRONMENT["HOME"] == "/scratch/home"
    assert b'path: ["http://127.0.0.1:8080/.git/HEAD"]' in git.TEMPLATE
    assert git.TEMPLATE.count(b"method: GET") == 1
    assert git.TEMPLATE.count(b"path:") == 1
    assert b"redirects: false" in git.TEMPLATE
    assert b"name: git-head-signature" in git.TEMPLATE
    predicate = git.TEMPLATE.split(b"dsl:\n", 1)[1].strip()
    assert predicate.startswith(b'- \'status_code == 200 && content_type == "text/plain; charset=us-ascii" && (')
    assert predicate.endswith(b")'")
    assert predicate.count(b" || ") == 1
    assert [bytes.fromhex(value.decode()) for value in re.findall(br'hex_encode\(body\) == "([a-f0-9]+)"', predicate)] == [
        b"ref: refs/heads/main\n", b"ref: refs/heads/release\n"]


@pytest.mark.parametrize("fault", ["profile", "tool_id", "c16_template", "source", "destination",
    "template_hash", "template_size", "bool_size", "binary_hash", "extra", "missing", "reorder", "interpreter"])
def test_git_manifest_refuses_substitutions_even_with_fresh_commitments(fault):
    value = git.manifest()
    template = next(row for row in value["files"] if row["destination"] == git.TEMPLATE_PATH)
    if fault == "profile": value["profile"] = directory.PROFILE
    elif fault == "tool_id": value["tool_id"] = directory.TOOL_ID
    elif fault == "c16_template":
        template.update(next(row for row in directory.manifest()["files"] if row["destination"] == directory.TEMPLATE_PATH))
        value["files"].sort(key=lambda row: row["destination"])
    elif fault == "source": template["source"] = "/tmp/caller.yaml"
    elif fault == "destination": template["destination"] = "/tool/data/other.yaml"
    elif fault == "template_hash": template["sha256"] = "a" * 64
    elif fault == "template_size": template["size"] += 1
    elif fault == "bool_size": template["size"] = True
    elif fault == "binary_hash":
        next(row for row in value["files"] if row["destination"] == git.DESTINATION)["sha256"] = "a" * 64
    elif fault == "extra": value["files"].append(deepcopy(template))
    elif fault == "missing": value["files"].remove(template)
    elif fault == "reorder": value["files"].reverse()
    else: value["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
    assert hashlib.sha256(shared.encode(value)).hexdigest() != shared.manifest_digest(git.manifest())
    with pytest.raises(ValueError):
        shared.validate_manifest(value, tool_id=git.TOOL_ID)
    with pytest.raises(ValueError):
        git.validate_manifest(value)


@pytest.mark.parametrize("profile,other", [(git, directory), (directory, git)])
def test_cross_profile_manifest_rejected_before_any_staging_or_mount_read(profile, other, monkeypatch):
    value = other.manifest()
    with pytest.raises(ValueError):
        profile.validate_manifest(value)
    with pytest.raises(ValueError):
        shared.validate_manifest(value, tool_id=profile.TOOL_ID)
    with pytest.raises(ValueError):
        profile.snapshot(value, None)
    with pytest.raises(ValueError):
        profile.verify_mounted(value, None)
    with pytest.raises(ValueError):
        profile.command(None, None, value, None, "nonce", "commitment")


@pytest.mark.parametrize("tool_id", [None, True, 1, [], {}, "nuclei", "/tmp/caller.yaml", shared.OPENSSL])
def test_only_two_exact_tool_ids_select_the_static_runtime(tool_id):
    with pytest.raises(ValueError, match="unsupported_nuclei_profile"):
        directory.for_tool(tool_id)


def test_git_static_launcher_uses_same_bounded_tag_and_forbids_service_web(monkeypatch):
    value = git.manifest()
    closure = {"network_tools_runtime": value}
    assert launcher_protocol.runtime_tag({"profile": "owned_network_tools_lab"}, closure) == (
        "nuclei-tools-launch-preconditions")
    with pytest.raises(ValueError, match="nuclei_service_web_profile_forbidden"):
        shared._command(None, None, value, None, "nonce", "commitment", service_web=True)
    monkeypatch.setattr(directory, "_trusted_program", lambda name: "/usr/bin/" + name)
    argv = shared._command(SimpleNamespace(_namespace_fds=(10, 11)),
        ("/usr/lib/python3.13", [("/usr/bin/python3", "/usr/bin/python3")]),
        value, list(range(20, 28)), "a" * 64, "b" * 64)
    assert argv.count("--ro-bind-data") == len(value["files"])
    assert "CAP_SYS_ADMIN" in argv and "CAP_SETPCAP" in argv
    assert "/app/recon_cockpit/secure_agent/network_tools_nuclei_worker.py" in argv
    assert "/app/recon_cockpit/secure_agent/network_tools_nuclei_git_runtime.py" in argv
    assert directory.TEMPLATE_PATH not in argv and git.TEMPLATE_PATH in argv
    permissions = worker.landlock_permissions(value)
    assert git.TEMPLATE_PATH in permissions and directory.TEMPLATE_PATH not in permissions
    assert [path for path, rights in permissions.items() if rights & 1] == [git.DESTINATION]


def test_git_modules_are_available_to_the_outer_and_nested_sealed_launchers():
    # Identity validation occurs in the outer launcher before the nested worker
    # can start. A missing outer fixture mount otherwise hides as a refusal.
    required = {"network_tools_nuclei_git_runtime", "network_tools_nuclei_git_fixture"}
    assert required | {"network_tools_nuclei_git_parser"} <= set(NETWORK_TOOLS_MODULES)
    assert required <= set(shared.MODULES)


@pytest.mark.parametrize("selected,committed", [(git, git), (directory, directory), (git, directory), (directory, git)])
def test_worker_binds_authority_tool_to_its_exact_manifest_before_readiness(monkeypatch, selected, committed):
    value = committed.manifest()
    events = []
    monkeypatch.setattr(worker.sys, "argv", ["worker", "a" * 64, "b" * 64])
    monkeypatch.setattr(worker.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps({"runtime": value}).encode())))
    monkeypatch.setattr(worker.os, "fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO))
    monkeypatch.setattr(worker, "consume_launch", lambda *_: ({"tool_id": selected.TOOL_ID,
        "host_namespaces": {}}, time.monotonic() + 20, {}, shared.manifest_digest(value)))
    monkeypatch.setattr(worker, "assert_lab_namespaces", lambda *_: None)
    def verify(manifest, control):
        selected.validate_manifest(manifest)
        events.append("verified")
    monkeypatch.setattr(selected, "verify_mounted", verify)
    for module, name in [(worker, "mount_scratch"), (worker, "scratch_allocation_witness"),
            (worker, "seed_scratch"), (worker, "_limits"), (worker.worker, "drop_privileges"),
            (worker.common, "syscall_filter"), (worker.common, "_witnesses"),
            (worker.common, "_thread_bound_witness"), (worker.shared_worker, "_metadata_transport_witness"),
            (worker, "close_authority_descriptors"), (worker.common, "apply_landlock"),
            (worker, "scratch_execution_and_file_witness")]:
        monkeypatch.setattr(module, name, lambda *_args, _name=name, **_kwargs: events.append(_name))
    monkeypatch.setattr(worker.os, "write", lambda *_: events.append("ready"))
    class ExecReached(BaseException): pass
    def execute(path, argv, environment):
        assert (path, argv, environment) == (selected.DESTINATION, selected.FIXED_ARGV, selected.ENVIRONMENT)
        events.append("exec")
        raise ExecReached
    monkeypatch.setattr(worker.os, "execve", execute)
    if selected is committed:
        with pytest.raises(ExecReached):
            worker.main()
        assert events[0] == "verified"
        assert events[-3:] == ["scratch_execution_and_file_witness", "ready", "exec"]
    else:
        assert worker.main() == 78
        assert events == []
    assert worker.runtime is directory  # No process-global profile mutation.
