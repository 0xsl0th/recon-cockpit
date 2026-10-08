"""OPTIONS is a separate fixed authority profile despite sharing the curl ELF."""

import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent import network_tools_fixture as fixture
from recon_cockpit.secure_agent import network_tools_contract as contract
from recon_cockpit.secure_agent import network_tools_worker as worker
from recon_cockpit.secure_agent import tool_adapters as adapters
from recon_cockpit.secure_agent.execution import ExecutionControl
from recon_cockpit.secure_agent.isolation import IsolationUnavailable
from recon_cockpit.secure_agent.models import HTTPOptionsParameters, ValidationError, parse_action, parse_policy
from test_secure_network_tools_runtime import envelope, manifest, recommit, verify, policy


def test_all_27_accepted_runtime_invocations_remain_byte_identical():
    selected = {tool: [exe, runtime.FIXED_ARGV[tool], runtime.execution_environment(tool),
        [(source, destination, raw.hex()) for source, destination, raw in runtime.compiled_files(tool)]]
        for tool, exe in runtime.EXECUTABLES.items() if tool not in (runtime.HTTP_OPTIONS, runtime.SNMP_NEXT, runtime.SSH_ALGORITHMS, runtime.TLS_CERTIFICATE, runtime.NUCLEI, runtime.NUCLEI_GIT)}
    assert len(selected) == 27
    # Captured from accepted PR65 main before C12 changes.
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == (
        "6c8d8f25a6d06f373f06f05f55bcf6dc588173246dafc08f2202afbdc2f2325f")


def test_all_36_accepted_adapters_remain_byte_identical():
    selected = {tool: adapter.to_dict() for tool, adapter in adapters.ADAPTERS.items()
                if tool not in (adapters.HTTP_OPTIONS_TOOL_ID, adapters.SNMP_NEXT_TOOL_ID, adapters.SSH_ALGORITHMS_TOOL_ID, adapters.TLS_CERTIFICATE_TOOL_ID, adapters.NUCLEI_TOOL_ID, adapters.NUCLEI_GIT_TOOL_ID)}
    assert len(selected) == 36
    assert hashlib.sha256(runtime.encode(selected)).hexdigest() == (
        "e4883258e64198b32eab6128066ee27f33cc802e03db5dcd3f3b349e00d178a1")


def test_fixed_request_never_uses_advertised_methods_credentials_or_destinations():
    assert runtime.EXECUTABLES[runtime.HTTP_OPTIONS] == "/usr/bin/curl"
    assert runtime.FIXED_ARGV[runtime.HTTP_OPTIONS] == (
        "/tool/curl", "--disable", "--silent", "--show-error", "--ipv4", "--globoff",
        "--http1.1", "--proto", "=http", "--proto-redir", "=http", "--noproxy", "*", "--proxy", "",
        "--connect-timeout", "1", "--max-time", "3", "--max-filesize", "8192", "--retry", "0",
        "--max-redirs", "0", "--include", "--request", "OPTIONS", "--header", "Connection: close",
        "--user-agent", "recon-cockpit-owned-http-options/1", "http://127.0.0.1:8080/harbordesk/portal.html")
    assert not {"--location", "--location-trusted", "-L", "--user", "--netrc", "--netrc-file",
        "--anyauth", "--negotiate", "--ntlm", "--basic", "--digest", "--oauth2-bearer",
        "--cookie", "--cookie-jar", "--data", "--upload-file", "--config", "--url-query",
        "--head", "--fail", "--remote-name", "--resolve", "--connect-to", "--compressed",
        "--retry-all-errors", "--parallel", "--next"} & set(runtime.FIXED_ARGV[runtime.HTTP_OPTIONS])


def test_options_are_typed_immutable_and_require_explicit_options_permission():
    action = parse_action(contract.action("http-options-ok"))
    assert type(action.parameters) is HTTPOptionsParameters
    with pytest.raises(FrozenInstanceError):
        action.parameters.port = 8081
    descriptor = adapters.get_adapter(runtime.HTTP_OPTIONS).to_dict()
    assert descriptor["parameters"]["required"] == ["port", "timeout_seconds", "max_output_bytes"]
    assert descriptor["parameters"]["additionalProperties"] is False
    assert descriptor["parser_version"] == "curl-http-options-v1"
    configured = policy().to_dict()
    configured.update(allowed_tools=[runtime.HTTP_OPTIONS], allowed_methods=["OPTIONS"])
    assert parse_policy(configured).evaluate(action).decision == "approval_required"
    for methods in ([], ["GET"], ["HEAD"], ["GET", "HEAD"]):
        configured["allowed_methods"] = methods
        assert parse_policy(configured).evaluate(action).reasons == ("method_not_allowed",)


@pytest.mark.parametrize("tool_id", ["http_probe", "http_headers_v1", "curl_https_get_v1",
                                  "configurable_http_headers_v1"])
def test_options_policy_permission_does_not_expand_legacy_http_action_syntax(tool_id):
    action = contract.action("http-options-ok")
    action.update(tool_id=tool_id)
    action["parameters"].update(method="OPTIONS", path="/harbordesk/portal.html")
    with pytest.raises(ValidationError, match="unsupported_http_method"):
        parse_action(action)


@pytest.mark.parametrize("field", ["method", "path", "url", "headers", "body", "data", "user_agent",
    "argv", "executable", "environment", "username", "password", "cookies", "proxy", "redirects",
    "followup", "allow", "auth_scheme", "token", "netrc", "upload"])
def test_caller_cannot_add_http_operation_or_credential_parameters(field):
    action = contract.action("http-options-ok")
    action["parameters"][field] = "untrusted"
    with pytest.raises(ValidationError, match="unknown_parameters_fields"):
        parse_action(action)


@pytest.mark.parametrize("field,value", [("port", True), ("timeout_seconds", 0),
    ("max_output_bytes", False), ("port", 65536), ("timeout_seconds", 31), ("max_output_bytes", 65537)])
def test_parameter_types_and_bounds_are_closed(field, value):
    action = contract.action("http-options-ok")
    action["parameters"][field] = value
    with pytest.raises(ValidationError):
        parse_action(action)


def test_options_does_not_inherit_host_proxy_configuration_or_credentials(monkeypatch):
    for name in ("HOME", "CURL_HOME", "XDG_CONFIG_HOME", "http_proxy", "https_proxy", "ALL_PROXY",
                 "NO_PROXY", "NETRC", "CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSLKEYLOGFILE", "LD_PRELOAD"):
        monkeypatch.setenv(name, "/private/canary")
    assert runtime.execution_environment(runtime.HTTP_OPTIONS) == {
        "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "MALLOC_ARENA_MAX": "1"}
    assert runtime.compiled_files(runtime.HTTP_OPTIONS) == ()
    permissions = worker._landlock_permissions(manifest(runtime.HTTP_OPTIONS))
    assert permissions == worker._landlock_permissions(manifest(runtime.DOCKER_PING))
    assert permissions["/tool/curl"] == 5
    assert not {"/etc/resolv.conf", "/etc/hosts", "/root", "/home", "/tool/data", "/usr/bin/python3"} & permissions.keys()


@pytest.mark.parametrize("path", ["/etc/hosts", "/etc/resolv.conf", "/root/.curlrc", "/root/.netrc",
    "/home/user/.config/curlrc", "/tool/data/cookies", "/tool/data/credentials", "/tmp/body", "/bin/sh"])
def test_runtime_closure_rejects_proxy_authentication_or_request_files(path):
    value = manifest(runtime.HTTP_OPTIONS)
    value["files"].append({"source": path, "destination": path, "size": 4, "sha256": "a" * 64})
    value["files"].sort(key=lambda row: row["destination"])
    with pytest.raises(ValueError):
        runtime.validate_manifest(value)


def test_existing_curl_files_do_not_make_profile_commitments_interchangeable():
    old, new = manifest(runtime.DOCKER_PING), manifest(runtime.HTTP_OPTIONS)
    assert new == {**old, "tool_id": runtime.HTTP_OPTIONS}
    assert runtime.manifest_digest(new) != runtime.manifest_digest(old)
    assert runtime.runtime_source_mounts(new) == runtime.runtime_source_mounts(old)


@pytest.mark.parametrize("other_case", ["docker-ping-ok", "docker-version-ok", "winrm-ok", "ftp-ok", "smtp-ok"])
@pytest.mark.parametrize("reverse", [False, True])
def test_same_curl_elf_cannot_substitute_another_profile_authority(other_case, reverse):
    cases = (other_case, "http-options-ok") if reverse else ("http-options-ok", other_case)
    value, other = (envelope(case) for case in cases)
    assert value["runtime"]["files"] == other["runtime"]["files"]
    value["runtime"] = deepcopy(other["runtime"])
    with pytest.raises(ValueError):
        verify(value)
    value["launch"]["action"] = other["launch"]["action"]
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("methods", [[], ["GET"], ["HEAD"]])
def test_recommitted_policy_cannot_drop_explicit_options_permission(methods):
    value = envelope("http-options-ok")
    value["launch"]["policy"]["allowed_methods"] = methods
    recommit(value)
    with pytest.raises(ValueError):
        verify(value)


@pytest.mark.parametrize("case", fixture.HTTP_OPTIONS_CASES)
@pytest.mark.parametrize("fault", ["mode", "inner_mode", "identity", "manifest", "namespace",
    "deadline", "sequence", "reservation", "policy", "action", "limit"])
def test_fresh_commitments_cannot_expand_options_authority(case, fault):
    from test_secure_network_tools_runtime import test_fresh_commitments_do_not_bypass_fixed_authority
    test_fresh_commitments_do_not_bypass_fixed_authority(case, fault)


@pytest.mark.parametrize("code,reason,expected", [(0, None, "succeeded"), (22, None, "failed"),
    (-15, "timeout", "timeout"), (-15, "output_limit", "output_limit")])
def test_capture_preserves_headers_body_and_diagnostics_without_promoting_failures(monkeypatch, code, reason, expected):
    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform="linux"))
    launch = envelope("http-options-ok")
    selected = launch.pop("runtime")
    monkeypatch.setattr(runtime, "_snapshot", lambda *_: [])
    monkeypatch.setattr(runtime, "_command", lambda *_: ["fixed-worker"])
    stdout, stderr = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\n\r\nbody", b"diagnostic"
    def capture(argv, raw, timeout, maximum, **kwargs):
        assert argv == ["fixed-worker"] and 0 < timeout <= 5
        prefix = runtime.READY_PREFIX + hashlib.sha256(raw).hexdigest().encode() + b"\n"
        assert maximum == 8192 + len(prefix)
        return code, stdout, prefix + stderr, reason
    monkeypatch.setattr(runtime, "_capture_bounded", capture)
    lab = SimpleNamespace(_namespace_fds=(10, 11), _check=lambda *_: None, _verify_pins=lambda: None)
    result = runtime.run_network_tool_owned(lab=lab, launch=launch,
        control=ExecutionControl(time.monotonic() + 20), manifest=selected,
        closure={"stdlib": "/usr/lib/python3.13", "files": [], "network_tools_runtime": selected})
    assert result["status"] == expected and result["tool_observation"] is None
    assert result["truncated"] is (reason == "output_limit")
    assert base64.b64decode(result["raw_output_base64"]) == stdout
    assert base64.b64decode(result["raw_stderr_base64"]) == stderr
    assert result["provenance"]["runtime_manifest"]["tool_id"] == runtime.HTTP_OPTIONS
    assert result["provenance"]["parser_version"] == "curl-http-options-v1"
    assert result["provenance"]["exit_code"] == code and result["provenance"]["stop_reason"] == reason


def test_options_keeps_single_task_filter_and_strict_inherited_resource_caps(monkeypatch):
    calls, limits = [], {}
    monkeypatch.setattr(worker.common, "syscall_filter", lambda **kw: calls.append(kw))
    worker.syscall_filter(runtime.HTTP_OPTIONS)
    assert calls == [{"allow_threads": False}]
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (worker.resource.RLIM_INFINITY,) * 2)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    worker._limits(runtime.HTTP_OPTIONS)
    assert limits[worker.resource.RLIMIT_NPROC] == (1, 1)
    assert limits[worker.resource.RLIMIT_NOFILE] == (64, 64)
    assert limits[worker.resource.RLIMIT_AS] == (256 * 1024 * 1024,) * 2
    assert limits[worker.resource.RLIMIT_FSIZE] == (0, 0)
    monkeypatch.setattr(worker.resource, "getrlimit", lambda kind: (2, 2))
    worker._limits(runtime.HTTP_OPTIONS)
    assert set(limits.values()) == {(0, 0), (1, 1), (2, 2)}


def test_pinned_runtime_inspection_only_probes_existing_curl_elf(monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"\x7fELFcurl")
    monkeypatch.setattr(runtime, "read_runtime_file", lambda path, tool_id: b"\x7fELFbytes")
    monkeypatch.setattr(runtime, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(Path, "resolve", lambda self, strict: self)
    def probe(argv, *args):
        calls.append(argv)
        return b"libc.so.6 => /usr/lib/libc.so.6 (0x1)\n/usr/lib/ld-linux.so.2 (0x2)\n"
    monkeypatch.setattr(runtime, "_runtime_probe", probe)
    value = runtime.inspect_tool_runtime(runtime.HTTP_OPTIONS, SimpleNamespace(check=lambda: None))
    assert calls == [["/usr/bin/ldd", "/usr/bin/curl"]]
    assert {row["source"] for row in value["files"]} == {
        "/usr/bin/curl", "/usr/lib/libc.so.6", "/usr/lib/ld-linux.so.2"}


def test_shell_wrapper_is_rejected_before_any_probe(monkeypatch):
    monkeypatch.setattr(runtime, "_read_regular", lambda path: b"#!/bin/sh\nexec other")
    monkeypatch.setattr(runtime, "_runtime_probe", lambda *args: pytest.fail("wrapper probed"))
    with pytest.raises(IsolationUnavailable, match="ELF"):
        runtime.inspect_tool_runtime(runtime.HTTP_OPTIONS, SimpleNamespace(check=lambda: None))
