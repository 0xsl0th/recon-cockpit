"""Static staging limits are selected only by the exact Nuclei bootstrap tag."""

from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4

import pytest

from recon_cockpit.secure_agent import launcher_isolation as isolation
from recon_cockpit.secure_agent import launcher_protocol as protocol
from recon_cockpit.secure_agent import launcher_worker as worker
from recon_cockpit.secure_agent import network_tools_nuclei_runtime as nuclei
from recon_cockpit.secure_agent import network_tools_runtime as runtime
from recon_cockpit.secure_agent.network_tools_lab_contract import identity
from test_secure_network_tools_runtime import configuration, manifest


TAG = "nuclei-tools-launch-preconditions"


@pytest.mark.parametrize("tool_id", tuple(runtime.EXECUTABLES))
def test_nuclei_static_staging_tag_does_not_change_existing_tool_tags(tool_id):
    value = nuclei.manifest() if tool_id == runtime.NUCLEI else manifest(tool_id)
    config = {"profile": "owned_network_tools_lab"}
    closure = {"network_tools_runtime": value}
    expected = (TAG if tool_id == runtime.NUCLEI else
        "whatweb-tools-launch-preconditions" if tool_id == runtime.WHATWEB else
        "kerberos-tools-launch-preconditions" if tool_id == runtime.KERBRUTE else
        "smb-tools-launch-preconditions" if tool_id == runtime.SMB else "network-tools-launch-preconditions")
    assert protocol.runtime_tag(config, closure) == expected
    protocol.validate_runtime_tag(expected, config, closure)
    for tag in {*protocol.RUNTIME_TAGS.values(), TAG, "smb-tools-launch-preconditions",
                "kerberos-tools-launch-preconditions", "whatweb-tools-launch-preconditions", None} - {expected}:
        with pytest.raises(ValueError, match="runtime_profile_changed"):
            protocol.validate_runtime_tag(tag, config, closure)


@pytest.mark.parametrize("profile", tuple(protocol.PROFILES))
def test_nuclei_tag_is_scoped_to_network_tools_owned_profile(profile):
    config = {"profile": profile}
    closure = {"network_tools_runtime": nuclei.manifest()}
    if profile == "owned_network_tools_lab":
        protocol.validate_runtime_tag(TAG, config, closure)
    else:
        with pytest.raises(ValueError, match="runtime_profile_changed"):
            protocol.validate_runtime_tag(TAG, config, closure)


@pytest.mark.parametrize("fault", ["profile", "interpreter", "binary", "template", "extra"])
def test_tag_requires_exact_pinned_static_manifest(fault):
    value = nuclei.manifest()
    if fault == "profile": value["profile"] = runtime.PROFILE
    elif fault == "interpreter": value["interpreter"] = "/lib64/ld-linux-x86-64.so.2"
    elif fault == "binary":
        next(row for row in value["files"] if row["destination"] == nuclei.DESTINATION)["sha256"] = "a" * 64
    elif fault == "template":
        next(row for row in value["files"] if row["destination"] == nuclei.TEMPLATE_PATH)["sha256"] = "a" * 64
    else: value["files"].append(deepcopy(value["files"][0]))
    with pytest.raises(ValueError):
        protocol.runtime_tag({"profile": "owned_network_tools_lab"}, {"network_tools_runtime": value})


@pytest.mark.parametrize("case", ["dig-ok", "smb-ok", "openssl-ok", "kerberos-ok", "tls-cert-valid"])
def test_static_manifest_cannot_increase_limits_for_other_fixed_cases(case):
    # Validate the case-to-manifest binding before any admission or execution.
    if case == "tls-cert-valid":
        from recon_cockpit.secure_agent.network_tools_fixture import TLS_CERTIFICATE_CASES
        case = TLS_CERTIFICATE_CASES[0]
    config = {**configuration(case), "owned_lab": identity(case, str(uuid4()))}
    closure = {"stdlib": "/usr/lib/python3.11", "files": ["/usr/bin/python3", "/usr/sbin/nft",
        "/usr/bin/bwrap", "/usr/bin/nsenter"], "network_tools_runtime": nuclei.manifest()}
    with pytest.raises(ValueError, match="launcher_network_tool_runtime_changed"):
        protocol.initial({"configuration": config, "runtime": closure, "deadline": 130}, 100)


@pytest.mark.parametrize("kwargs,megabytes,staging,descriptors", [
    ({}, 256, 1, 128), ({"network_tools_runtime": True}, 256, 16, 128),
    ({"nmap_runtime": True}, 256, 16, 128), ({"smb_runtime": True}, 256, 40, 256),
    ({"web_tools_runtime": True}, 2048, 16, 128), ({"kerberos_runtime": True}, 2048, 16, 128),
    ({"service_web_runtime": True}, 2048, 16, 128), ({"configurable_runtime": True}, 256, 16, 128),
    ({"whatweb_runtime": True}, 256, 16, 256), ({"nuclei_runtime": True}, 2048, 160, 128)])
def test_nuclei_static_staging_caps_preserve_prior_launcher_limits(monkeypatch, kwargs, megabytes, staging, descriptors):
    limits = {}
    monkeypatch.setattr(worker, "ENTRY_DESCRIPTORS_VERIFIED", True)
    monkeypatch.setattr(worker.sys, "platform", "linux")
    monkeypatch.setattr(worker.os, "getuid", lambda: 1000)
    monkeypatch.setattr(worker.os, "getgid", lambda: 1000)
    monkeypatch.setattr(worker.os, "readlink", lambda _: "private")
    monkeypatch.setattr(worker.Path, "read_text", lambda self: "1000 1000 1\n")
    monkeypatch.setattr(worker.socket, "if_nameindex", lambda: [(1, "lo")])
    for name in ("_zero_capabilities", "_no_new_privileges", "_root_read_only"):
        monkeypatch.setattr(worker.bootstrap, name, lambda: None)
    monkeypatch.setattr(worker.resource, "setrlimit", lambda kind, value: limits.update({kind: value}))
    assert worker.boundary({"net": "host"}, **kwargs) == dict.fromkeys(protocol.CHECKS, True)
    assert limits == {worker.resource.RLIMIT_AS: (megabytes * 1048576,) * 2,
        worker.resource.RLIMIT_CPU: (30, 30), worker.resource.RLIMIT_NOFILE: (descriptors,) * 2,
        worker.resource.RLIMIT_CORE: (0, 0), worker.resource.RLIMIT_FSIZE: (staging * 1048576,) * 2,
        worker.resource.RLIMIT_NPROC: (64, 64)}


@pytest.mark.parametrize("tag,kwargs", [(None, {}), ("launch-witness", {}), ("launch-preconditions", {}),
    ("nmap-launch-preconditions", {"nmap_runtime": True}), ("web-launch-preconditions", {"nmap_runtime": True}),
    ("http-headers-launch-preconditions", {"nmap_runtime": True}),
    ("web-tools-launch-preconditions", {"web_tools_runtime": True}),
    ("network-tools-launch-preconditions", {"network_tools_runtime": True}),
    ("smb-tools-launch-preconditions", {"smb_runtime": True}),
    ("kerberos-tools-launch-preconditions", {"kerberos_runtime": True}),
    ("service-web-launch-preconditions", {"service_web_runtime": True}),
    ("configurable-launch-preconditions", {"configurable_runtime": True}),
    ("whatweb-tools-launch-preconditions", {"whatweb_runtime": True}), (TAG, {"nuclei_runtime": True})])
def test_worker_bootstrap_dispatch_keeps_every_legacy_tag(monkeypatch, tag, kwargs):
    seen = []
    monkeypatch.setattr(worker.sys, "argv", ["worker", "commitment", "user", "net", "mnt", "pid"]
        + ([] if tag is None else [tag]))
    monkeypatch.setattr(worker.bootstrap, "_arguments", lambda *_: (None, {"user": "host"}))
    monkeypatch.setattr(worker, "boundary", lambda host, **flags: seen.append((host, flags)))
    class BoundaryReached(BaseException): pass
    def stop(**_): raise BoundaryReached
    monkeypatch.setattr(worker.socket, "socket", stop)
    with pytest.raises(BoundaryReached):
        worker.main()
    assert seen == [({"user": "host"}, kwargs)]


def test_outer_bubblewrap_passes_reviewed_protocol_tag_to_worker(monkeypatch):
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolation, "_namespaces", lambda: {name: name + "host" for name in ("user", "net", "mnt", "pid")})
    launcher = SimpleNamespace(_config={"profile": "owned_network_tools_lab"},
        _approval_source={}, _witness_source={})
    closure = {"stdlib": "/usr/lib/python3.13", "network_tools_runtime": nuclei.manifest()}
    argv = isolation.LinuxFixtureLauncher._command(launcher, closure, [], "a" * 64)
    assert argv[-1] == TAG
    assert argv[-7] == "/app/recon_cockpit/secure_agent/launcher_worker.py"
    assert "--cap-drop" in argv and "--clearenv" in argv and "--unshare-net" in argv
    assert "CAP_SYS_ADMIN" not in argv
