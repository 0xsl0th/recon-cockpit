"""Portable regression coverage for native Linux runtime dependency discovery."""

from pathlib import Path
import subprocess

import pytest

from recon_cockpit.secure_agent import isolation


@pytest.fixture
def runtime(monkeypatch):
    state = {
        "probe": b"/usr/lib/python3.14\nx86_64-linux-gnu\n",
        "files": {"/lib/i386-linux-gnu/libseccomp.so.2", "/lib/x86_64-linux-gnu/libseccomp.so.2"},
        "ldd": b"libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1000)\n",
        "commands": [],
    }

    def run(argv, **kwargs):
        state["commands"].append(argv)
        assert kwargs["check"] is True
        assert kwargs["env"] == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
        if argv[0] == "/usr/bin/python3":
            assert argv[1:4] == ["-I", "-S", "-c"]
            output = state["probe"]
        else:
            assert argv[0] == "/usr/bin/ldd"
            output = state["ldd"]
        return subprocess.CompletedProcess(argv, 0, stdout=output, stderr=b"")

    class RuntimePath(type(Path())):
        def is_dir(self):
            return str(self) == "/usr/lib/python3.14"

        def is_file(self):
            return str(self) in state["files"]

        def glob(self, _pattern):
            return iter(())

        def resolve(self, **_kwargs):
            return self

    monkeypatch.setattr(isolation.subprocess, "run", run)
    monkeypatch.setattr(isolation, "_trusted_program", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(isolation, "Path", RuntimePath)
    return state


def test_native_seccomp_is_selected_on_a_multiarch_host(runtime):
    stdlib, files = isolation._runtime_files("/usr/bin/python3", "/usr/sbin/nft")
    assert stdlib == "/usr/lib/python3.14"
    assert runtime["commands"][1][3] == "/lib/x86_64-linux-gnu/libseccomp.so.2"
    destinations = {destination for _, destination in files}
    assert "/lib/x86_64-linux-gnu/libseccomp.so.2" in destinations
    assert "/lib/i386-linux-gnu/libseccomp.so.2" not in destinations
    assert "/lib/x86_64-linux-gnu/libc.so.6" in destinations
    assert not destinations.intersection({"/usr", "/lib"})


def test_foreign_seccomp_does_not_satisfy_native_dependency(runtime):
    runtime["files"] = {"/lib/i386-linux-gnu/libseccomp.so.2"}
    with pytest.raises(isolation.IsolationUnavailable, match="native libseccomp2"):
        isolation._runtime_files("/usr/bin/python3", "/usr/sbin/nft")
    assert len(runtime["commands"]) == 1


def test_native_library_in_usr_lib_is_supported(runtime):
    runtime["files"] = {"/usr/lib/x86_64-linux-gnu/libseccomp.so.2"}
    _, files = isolation._runtime_files("/usr/bin/python3", "/usr/sbin/nft")
    assert "/usr/lib/x86_64-linux-gnu/libseccomp.so.2" in {destination for _, destination in files}


@pytest.mark.parametrize("probe", [b"/usr/lib/python3.14\n", b"/usr/lib/python3.14\nNone\n",
                                   b"/usr/lib/python3.14\n../../tmp\n"])
def test_unidentified_or_unsafe_runtime_architecture_fails_closed(runtime, probe):
    runtime["probe"] = probe
    with pytest.raises(isolation.IsolationUnavailable, match="Cannot identify"):
        isolation._runtime_files("/usr/bin/python3", "/usr/sbin/nft")
    assert len(runtime["commands"]) == 1


def test_native_runtime_still_rejects_missing_transitive_dependencies(runtime):
    runtime["ldd"] = b"libc.so.6 => not found\n"
    with pytest.raises(isolation.IsolationUnavailable, match="missing shared libraries"):
        isolation._runtime_files("/usr/bin/python3", "/usr/sbin/nft")
