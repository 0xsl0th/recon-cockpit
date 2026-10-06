"""Portable coverage of shared inspection routing and private manifest custody."""

import errno
import json
import os

import pytest

from recon_cockpit.secure_agent import assessment_inspection as inspection
from recon_cockpit.secure_agent import configurable_evidence, evidence, nmap_evidence


@pytest.fixture
def inspectors(monkeypatch):
    calls = []
    reports = {name: {"selected": name, "integrity_issues": []}
               for name in ("legacy", "native", "configurable")}

    def delegate(name):
        def inspect(directory):
            calls.append((name, directory))
            return reports[name]
        return inspect

    for name, module in (("legacy", evidence), ("native", nmap_evidence),
                         ("configurable", configurable_evidence)):
        monkeypatch.setattr(module, "inspect_assessment", delegate(name))
    return calls, reports


def private_manifest(tmp_path, value):
    directory = tmp_path / "assessment"
    directory.mkdir(mode=0o700)
    manifest = directory / "manifest.json"
    manifest.write_bytes(json.dumps(value).encode("ascii"))
    manifest.chmod(0o600)
    return directory, manifest


@pytest.mark.parametrize("workflow,selected", [
    ("owned-http-assessment-v1", "legacy"),
    ("owned-discovery-http-assessment-v1", "legacy"),
    ("owned-workflow-assessment-v1", "legacy"),
    ("owned-lab-workflow-assessment-v1", "legacy"),
    ("owned-nmap-http-assessment-v1", "native"),
    ("owned-web-assessment-v1", "native"),
    ("owned-http-headers-assessment-v1", "native"),
    ("owned-web-tool-assessment-v1", "native"),
    ("owned-network-tool-assessment-v1", "native"),
    ("owned-service-web-assessment-v1", "native"),
    ("configurable-owned-http-ssh-v1", "configurable"),
    ("future-or-untrusted-workflow", "legacy"),
    ("recon_cockpit.secure_agent.configurable_cli", "legacy"),
    (None, "legacy"), ([], "legacy"), ({}, "legacy"), (7, "legacy"),
])
def test_known_workflows_use_existing_inspectors_without_rewriting_evidence(
        tmp_path, inspectors, workflow, selected):
    directory, manifest = private_manifest(tmp_path, {"workflow": workflow})
    before = manifest.read_bytes(), manifest.stat().st_mtime_ns, manifest.stat().st_mode
    calls, reports = inspectors
    assert inspection.inspect_saved_assessment(directory) is reports[selected]
    assert calls == [(selected, directory)]
    assert before == (manifest.read_bytes(), manifest.stat().st_mtime_ns, manifest.stat().st_mode)
    assert list(directory.iterdir()) == [manifest]


@pytest.mark.parametrize("raw", [
    b"", b"{", b"[]", b"null", b"\xff",
    b'{"workflow":"configurable-owned-http-ssh-v1","workflow":"owned-web-assessment-v1"}',
    b'{"workflow":"configurable-owned-http-ssh-v1","unused":NaN}',
    b'{"workflow":"configurable-owned-http-ssh-v1"}' + b" " * 8192,
])
def test_invalid_manifest_cannot_select_an_inspector(tmp_path, inspectors, raw):
    directory, manifest = private_manifest(tmp_path, {})
    manifest.write_bytes(raw)
    calls, reports = inspectors
    assert inspection.inspect_saved_assessment(directory) is reports["legacy"]
    assert calls == [("legacy", directory)]
    assert manifest.read_bytes() == raw


@pytest.mark.parametrize("fault", ["missing", "public", "symlink", "hardlink", "directory", "fifo"])
def test_manifest_must_be_a_private_single_link_regular_file(tmp_path, inspectors, fault):
    directory, manifest = private_manifest(tmp_path, {"workflow": "configurable-owned-http-ssh-v1"})
    if fault == "missing":
        manifest.unlink()
    elif fault == "public":
        manifest.chmod(0o644)
    elif fault == "symlink":
        target = tmp_path / "original.json"
        manifest.rename(target)
        manifest.symlink_to(target)
    elif fault == "hardlink":
        os.link(manifest, tmp_path / "alias.json")
    elif fault == "directory":
        manifest.unlink()
        manifest.mkdir(mode=0o700)
    elif fault == "fifo":
        manifest.unlink()
        os.mkfifo(manifest, mode=0o600)
    calls, reports = inspectors
    assert inspection.inspect_saved_assessment(directory) is reports["legacy"]
    assert calls == [("legacy", directory)]


@pytest.mark.parametrize("fault", ["missing", "symlink", "file"])
def test_directory_must_exist_and_must_not_be_a_symlink(tmp_path, inspectors, fault):
    directory, manifest = private_manifest(tmp_path, {"workflow": "configurable-owned-http-ssh-v1"})
    supplied = tmp_path / "supplied"
    if fault == "symlink":
        supplied.symlink_to(directory, target_is_directory=True)
    elif fault == "file":
        supplied.write_bytes(manifest.read_bytes())
        supplied.chmod(0o600)
    calls, reports = inspectors
    assert inspection.inspect_saved_assessment(supplied) is reports["legacy"]
    assert calls == [("legacy", supplied)]


@pytest.mark.parametrize("valid", [False, True])
def test_dispatch_manifest_descriptor_is_closed_before_delegating(tmp_path, monkeypatch, valid):
    directory, manifest = private_manifest(tmp_path, {"workflow": "configurable-owned-http-ssh-v1"})
    if not valid:
        manifest.write_bytes(b"{")
    observed = []
    read_private = inspection._read_private

    def capture_fd(fd, name, limit):
        observed.append(fd)
        return read_private(fd, name, limit)

    def delegate(supplied):
        assert supplied == directory and len(observed) == 1
        with pytest.raises(OSError) as raised:
            os.fstat(observed[0])
        assert raised.value.errno == errno.EBADF
        return {"integrity_issues": []}

    monkeypatch.setattr(inspection, "_read_private", capture_fd)
    monkeypatch.setattr(configurable_evidence if valid else evidence, "inspect_assessment", delegate)
    assert inspection.inspect_saved_assessment(directory) == {"integrity_issues": []}


def test_missing_assessment_preserves_the_existing_evidence_failure(tmp_path):
    directory = tmp_path / "missing"
    with pytest.raises(evidence.EvidenceUnavailable) as original:
        evidence.inspect_assessment(directory)
    with pytest.raises(evidence.EvidenceUnavailable) as shared:
        inspection.inspect_saved_assessment(directory)
    assert str(shared.value) == str(original.value)
    assert not directory.exists()


def test_delegate_failure_is_not_retried_with_another_inspector(tmp_path, monkeypatch, inspectors):
    directory, _ = private_manifest(tmp_path, {"workflow": "configurable-owned-http-ssh-v1"})

    def failed(_):
        raise evidence.EvidenceUnavailable("evidence_unavailable")

    monkeypatch.setattr(configurable_evidence, "inspect_assessment", failed)
    with pytest.raises(evidence.EvidenceUnavailable):
        inspection.inspect_saved_assessment(directory)
    assert inspectors[0] == []
