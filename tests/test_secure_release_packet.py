"""Offline packets replay genuine saved bundles; only source Git is doubled.

The source archive's Git object verification has separate tests. These tests
exercise the packet boundary with real baseline and planning evidence, audits,
and simulation accounting, generated once with the existing portable runtime.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import release_packet as packet
from recon_cockpit.secure_agent.evaluation import EvaluationRunner, inspect_evaluation
from recon_cockpit.secure_agent.evidence import _encode
from recon_cockpit.secure_agent.planning_evaluation import PlanningEvaluationRunner, inspect_planning_evaluation
from test_secure_evaluation import boundaries, policy
from test_secure_planning_evaluation_grading import planning_boundaries


REVISION = "a" * 40
TREE = "b" * 40
ARCHIVE = b"portable source archive boundary fixture\n"
REPOSITORY = Path(packet.__file__).resolve().parents[2]


def _source_metadata():
    return {"schema_version": "1", "verification_revision": REVISION,
            "verification_tree": TREE, "commit_object_base64": "Zml4dHVyZQ==",
            "archive_sha256": hashlib.sha256(ARCHIVE).hexdigest(),
            "archive_bytes": len(ARCHIVE), "files": []}


def _install_source_double(monkeypatch):
    calls = []

    def build(repository, revision):
        assert Path(repository).resolve() == REPOSITORY
        assert revision == REVISION
        calls.append((Path(repository), revision))
        return ARCHIVE, _source_metadata()

    def inspect(archive, metadata):
        if archive != ARCHIVE or metadata != _source_metadata():
            raise ValueError("invalid_portable_source_archive")

    monkeypatch.setattr(packet, "build_source_archive", build)
    monkeypatch.setattr(packet, "inspect_source_archive", inspect)
    return calls


def _state(path):
    """Include identities, private modes and mtimes, without following links."""
    result = {}
    for item in (path, *sorted(path.rglob("*"))):
        value = item.lstat()
        result[str(item.relative_to(path))] = (
            value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size, value.st_mtime_ns,
            item.read_bytes() if stat.S_ISREG(value.st_mode) else None,
        )
    return result


def _bytes(path):
    return {str(item.relative_to(path)): item.read_bytes()
            for item in sorted(path.rglob("*")) if item.is_file()}


def _private_write(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


@pytest.fixture(scope="module")
def saved_inputs(tmp_path_factory):
    root = tmp_path_factory.mktemp("release-packet-inputs")
    baseline = root / "baseline"
    planning = root / "planning"
    with pytest.MonkeyPatch.context() as patches:
        labs = boundaries.__wrapped__(patches)
        baseline_report = EvaluationRunner(baseline, policy()).run(execute=True)
        planning_boundaries.__wrapped__(labs, patches)
        planning_report = PlanningEvaluationRunner(planning, policy()).run(execute=True)
    assert baseline_report["status"] == planning_report["status"] == "passed"
    assert baseline_report["passed_trials"] == planning_report["passed_trials"] == 18
    assert len(labs) == 36 and all(lab.closed for lab in labs)
    return SimpleNamespace(root=root, baseline=baseline, planning=planning,
                           baseline_report=baseline_report, planning_report=planning_report)


@pytest.fixture
def source_double(monkeypatch):
    return _install_source_double(monkeypatch)


@pytest.fixture(scope="module")
def saved_packet(saved_inputs, tmp_path_factory):
    directory = tmp_path_factory.mktemp("release-packet-cache") / "packet"
    with pytest.MonkeyPatch.context() as patches:
        _install_source_double(patches)
        report = packet.build_release_packet(directory, baseline=saved_inputs.baseline,
                                            planning=saved_inputs.planning,
                                            repository=REPOSITORY, revision=REVISION)
        assert packet.inspect_release_packet(directory) == report
    return SimpleNamespace(directory=directory, report=report)


def _build(path, saved_inputs, **overrides):
    arguments = {"baseline": saved_inputs.baseline, "planning": saved_inputs.planning,
                 "repository": REPOSITORY, "revision": REVISION, **overrides}
    return packet.build_release_packet(path, **arguments)


def test_packet_is_deterministic_private_and_preserves_source_bundles(saved_inputs, tmp_path, source_double):
    before = (_state(saved_inputs.baseline), _state(saved_inputs.planning))
    first, second = tmp_path / "first", tmp_path / "second"
    report = _build(first, saved_inputs)
    assert _build(second, saved_inputs) == report
    assert _bytes(first) == _bytes(second)
    assert (_state(saved_inputs.baseline), _state(saved_inputs.planning)) == before
    assert len(source_double) == 2
    assert {item.name for item in first.iterdir()} == {
        "baseline", "planning", "source.tar", "manifest.json", "report.json", "report.md"}
    for item in (first, *first.rglob("*")):
        attributes = item.lstat()
        assert attributes.st_uid == os.getuid()
        assert stat.S_IMODE(attributes.st_mode) == (0o700 if item.is_dir() else 0o600)
        if item.is_file():
            assert attributes.st_nlink == 1
    assert _bytes(first / "baseline") == _bytes(saved_inputs.baseline)
    assert _bytes(first / "planning") == _bytes(saved_inputs.planning)
    assert report["profile"] == "offline-release-evidence-v1"
    assert report["status"] == "verified_offline_packet"
    assert report["actual_provider_calls"] == 0
    assert report["acceptance"] == {"offline_evidence": "verified", "live_model": "pending",
                                    "operator_review": "pending", "release": "local_candidate", "published": False}
    assert report["source"] == {"verification_revision": REVISION, "verification_tree": TREE,
                                "archive_sha256": hashlib.sha256(ARCHIVE).hexdigest(),
                                "execution_revision": "not_recorded"}
    assert [row["case"] for row in report["comparison"]] == list("abcdef")
    assert all(row["trials"] == 3 for row in report["comparison"])


def test_copied_bundles_independently_regrade_and_inspection_never_executes(
        saved_packet, saved_inputs, source_double, monkeypatch):
    directory = saved_packet.directory
    before = _state(directory)

    def forbidden(*_args, **_kwargs):
        pytest.fail("packet inspection attempted execution or source construction")

    monkeypatch.setattr(EvaluationRunner, "run", forbidden)
    monkeypatch.setattr(PlanningEvaluationRunner, "run", forbidden)
    monkeypatch.setattr(packet, "build_source_archive", forbidden)
    assert inspect_evaluation(directory / "baseline") == saved_inputs.baseline_report
    assert inspect_planning_evaluation(directory / "planning") == saved_inputs.planning_report
    assert packet.inspect_release_packet(directory) == saved_packet.report
    assert _state(directory) == before


def test_manifest_binds_every_copied_file_and_source_archive(saved_packet, source_double):
    directory = saved_packet.directory
    manifest = json.loads((directory / "manifest.json").read_bytes())
    contents = _bytes(directory)
    for cached in ("manifest.json", "report.json", "report.md"):
        contents.pop(cached)
    expected = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in sorted(contents.items())]
    assert manifest["inventory"] == expected
    assert manifest["source"] == _source_metadata()
    assert saved_packet.report["packet_sha256"] == hashlib.sha256(
        (directory / "manifest.json").read_bytes()).hexdigest()


def _damage(directory, fault, external):
    trial = directory / "trial-001-a"
    target = trial / "runtime.json"
    if fault == "tamper":
        target.write_text("{}")
    elif fault == "missing":
        target.unlink()
    elif fault == "extra":
        _private_write(directory / "unexpected", b"unreviewed input")
    elif fault == "symlink":
        _private_write(external, target.read_bytes())
        target.unlink()
        target.symlink_to(external)
    elif fault == "hardlink":
        os.link(target, external)
    elif fault == "public_file":
        target.chmod(0o644)
    elif fault == "public_directory":
        trial.chmod(0o755)
    elif fault == "symlink_directory":
        trial.rename(external)
        trial.symlink_to(external, target_is_directory=True)
    elif fault == "fifo":
        target.unlink()
        os.mkfifo(target, 0o600)
    elif fault == "oversized":
        with target.open("r+b") as stream:
            stream.truncate(packet.MAX_BUNDLE_FILE_BYTES + 1)
    else:
        raise AssertionError(fault)


@pytest.mark.parametrize("profile", ["baseline", "planning"])
@pytest.mark.parametrize("fault", ["tamper", "missing", "extra", "symlink", "hardlink",
                                   "public_file", "public_directory", "symlink_directory", "fifo", "oversized"])
def test_build_rejects_untrusted_input_bundles(saved_inputs, tmp_path, source_double, profile, fault):
    source = tmp_path / profile
    shutil.copytree(getattr(saved_inputs, profile), source)
    _damage(source, fault, tmp_path / "external")
    with pytest.raises(packet.ReleasePacketError):
        _build(tmp_path / "packet", saved_inputs, **{profile: source})


@pytest.mark.parametrize("fault", ["missing", "extra", "symlink", "hardlink", "public_file",
                                   "public_directory", "fifo", "oversized", "report_json", "report_markdown",
                                   "manifest", "source_archive", "baseline_evidence", "planning_evidence"])
def test_inspection_rejects_changed_packet_without_repairing_it(saved_packet, tmp_path, source_double, fault):
    directory = tmp_path / "packet"
    shutil.copytree(saved_packet.directory, directory)
    if fault in {"missing", "symlink", "hardlink", "public_file", "public_directory", "fifo", "oversized"}:
        _damage(directory / "planning", fault, tmp_path / "external")
    elif fault == "extra":
        _private_write(directory / "extra", b"unexpected")
    elif fault == "report_json":
        report = json.loads((directory / "report.json").read_bytes())
        report["acceptance"]["live_model"] = "accepted"
        (directory / "report.json").write_text(json.dumps(report))
    elif fault == "report_markdown":
        (directory / "report.md").write_text("Approved for live release.\n")
    elif fault == "manifest":
        manifest = json.loads((directory / "manifest.json").read_bytes())
        manifest["source"]["verification_revision"] = "c" * 40
        (directory / "manifest.json").write_text(json.dumps(manifest))
    elif fault == "source_archive":
        (directory / "source.tar").write_bytes(ARCHIVE + b"changed")
    else:
        profile = fault.removesuffix("_evidence")
        _damage(directory / profile, "tamper", tmp_path / "external")
    before = _state(directory)
    with pytest.raises(packet.ReleasePacketError):
        packet.inspect_release_packet(directory)
    assert _state(directory) == before


def test_source_archive_validation_cannot_be_skipped(saved_inputs, tmp_path, source_double, monkeypatch):
    monkeypatch.setattr(packet, "build_source_archive", lambda *_args: (ARCHIVE + b"changed", _source_metadata()))
    with pytest.raises(packet.ReleasePacketError):
        _build(tmp_path / "packet", saved_inputs)


def test_unrelated_repository_cannot_supply_the_verification_revision(
        saved_inputs, tmp_path, source_double, monkeypatch):
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir(mode=0o700)

    def forbidden(*_args, **_kwargs):
        pytest.fail("unrelated repository reached the source archive builder")

    monkeypatch.setattr(packet, "build_source_archive", forbidden)
    with pytest.raises(packet.ReleasePacketError):
        _build(tmp_path / "packet", saved_inputs, repository=unrelated)


@pytest.mark.parametrize("profile", ["baseline", "planning"])
def test_rehashed_corrupt_evidence_still_requires_independent_regrading(
        saved_packet, tmp_path, source_double, monkeypatch, profile):
    directory = tmp_path / "packet"
    shutil.copytree(saved_packet.directory, directory)
    relative = profile + "/trial-001-a/runtime.json"
    (directory / relative).write_bytes(b"{}")
    manifest = json.loads((directory / "manifest.json").read_bytes())
    row = next(row for row in manifest["inventory"] if row["path"] == relative)
    row.update(size=2, sha256=hashlib.sha256(b"{}").hexdigest())
    encoded = _encode(manifest)
    (directory / "manifest.json").write_bytes(encoded)
    report = json.loads((directory / "report.json").read_bytes())
    report["packet_sha256"] = hashlib.sha256(encoded).hexdigest()
    (directory / "report.json").write_bytes(_encode(report))
    calls = []
    inspector = inspect_evaluation if profile == "baseline" else inspect_planning_evaluation

    def observe(path):
        result = inspector(path)
        calls.append(result["status"])
        return result

    monkeypatch.setattr(packet, "inspect_evaluation" if profile == "baseline"
                        else "inspect_planning_evaluation", observe)
    before = _state(directory)
    with pytest.raises(packet.ReleasePacketError):
        packet.inspect_release_packet(directory)
    assert calls == ["failed"]
    assert _state(directory) == before


def test_saved_source_archive_is_reverified_during_inspection(saved_packet, source_double, monkeypatch):
    calls = []

    def reject(archive, metadata):
        calls.append((archive, metadata))
        raise ValueError("source_object_verification_failed")

    monkeypatch.setattr(packet, "inspect_source_archive", reject)
    before = _state(saved_packet.directory)
    with pytest.raises(packet.ReleasePacketError):
        packet.inspect_release_packet(saved_packet.directory)
    assert calls == [(ARCHIVE, _source_metadata())]
    assert _state(saved_packet.directory) == before


@pytest.mark.parametrize("operation", ["build", "inspect"])
def test_artifact_changes_during_regrading_fail_closed(
        saved_inputs, saved_packet, tmp_path, source_double, monkeypatch, operation):
    source = tmp_path / "source"
    shutil.copytree(saved_inputs.baseline if operation == "build" else saved_packet.directory, source)
    baseline = source if operation == "build" else source / "baseline"
    changed = []

    def mutate_after_grading(path):
        report = inspect_evaluation(path)
        if Path(path) == baseline:
            artifact = baseline / "trial-001-a" / "runtime.json"
            artifact.write_bytes(artifact.read_bytes() + b"\n")
            changed.append(artifact)
        return report

    monkeypatch.setattr(packet, "inspect_evaluation", mutate_after_grading)
    with pytest.raises(packet.ReleasePacketError):
        if operation == "build":
            _build(tmp_path / "packet", saved_inputs, baseline=baseline)
        else:
            packet.inspect_release_packet(source)
    assert len(changed) == 1


@pytest.mark.parametrize("operation", ["build", "inspect"])
@pytest.mark.parametrize("addition", ["private_file", "empty_directory"])
def test_ledger_cannot_carry_unreviewed_siblings_even_with_matching_packet_hashes(
        saved_inputs, saved_packet, tmp_path, source_double, operation, addition):
    directory = tmp_path / "source"
    shutil.copytree(saved_inputs.planning if operation == "build" else saved_packet.directory, directory)
    planning = directory if operation == "build" else directory / "planning"
    extra = planning / "planning-ledger" / "unreviewed"
    if addition == "private_file":
        _private_write(extra, b"unreviewed ledger sibling")
    else:
        extra.mkdir(mode=0o700)
    if operation == "inspect":
        manifest = json.loads((directory / "manifest.json").read_bytes())
        contents = {name: data for name, data in _bytes(directory).items()
                    if name not in {"manifest.json", "report.json", "report.md"}}
        manifest["inventory"] = [
            {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(contents.items())]
        encoded = _encode(manifest)
        (directory / "manifest.json").write_bytes(encoded)
        report = json.loads((directory / "report.json").read_bytes())
        report["packet_sha256"] = hashlib.sha256(encoded).hexdigest()
        (directory / "report.json").write_bytes(_encode(report))
        (directory / "report.md").write_bytes(packet._markdown(report))
    before = _state(directory)
    with pytest.raises(packet.ReleasePacketError):
        if operation == "build":
            _build(tmp_path / "packet", saved_inputs, planning=planning)
        else:
            packet.inspect_release_packet(directory)
    assert _state(directory) == before


def test_existing_output_is_never_overwritten(saved_inputs, saved_packet, tmp_path, source_double):
    directory = tmp_path / "existing"
    shutil.copytree(saved_packet.directory, directory)
    before = _state(directory)
    with pytest.raises(packet.ReleasePacketError):
        _build(directory, saved_inputs)
    assert _state(directory) == before


@pytest.mark.parametrize("profile", ["baseline", "planning"])
def test_output_cannot_be_created_inside_an_input_bundle(saved_inputs, tmp_path, source_double, profile):
    source = tmp_path / profile
    shutil.copytree(getattr(saved_inputs, profile), source)
    before = _state(source)
    with pytest.raises(packet.ReleasePacketError):
        _build(source / "packet", saved_inputs, **{profile: source})
    assert _state(source) == before


@pytest.mark.parametrize("profile", ["baseline", "planning"])
def test_input_root_symlinks_are_refused(saved_inputs, tmp_path, source_double, profile):
    linked = tmp_path / "linked"
    linked.symlink_to(getattr(saved_inputs, profile), target_is_directory=True)
    before = _state(getattr(saved_inputs, profile))
    with pytest.raises(packet.ReleasePacketError):
        _build(tmp_path / "packet", saved_inputs, **{profile: linked})
    assert _state(getattr(saved_inputs, profile)) == before


def test_combined_packet_and_source_archive_limits_are_enforced(saved_inputs, tmp_path, source_double, monkeypatch):
    sizes = [sum(map(len, _bytes(path).values())) for path in (saved_inputs.baseline, saved_inputs.planning)]
    with monkeypatch.context() as patches:
        patches.setattr(packet, "MAX_TOTAL_BYTES", max(sizes) + len(ARCHIVE))
        with pytest.raises(packet.ReleasePacketError):
            _build(tmp_path / "aggregate-too-large", saved_inputs)
    with monkeypatch.context() as patches:
        patches.setattr(packet, "MAX_SOURCE_BYTES", len(ARCHIVE) - 1)
        with pytest.raises(packet.ReleasePacketError):
            _build(tmp_path / "source-too-large", saved_inputs)


@pytest.mark.parametrize("fault", ["files", "directories", "depth", "file_bytes", "total_bytes", "public_root"])
def test_snapshot_enforces_caps_before_accepting_unbounded_input(tmp_path, monkeypatch, fault):
    directory = tmp_path / "tree"
    directory.mkdir(mode=0o700)
    if fault == "files":
        monkeypatch.setattr(packet, "MAX_FILES", 2)
        for index in range(3):
            _private_write(directory / str(index), b"x")
    elif fault == "directories":
        monkeypatch.setattr(packet, "MAX_DIRS", 2)
        for index in range(3):
            (directory / str(index)).mkdir(mode=0o700)
    elif fault == "depth":
        monkeypatch.setattr(packet, "MAX_DEPTH", 1)
        (directory / "first").mkdir(mode=0o700)
        (directory / "first" / "second").mkdir(mode=0o700)
        _private_write(directory / "first" / "second" / "value", b"x")
    elif fault == "file_bytes":
        monkeypatch.setattr(packet, "MAX_BUNDLE_FILE_BYTES", 2)
        _private_write(directory / "value", b"abc")
    elif fault == "total_bytes":
        monkeypatch.setattr(packet, "MAX_TOTAL_BYTES", 7)
        _private_write(directory / "first", b"abcd")
        _private_write(directory / "second", b"efgh")
    elif fault == "public_root":
        directory.chmod(0o755)
    with pytest.raises(packet.ReleasePacketError):
        packet._snapshot(directory)


@pytest.mark.parametrize("fault", ["policy", "limits", "semantic_fingerprint", "provider_calls", "unsettled",
                                   "incomplete", "failed", "insufficient_trials", "unresolved", "actual_incomplete"])
def test_reports_must_agree_and_cannot_claim_live_or_uncertain_accounting(saved_inputs, fault):
    baseline = deepcopy(saved_inputs.baseline_report)
    planning = deepcopy(saved_inputs.planning_report)
    if fault == "policy":
        planning["policy_digest"] = "0" * 64
    elif fault == "limits":
        planning["limits"]["repeats"] = 1
    elif fault == "semantic_fingerprint":
        for row in planning["trials"]:
            if row["case"] == "a":
                row["grade"]["semantic_fingerprint"] = "0" * 64
    elif fault == "provider_calls":
        planning["actual_provider_calls"] = 1
    elif fault == "unsettled":
        planning["planning_cost"]["summary"]["reserved_microusd"] = 1
    elif fault == "incomplete":
        planning["status"] = "incomplete"
    elif fault == "failed":
        baseline["status"] = "failed"
    elif fault == "insufficient_trials":
        baseline["passed_trials"] = planning["passed_trials"] = 6
    elif fault == "unresolved":
        planning["planning_cost"]["summary"]["unresolved_attempts"] = 1
    elif fault == "actual_incomplete":
        planning["planning_cost"]["summary"]["actual_complete"] = False
    with pytest.raises(packet.ReleasePacketError):
        packet._compare_reports(baseline, planning)
