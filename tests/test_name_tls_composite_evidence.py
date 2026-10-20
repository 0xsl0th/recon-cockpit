"""Portable custody/entrypoint checks; synthetic objects are not native proof."""

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import name_tls_composite_evidence as composite


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "name_tls_composite_inspect.py"


def minimal_composite(configuration="A"):
    # Only the fields the wrapper extracts. Semantic success is always mocked;
    # the unchanged production validator must reject this incomplete evidence.
    owner = {"manifest": {"selection": {"case": "N15", "configuration": configuration}},
             "dns_outcome": {"execution_status": "succeeded", "untrusted_result": {"status": "succeeded"}}}
    return {"case": "N15", "test_authority": "scripted_owned_pty", "owners": [deepcopy(owner) for _ in range(3)]}


def save(path, value=None, *, raw=None):
    if raw is None:
        raw = json.dumps(minimal_composite() if value is None else value, sort_keys=True).encode("ascii")
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


def expected_report(raw, *, configuration="A", passed=True):
    return {"schema_version": "1", "case_passed": passed,
            "classification": "expected_negative" if passed else "incomplete", "case": "N15",
            "configuration": configuration, "test_authority": "scripted_owned_pty",
            "composite_sha256": hashlib.sha256(raw).hexdigest(), "actual_provider_calls": 0, "owner_count": 3}


@pytest.fixture
def held_descriptors(monkeypatch):
    original, descriptors = os.open, []
    def tracked(*args, **kwargs):
        descriptor = original(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor
    monkeypatch.setattr(composite.os, "open", tracked)
    yield descriptors
    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("passed", (True, False))
def test_exact_historical_report_and_production_delegation_are_immutable(tmp_path, monkeypatch, held_descriptors,
                                                                      configuration, passed):
    path = tmp_path / "composite.json"
    value = minimal_composite(configuration)
    raw = save(path, value)
    before = (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
    calls = []
    def validate(probes, **kwargs):
        calls.append((deepcopy(probes), deepcopy(kwargs)))
        return passed
    monkeypatch.setattr(composite, "validate_probe_evidence", validate)
    assert composite.inspect_composite(path) == expected_report(raw, configuration=configuration, passed=passed)
    assert calls == [(value, {"manifest": value["owners"][0]["manifest"],
                            "results": [{"status": "succeeded"}],
                            "outcomes": [{"execution_status": "succeeded"}]})]
    assert (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) == before


def test_short_reads_are_completed_to_eof_on_both_reads(tmp_path, monkeypatch, held_descriptors):
    path = tmp_path / "composite.json"
    raw = save(path)
    read, reads = os.read, []
    def short(descriptor, maximum):
        reads.append(maximum)
        return read(descriptor, min(maximum, 7))
    monkeypatch.setattr(composite.os, "read", short)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: True)
    assert composite.inspect_composite(path) == expected_report(raw)
    assert len(reads) > 2 * len(raw) // 7


def test_exact_one_mib_input_remains_within_the_existing_decoder_limit(tmp_path, monkeypatch, held_descriptors):
    path = tmp_path / "composite.json"
    raw = json.dumps(minimal_composite(), sort_keys=True).encode("ascii")
    raw += b" " * (composite.MAX_JSON_BYTES - len(raw))
    save(path, raw=raw)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: True)
    assert composite.inspect_composite(path) == expected_report(raw)


def test_nonboolean_validator_result_cannot_become_partial_success(tmp_path, monkeypatch, held_descriptors):
    path = tmp_path / "composite.json"
    save(path)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: 1)
    with pytest.raises(ValueError, match="validation_result"):
        composite.inspect_composite(path)


@pytest.mark.parametrize("mode", (0o400, 0o640, 0o644, 0o700))
def test_nonprivate_modes_refuse_before_validation(tmp_path, monkeypatch, held_descriptors, mode):
    path = tmp_path / "composite.json"
    save(path)
    path.chmod(mode)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: pytest.fail("validated unsafe input"))
    with pytest.raises(ValueError, match="private_file"):
        composite.inspect_composite(path)


@pytest.mark.parametrize("kind", ("empty", "oversized", "directory", "fifo", "hardlink", "foreign_owner"))
def test_nonregular_unbounded_or_unowned_input_refuses(tmp_path, monkeypatch, held_descriptors, kind):
    path = tmp_path / "input"
    if kind == "directory":
        path.mkdir(mode=0o700)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        save(path, raw=b"" if kind == "empty" else b"x" * (composite.MAX_JSON_BYTES + 1) if kind == "oversized" else b"{}")
        if kind == "hardlink":
            os.link(path, tmp_path / "alias")
        if kind == "foreign_owner":
            owner = os.getuid()
            monkeypatch.setattr(composite.os, "getuid", lambda: owner + 1)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: pytest.fail("validated unsafe input"))
    with pytest.raises(ValueError, match="private_file"):
        composite.inspect_composite(path)


def test_symlink_never_opens_target(tmp_path, monkeypatch):
    target, path = tmp_path / "target", tmp_path / "link"
    save(target)
    path.symlink_to(target)
    monkeypatch.setattr(composite, "_read", lambda *args: pytest.fail("read symlink target"))
    with pytest.raises(OSError):
        composite.inspect_composite(path)


@pytest.mark.parametrize("raw", (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}', b'[]', b'\xff',
                                b'{"a":' + b'[' * 65 + b'0' + b']' * 65 + b'}'))
def test_original_decoder_refuses_ambiguous_nonfinite_or_deep_json(tmp_path, monkeypatch, held_descriptors, raw):
    path = tmp_path / "composite.json"
    save(path, raw=raw)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: pytest.fail("decoded invalid JSON"))
    with pytest.raises(ValueError):
        composite.inspect_composite(path)


@pytest.mark.parametrize("change", ("case", "authority", "owners_type", "owner_count", "primary", "selection_case",
                                    "configuration", "outcome", "missing_result"))
def test_only_n15_composites_reach_semantic_validation(tmp_path, monkeypatch, held_descriptors, change):
    value = minimal_composite()
    if change == "case":
        value["case"] = "N14"
    elif change == "authority":
        value["test_authority"] = "saved_grant"
    elif change == "owners_type":
        value["owners"] = {}
    elif change == "owner_count":
        value["owners"].pop()
    elif change == "primary":
        value["owners"][0] = None
    elif change == "selection_case":
        value["owners"][0]["manifest"]["selection"]["case"] = "N14"
    elif change == "configuration":
        value["owners"][0]["manifest"]["selection"]["configuration"] = "C"
    elif change == "outcome":
        value["owners"][0]["dns_outcome"] = []
    else:
        del value["owners"][0]["dns_outcome"]["untrusted_result"]
    path = tmp_path / "composite.json"
    save(path, value)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: pytest.fail("validated wrong shape"))
    with pytest.raises(ValueError, match="composite_shape"):
        composite.inspect_composite(path)


def test_incomplete_evidence_cannot_pass_real_production_validator(tmp_path, held_descriptors):
    path = tmp_path / "composite.json"
    save(path)
    with pytest.raises(ValueError):
        composite.inspect_composite(path)


@pytest.mark.parametrize("change", ("bytes", "mode", "mtime", "replace", "symlink", "hardlink", "unlink"))
def test_input_mutation_or_replacement_during_validation_cannot_return_report(tmp_path, monkeypatch, held_descriptors, change):
    path = tmp_path / "composite.json"
    raw = save(path)
    initial = path.stat()
    def validate(*args, **kwargs):
        if change == "bytes":
            path.write_bytes(raw.replace(b'"A"', b'"B"'))
        elif change == "mode":
            path.chmod(0o644)
        elif change == "mtime":
            os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns + 1000000000))
        elif change in ("replace", "symlink"):
            other = tmp_path / "other"
            save(other, raw=raw)
            if change == "replace":
                other.replace(path)
            else:
                path.unlink()
                path.symlink_to(other)
        elif change == "hardlink":
            os.link(path, tmp_path / "alias")
        else:
            path.unlink()
        return True
    monkeypatch.setattr(composite, "validate_probe_evidence", validate)
    with pytest.raises((ValueError, OSError)):
        composite.inspect_composite(path)


def test_reread_detects_changed_bytes_even_if_metadata_observation_is_unchanged(tmp_path, monkeypatch, held_descriptors):
    path = tmp_path / "composite.json"
    raw = save(path)
    monkeypatch.setattr(composite, "_unchanged", lambda *args: None)
    def validate(*args, **kwargs):
        path.write_bytes(raw.replace(b'"A"', b'"B"'))
        return True
    monkeypatch.setattr(composite, "validate_probe_evidence", validate)
    with pytest.raises(ValueError, match="changed"):
        composite.inspect_composite(path)


@pytest.mark.parametrize("phase", ("initial", "final"))
def test_mutation_during_either_read_is_detected(tmp_path, monkeypatch, held_descriptors, phase):
    path = tmp_path / "composite.json"
    save(path)
    read, eofs = os.read, []
    def mutate_at_eof(descriptor, maximum):
        chunk = read(descriptor, maximum)
        if not chunk:
            eofs.append(True)
            if len(eofs) == (1 if phase == "initial" else 2):
                path.chmod(0o640)
        return chunk
    monkeypatch.setattr(composite.os, "read", mutate_at_eof)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: True)
    with pytest.raises(ValueError, match="changed"):
        composite.inspect_composite(path)


def test_read_cap_still_applies_if_file_grows_after_initial_stat(tmp_path, monkeypatch, held_descriptors):
    path = tmp_path / "composite.json"
    save(path)
    read, first = os.read, []
    def growing(descriptor, maximum):
        if not first:
            first.append(True)
            path.write_bytes(b"x" * (composite.MAX_JSON_BYTES + 1))
        return read(descriptor, maximum)
    monkeypatch.setattr(composite.os, "read", growing)
    with pytest.raises(ValueError, match="composite_size"):
        composite.inspect_composite(path)


@pytest.mark.parametrize("error", (ValueError("semantic_refusal"), RuntimeError("parser_unavailable"), OSError("read_failed")))
def test_validator_failure_never_leaks_descriptor_or_becomes_success(tmp_path, monkeypatch, held_descriptors, error):
    path = tmp_path / "composite.json"
    save(path)
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(composite, "validate_probe_evidence", fail)
    with pytest.raises(type(error), match=str(error)):
        composite.inspect_composite(path)


def cli_module():
    spec = importlib.util.spec_from_file_location("name_tls_composite_inspect_cli_test", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("passed", (True, False))
def test_cli_preserves_exact_json_and_success_status(tmp_path, monkeypatch, capsys, passed):
    path = tmp_path / "composite.json"
    raw = save(path)
    monkeypatch.setattr(composite, "validate_probe_evidence", lambda *args, **kwargs: passed)
    assert cli_module().main([str(path)]) == (0 if passed else 1)
    output = capsys.readouterr()
    assert json.loads(output.out) == expected_report(raw, passed=passed)
    assert output.err == ""


@pytest.mark.parametrize("argument", ("--execute", "--unattended-owned-lab-test", "--run"))
def test_cli_has_no_execution_or_approval_mode(tmp_path, monkeypatch, argument):
    monkeypatch.setattr(composite, "inspect_composite", lambda *args: pytest.fail("unexpected inspection"))
    with pytest.raises(SystemExit) as failure:
        cli_module().main([str(tmp_path / "input"), argument])
    assert failure.value.code == 2


def test_cli_subprocess_refuses_malformed_saved_file_without_report(tmp_path):
    path = tmp_path / "composite.json"
    raw = save(path, raw=b'{"a":1,"a":2}')
    before = (raw, path.stat().st_mode, path.stat().st_mtime_ns)
    result = subprocess.run([sys.executable, str(CLI), str(path)], capture_output=True, timeout=5, check=False)
    assert result.returncode != 0 and result.stdout == b""
    assert b"name_tls_evidence_duplicate_key" in result.stderr
    assert (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns) == before
