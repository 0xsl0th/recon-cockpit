"""Independent offline file/CLI witnesses; none supplies execution authority."""

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest

from recon_cockpit.secure_agent import engagement_inspection as inspection
from recon_cockpit.secure_agent.engagement_contract import EngagementError


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "engagement_records.py"
FIELDS = {"schema_version", "kind", "engagement_id", "revision", "generation", "status",
          "revision_count", "event_count", "roe_sha256", "export_sha256", "execution_authority"}


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _id(number):
    return str(uuid.UUID(int=number, version=4))


def _roe():
    return {"schema_version": "1", "mode": "disconnected_owned",
            "scope": {"schema_version": "1", "scope_id": "owned-example",
                      "http": {"target": "10.77.0.10", "port": 8080, "path": "/"},
                      "ssh": {"target": "10.77.0.20", "port": 2222}},
            "allowed_profiles": ["configurable_http_headers_v1", "configurable_nmap_service_v1",
                                 "configurable_ssh_host_keys_v1"], "excluded_services": [],
            "window": {"start_utc": "2026-10-20T00:00:00Z", "end_utc": "2026-10-21T00:00:00Z"},
            "limits": {"max_actions": 64, "max_connections": 256, "max_request_bytes": 1048576,
                       "max_response_bytes": 1048576, "max_action_ms": 60000,
                       "max_engagement_ms": 86400000}}


def _snapshot(revisions=2, revoked=True):
    # Construct history independently of production validators/store helpers.
    result = {"schema_version": "1", "kind": "engagement-record-export",
              "engagement_id": _id(1), "state": {}, "revisions": [], "events": []}
    for seq in range(1, revisions + 1 + int(revoked)):
        revoke = seq > revisions
        operation = "revoke" if revoke else "create" if seq == 1 else "revise"
        roe = None if revoke else _roe()
        if roe is not None:
            roe["scope"]["scope_id"] = "owned-case-" + str(seq)
            digest = hashlib.sha256(b"recon-engagement-roe-v1\x00" + _bytes(roe)).hexdigest()
            result["revisions"].append({"revision": seq, "roe": roe, "roe_sha256": digest})
        request = {"schema_version": "1", "engagement_id": _id(1), "event_id": _id(seq + 100),
                   "operation": operation, "expected_revision": None if seq == 1 else seq - 1,
                   "expected_generation": None if seq == 1 else seq - 2, "roe": roe}
        receipt = {k: request[k] for k in ("schema_version", "engagement_id", "event_id", "operation",
                                         "expected_revision", "expected_generation")}
        receipt.update(sequence=seq, revision=min(seq, revisions), generation=seq - 1,
                       status="revoked" if revoke else "recorded", roe_sha256=digest,
                       request_sha256=hashlib.sha256(b"recon-engagement-request-v1\x00" + _bytes(request)).hexdigest())
        result["events"].append(receipt)
    result["state"] = {"revision": revisions, "generation": len(result["events"]) - 1,
                       "status": "revoked" if revoked else "recorded",
                       "last_sequence": len(result["events"])}
    return result


def _save(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _identity(path):
    s = path.stat()
    return path.read_bytes(), stat.S_IMODE(s.st_mode), s.st_mtime_ns


def _call(*args):
    result = subprocess.run([sys.executable, "-B", str(CLI), *map(str, args)],
                            cwd=ROOT, capture_output=True, timeout=10)
    assert result.stderr == b"", result.stderr
    assert len(result.stdout) <= 4096
    return result.returncode, json.loads(result.stdout)


def _refuses(function, *args, code=None, **kwargs):
    with pytest.raises(EngagementError) as caught:
        function(*args, **kwargs)
    assert str(caught.value) == caught.value.code
    if code is not None:
        assert caught.value.code == code
    return caught.value.code


def _script():
    spec = importlib.util.spec_from_file_location("engagement_cli_test", CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_python_cli_exact_report(tmp_path):
    value = _snapshot()
    raw = _bytes(value)
    path = _save(tmp_path / "record.json", raw)
    before = _identity(path)
    report = inspection.inspect_export(path)
    assert set(report) == FIELDS
    assert report == {"schema_version": "1", "kind": "engagement-record-inspection",
                      "engagement_id": _id(1), "revision": 2, "generation": 2,
                      "status": "revoked", "revision_count": 2, "event_count": 3,
                      "roe_sha256": value["revisions"][-1]["roe_sha256"],
                      "export_sha256": hashlib.sha256(raw).hexdigest(), "execution_authority": False}
    assert _call("inspect", "--export", path) == (0, report)
    assert _identity(path) == before


def test_canonical_export_only(tmp_path):
    value = _snapshot()
    for index, raw in enumerate((_bytes(value) + b"\n", b" " + _bytes(value),
                                 json.dumps(value).encode(), json.dumps(value, indent=2).encode())):
        path = _save(tmp_path / str(index), raw)
        _refuses(inspection.inspect_export, path)
        assert path.read_bytes() == raw


def test_roe_input_normalization(tmp_path):
    raw = json.dumps(_roe(), indent=2).encode()
    raw += b" " * (4096 - len(raw))
    path = _save(tmp_path / "roe.json", raw)
    assert inspection.read_roe_file(path) == _roe()
    assert path.read_bytes() == raw
    _refuses(inspection.read_roe_file, _save(tmp_path / "too-big", raw + b" "),
             code="engagement_limit_exceeded")


def test_input_file_kind_and_link_custody(tmp_path, monkeypatch):
    target = _save(tmp_path / "target", _bytes(_snapshot()))
    link = tmp_path / "symlink"
    link.symlink_to(target)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    hardlink = tmp_path / "hardlink"
    os.link(target, hardlink)
    for path in (link, fifo, directory, hardlink, target):
        _refuses(inspection.inspect_export, path, code="engagement_invalid_input")
    hardlink.unlink()
    original = os.fstat
    def character(fd):
        s = original(fd)
        if stat.S_ISREG(s.st_mode):
            values = {k: getattr(s, k) for k in dir(s) if k.startswith("st_")}
            values["st_mode"] = stat.S_IFCHR | 0o600
            return SimpleNamespace(**values)
        return s
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "fstat", character)
        _refuses(inspection.inspect_export, target, code="engagement_invalid_input")
    # Closing any auxiliary descriptor for a live SQLite DB can release this
    # process's POSIX locks. Both readers must refuse before opening that DB.
    from recon_cockpit.secure_agent.engagement_store import EngagementStore
    child = '''import sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0.05, isolation_level=None)
try:
    connection.execute("BEGIN IMMEDIATE")
except sqlite3.OperationalError as error:
    assert error.sqlite_errorcode == sqlite3.SQLITE_BUSY
    print("blocked")
else:
    print("acquired")
    connection.rollback()
finally:
    connection.close()
'''
    with EngagementStore.create(tmp_path / "store", engagement_id=_id(1),
                                roe=_roe(), event_id=_id(101)) as store:
        database = store.directory / "records.sqlite3"
        def writer():
            result = subprocess.run([sys.executable, "-B", "-c", child, str(database)],
                                    capture_output=True, timeout=10)
            assert result.returncode == 0 and result.stderr == b""
            return result.stdout
        with store._transaction(write=True):
            assert writer() == b"blocked\n"
            for read in (inspection.read_roe_file, inspection.inspect_export):
                code = _refuses(read, database)
                assert writer() == b"blocked\n"
                assert code == "engagement_invalid_input"
        assert writer() == b"acquired\n"


def test_private_parent_and_alias_boundary(tmp_path):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = _save(parent / "record", _bytes(_snapshot()))
    alias = tmp_path / "alias"
    alias.symlink_to(parent, target_is_directory=True)
    assert inspection.inspect_export(alias / path.name) == inspection.inspect_export(path)
    parent.chmod(0o750)
    _refuses(inspection.inspect_export, path, code="engagement_invalid_input")
    parent.chmod(0o700)
    path.chmod(0o640)
    _refuses(inspection.inspect_export, path, code="engagement_invalid_input")


def test_bounded_short_reads_to_eof(tmp_path, monkeypatch):
    path = _save(tmp_path / "record", _bytes(_snapshot()))
    original_read, original_open = os.read, os.open
    reads, fds = [], []
    def short(fd, size):
        raw = original_read(fd, min(size, 7))
        reads.append(raw)
        return raw
    def tracked(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        fds.append(fd)
        return fd
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "read", short)
        patch.setattr(inspection.os, "open", tracked)
        report = inspection.inspect_export(path)
    assert report["export_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert len(reads) > 2 * len(path.read_bytes()) // 7 and reads.count(b"") >= 2
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_input_size_and_growth_caps(tmp_path, monkeypatch):
    for index, raw in enumerate((b"", b" " * 524288, b" " * 524289)):
        code = _refuses(inspection.inspect_export, _save(tmp_path / str(index), raw))
        if len(raw) > 524288:
            assert code == "engagement_limit_exceeded"
        assert (tmp_path / str(index)).read_bytes() == raw
    path = _save(tmp_path / "grow", _bytes(_snapshot()))
    original = os.read
    grown = []
    def growing(fd, size):
        if not grown:
            grown.append(True)
            with path.open("ab") as destination:
                destination.write(b" " * 524289)
        return original(fd, size)
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "read", growing)
        assert _refuses(inspection.inspect_export, path) in {
            "engagement_limit_exceeded", "engagement_snapshot_changed"}


def test_input_bytes_changed_during_validation(tmp_path, monkeypatch):
    path = _save(tmp_path / "record", _bytes(_snapshot()))
    original, changed = inspection.decode_export, []
    def mutate(raw):
        result = original(raw)
        if not changed:
            changed.append(True)
            old = path.stat()
            path.write_bytes(path.read_bytes().replace(b"owned-case", b"other-case"))
            os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
        return result
    monkeypatch.setattr(inspection, "decode_export", mutate)
    _refuses(inspection.inspect_export, path, code="engagement_snapshot_changed")
    assert changed


def test_input_name_replaced_during_validation(tmp_path, monkeypatch):
    original = inspection.decode_export
    for kind in ("file", "parent"):
        parent = tmp_path / kind
        parent.mkdir(mode=0o700)
        path = _save(parent / "record", _bytes(_snapshot()))
        changed = []
        def replace(raw):
            result = original(raw)
            if not changed:
                changed.append(True)
                if kind == "file":
                    path.rename(parent / "old")
                else:
                    parent.rename(tmp_path / (kind + "-old"))
                    parent.mkdir(mode=0o700)
                _save(path, raw)
            return result
        with monkeypatch.context() as patch:
            patch.setattr(inspection, "decode_export", replace)
            _refuses(inspection.inspect_export, path, code="engagement_snapshot_changed")
        assert changed


def test_input_metadata_changed_during_validation(tmp_path, monkeypatch):
    original = inspection.decode_export
    for kind in ("mode", "mtime", "nlink", "size"):
        path = _save(tmp_path / kind, _bytes(_snapshot()))
        changed = []
        def mutate(raw):
            result = original(raw)
            if not changed:
                changed.append(True)
                if kind == "mode":
                    path.chmod(0o400)
                elif kind == "mtime":
                    s = path.stat()
                    os.utime(path, ns=(s.st_atime_ns, s.st_mtime_ns + 1000000))
                elif kind == "nlink":
                    os.link(path, tmp_path / "new-link")
                else:
                    with path.open("ab") as destination:
                        destination.write(b" ")
            return result
        with monkeypatch.context() as patch:
            patch.setattr(inspection, "decode_export", mutate)
            _refuses(inspection.inspect_export, path, code="engagement_snapshot_changed")
        assert changed
    # A read-induced atime change must not invalidate an otherwise stable file.
    good = _save(tmp_path / "good", _bytes(_snapshot()))
    assert inspection.inspect_export(good)["execution_authority"] is False


def test_export_never_overwrites(tmp_path):
    target = _save(tmp_path / "existing", b"preserve-me")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    for path in (target, alias):
        _refuses(inspection.write_export, path, _snapshot(), code="engagement_output_exists")
        assert target.read_bytes() == b"preserve-me" and alias.is_symlink()
    invalid = deepcopy(_snapshot())
    invalid["state"]["generation"] = 99
    absent = tmp_path / "invalid"
    _refuses(inspection.write_export, absent, invalid)
    assert not absent.exists()
    reserved = tmp_path / "records.sqlite3"
    _refuses(inspection.write_export, reserved, _snapshot(), code="engagement_invalid_input")
    assert not reserved.exists()
    from recon_cockpit.secure_agent.engagement_store import EngagementStore
    directory = tmp_path / "store"
    with EngagementStore.create(directory, engagement_id=_id(1), roe=_roe(), event_id=_id(101)) as store:
        snapshot = store.snapshot()
    database = directory / "records.sqlite3"
    before = _identity(database)
    output = directory / "export.json"
    _refuses(inspection.write_export, output, snapshot, code="engagement_invalid_input")
    assert not output.exists() and _identity(database) == before
    with EngagementStore.open(directory, read_only=True) as store:
        assert store.snapshot() == snapshot


def test_partial_export_writes(tmp_path, monkeypatch):
    original = os.write
    writes = []
    def short(fd, raw):
        writes.append(len(raw))
        return original(fd, raw[:7])
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "write", short)
        report = inspection.write_export(tmp_path / "valid", _snapshot())
    assert len(writes) > 2
    assert (tmp_path / "valid").read_bytes() == _bytes(_snapshot())
    assert report == inspection.inspect_export(tmp_path / "valid")
    for kind in ("zero", "error"):
        path = tmp_path / kind
        def failed(fd, raw):
            if kind == "zero":
                return 0
            raise OSError("private-write-marker")
        with monkeypatch.context() as patch:
            patch.setattr(inspection.os, "write", failed)
            _refuses(inspection.write_export, path, _snapshot(), code="engagement_store_unavailable")
        if path.exists():
            _refuses(inspection.inspect_export, path)


def test_export_sync_and_custody_failures(tmp_path, monkeypatch):
    original = os.fsync
    for kind in ("file-sync", "parent-sync", "replacement"):
        path = tmp_path / kind
        triggered = []
        def fault(fd):
            mode = os.fstat(fd).st_mode
            target = stat.S_ISDIR(mode) if kind == "parent-sync" else stat.S_ISREG(mode)
            if target and not triggered:
                triggered.append(True)
                if kind == "replacement":
                    path.rename(tmp_path / "retained-written-output")
                    _save(path, b"replacement-must-not-be-overwritten")
                else:
                    raise OSError("private-sync-marker")
            return original(fd)
        with monkeypatch.context() as patch:
            patch.setattr(inspection.os, "fsync", fault)
            assert _refuses(inspection.write_export, path, _snapshot()) in {
                "engagement_store_unavailable", "engagement_snapshot_changed"}
        assert triggered
        if kind == "replacement":
            assert path.read_bytes() == b"replacement-must-not-be-overwritten"
    # Cleanup cannot turn an expired operation into an acknowledged success.
    path = tmp_path / "completed-but-expired"
    original_close = os.close
    clock = [100.0]
    def slow_close(fd):
        original_close(fd)
        clock[0] = 102.01
    with monkeypatch.context() as patch:
        patch.setattr(inspection.time, "monotonic", lambda: clock[0])
        patch.setattr(inspection.os, "close", slow_close)
        _refuses(inspection.write_export, path, _snapshot(), code="engagement_timeout")
    # The fully written file is retained for explicit inspection after failure.
    assert inspection.inspect_export(path)["execution_authority"] is False
    # Reading and report validation share the same deadline. A late nested
    # validator must refuse before beginning another canonicalization pass.
    from recon_cockpit.secure_agent import engagement_contract as contract
    original_decode = inspection.decode_export
    original_validate = inspection.validate_export
    original_canonical = contract.canonical
    clock, late_work = [100.0], []
    def delayed_decode(raw):
        value = original_decode(raw)
        clock[0] = 101.9
        return value
    def expired_validate(value):
        clock[0] = 102.01
        return original_validate(value)
    def observed_canonical(value):
        if clock[0] >= 102:
            late_work.append(True)
        return original_canonical(value)
    with monkeypatch.context() as patch:
        patch.setattr(inspection.time, "monotonic", lambda: clock[0])
        patch.setattr(inspection, "decode_export", delayed_decode)
        patch.setattr(inspection, "validate_export", expired_validate)
        patch.setattr(contract, "canonical", observed_canonical)
        _refuses(inspection.inspect_export, path, code="engagement_timeout")
    assert late_work == []
    # Expiry resets the inherited context for the next independent operation.
    assert inspection.inspect_export(path)["execution_authority"] is False


def test_cli_closed_errors_and_exit_codes(tmp_path, monkeypatch, capsys):
    marker = "DO-NOT-ECHO-private-input"
    rows = [[], [marker], ["inspect"], ["inspect", "--export", marker, "--export", marker],
            ["inspect", "--exp", marker], ["inspect", "--export", marker, "--unexpected", marker],
            ["inspect", "--export", marker], ["inspect", "--export=" + marker, "--export=" + marker]]
    for number in ("0", "-1", "+1", "01", " 1", "١", "65", "9" * 1000):
        rows.append(["revoke", "--store", marker, "--event-id", _id(9),
                     "--expected-revision", number, "--expected-generation", "0"])
    bad = _save(tmp_path / "private-name", ('{"secret":"' + marker + '"}').encode())
    rows.append(["create", "--store", str(tmp_path / "absent"), "--engagement-id", _id(1),
                 "--event-id", _id(101), "--roe-file", str(bad)])
    for args in rows:
        code, result = _call(*args)
        assert code == 2 and set(result) == {"schema_version", "error"}
        assert result["schema_version"] == "1" and result["error"].startswith("engagement_")
        assert marker not in json.dumps(result) and str(tmp_path) not in json.dumps(result)
    cli = _script()
    def unexpected(args):
        raise RuntimeError(marker)
    monkeypatch.setattr(cli, "_run", unexpected)
    assert cli.main(["show", "--store", marker]) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out) == {
        "schema_version": "1", "error": "engagement_store_unavailable"}
    help_result = subprocess.run([sys.executable, "-B", str(CLI), "--help"],
                                 capture_output=True, timeout=5)
    assert help_result.returncode == 0 and help_result.stderr == b"" and b"create" in help_result.stdout
    for phase in ("write", "flush", "short"):
        emitted = []
        class BrokenOutput:
            def write(self, value):
                if phase == "write":
                    raise OSError(marker)
                emitted.append(value[:-1] if phase == "short" else value)
                return len(value) - int(phase == "short")
            def flush(self):
                if phase == "flush":
                    raise RuntimeError(marker)
            def fileno(self):
                raise OSError(marker)
        with monkeypatch.context() as patch:
            patch.setattr(cli, "_run", lambda _args: {"schema_version": "1", "execution_authority": False})
            patch.setattr(cli.sys, "stdout", BrokenOutput())
            assert cli.main(["show", "--store", marker]) == 2
        assert all(marker not in value for value in emitted)
        captured = capsys.readouterr()
        assert captured.out == captured.err == ""
    # Exercise CPython shutdown with a real broken stdout pipe, not only a mock.
    export = _save(tmp_path / "valid-export", _bytes(_snapshot()))
    for args in (("inspect", "--export", str(export)), ("--help",)):
        child = subprocess.Popen([sys.executable, "-B", str(CLI), *args],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            child.stdout.close()
            child.stdout = None
            _, stderr = child.communicate(timeout=10)
            assert child.returncode == 2 and stderr == b""
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)


def test_readonly_commands_preserve_store(tmp_path):
    from recon_cockpit.secure_agent.engagement_store import EngagementStore
    path = tmp_path / "store"
    with EngagementStore.create(path, engagement_id=_id(1), roe=_roe(), event_id=_id(101)) as store:
        receipt = store.event_receipt(_id(101))
    before = {p.name: _identity(p) for p in path.iterdir()}
    code, show = _call("show", "--store", path)
    assert code == 0 and show["execution_authority"] is False
    assert _call("receipt", "--store", path, "--event-id", _id(101)) == (0, receipt)
    assert _call("export", "--store", path, "--output", tmp_path / "export") == (0, show)
    assert {p.name: _identity(p) for p in path.iterdir()} == before


def test_inspection_has_no_execution_or_import(tmp_path):
    path = _save(tmp_path / "record", _bytes(_snapshot()))
    child = '''import builtins, runpy, sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name == "sqlite3" or name.endswith("engagement_store") or any(part in name for part in ("launcher", "provider", "controller", "cost_ledger")):
        raise RuntimeError("forbidden import")
    return original(name, *args, **kwargs)
def audit(event, args):
    if event.startswith(("subprocess.", "socket.", "sqlite3.")):
        raise RuntimeError("forbidden execution")
builtins.__import__ = guarded
sys.addaudithook(audit)
sys.argv = [sys.argv[1], "inspect", "--export", sys.argv[2]]
runpy.run_path(sys.argv[0], run_name="__main__")
'''
    result = subprocess.run([sys.executable, "-B", "-c", child, str(CLI), str(path)],
                            cwd=ROOT, capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stderr == b""
    assert json.loads(result.stdout) == inspection.inspect_export(path)


def test_report_output_caps(tmp_path):
    value = _snapshot(64)
    raw = _bytes(value)
    digest = hashlib.sha256(raw).hexdigest()
    report = inspection.report_export(value, raw_sha256=digest)
    assert set(report) == FIELDS and len(_bytes(report)) + 1 <= 4096
    assert report["revision_count"] == 64 and report["event_count"] == 65
    for supplied in (None, True, 1, "", digest.upper(), "g" * 64, "0" * 64, digest + "\n"):
        _refuses(inspection.report_export, value, raw_sha256=supplied)
    assert inspection.inspect_export(_save(tmp_path / "maximum", raw)) == report


def test_cli_create_revise_revoke_export_workflow(tmp_path):
    store, roe_file = tmp_path / "store", tmp_path / "roe"
    _save(roe_file, _bytes(_roe()))
    code, created = _call("create", "--store", store, "--engagement-id", _id(1),
                           "--roe-file", roe_file, "--event-id", _id(101))
    assert code == 0 and created["revision"] == 1 and created["generation"] == 0
    # Explicit receipt retrieval works even when a caller lost create's response.
    assert _call("receipt", "--store", store, "--event-id", _id(101)) == (0, created)
    roe = _roe()
    roe["scope"]["scope_id"] = "revised-owned"
    _save(roe_file, _bytes(roe))
    revise = ("revise", "--store", store, "--roe-file", roe_file, "--event-id", _id(102),
              "--expected-revision", "1", "--expected-generation", "0")
    code, revised = _call(*revise)
    assert code == 0 and (revised["revision"], revised["generation"]) == (2, 1)
    code, revoked = _call("revoke", "--store", store, "--event-id", _id(103),
                           "--expected-revision", "2", "--expected-generation", "1")
    assert code == 0 and revoked["status"] == "revoked" and revoked["generation"] == 2
    assert _call(*revise) == (0, revised)
    code, report = _call("export", "--store", store, "--output", tmp_path / "export")
    assert code == 0 and report["event_count"] == 3 and report["status"] == "revoked"
    assert _call("inspect", "--export", tmp_path / "export") == (0, report)
    assert _call("revoke", "--store", store, "--event-id", _id(104),
                 "--expected-revision", "2", "--expected-generation", "2")[0] == 2
