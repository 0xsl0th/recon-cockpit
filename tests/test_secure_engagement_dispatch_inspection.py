"""Independent saved-data, file-custody and CLI proofs; no dispatch occurs."""

from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

from recon_cockpit.secure_agent import engagement_dispatch_inspection as inspection
from recon_cockpit.secure_agent.engagement_dispatch_contract import DispatchLedgerError


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/engagement_dispatch_records.py"
FIELDS = {"schema_version", "kind", "engagement_id", "revision", "generation", "status",
          "usage", "utc_high_water_ns", "counts", "reported_outcomes", "uncompleted_reservations",
          "state_sha256", "export_sha256", "consistency", "authority", "physical_delivery"}


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _id(number):
    return str(UUID(int=number, version=4))


def _roe():
    value = json.loads((ROOT / "examples/secure-agent-engagement-roe.json").read_text())
    value["scope"]["http"]["path"] = "/"
    value["allowed_profiles"] = ["configurable_http_headers_v1", "configurable_nmap_service_v1"]
    value["excluded_services"] = []
    value["window"] = {"start_utc": "2026-10-20T00:00:00Z", "end_utc": "2026-10-21T00:00:00Z"}
    value["limits"] = {"max_actions": 64, "max_connections": 256, "max_request_bytes": 1048576,
                       "max_response_bytes": 1048576, "max_action_ms": 30000,
                       "max_engagement_ms": 86400000}
    return value


def _clock(ms):
    # Deliberately supplied observations, not a claim about current host time.
    return {"utc_ns": 1792454401000000000 + ms * 1000000,
            "mono_before_ns": 1000000000 + ms * 1000000,
            "mono_after_ns": 1000000000 + ms * 1000000}


def _store(path):
    from recon_cockpit.secure_agent.engagement_dispatch_store import DispatchLedger
    return DispatchLedger.create(path, engagement_id=_id(1), roe=_roe(), event_id=_id(101))


@pytest.fixture
def snapshot(tmp_path):
    with _store(tmp_path / "store") as store:
        return store.snapshot()


def _save(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return path


def _identity(path):
    info = path.stat(follow_symlinks=False)
    return path.read_bytes(), info.st_mode, info.st_mtime_ns


def _refuses(function, *args, code=None, **kwargs):
    with pytest.raises(DispatchLedgerError) as caught:
        function(*args, **kwargs)
    if code is not None:
        assert caught.value.code == "engagement_dispatch_" + code
    return caught.value.code


def _call(*args):
    result = subprocess.run([sys.executable, "-B", str(CLI), *map(str, args)],
                            cwd=ROOT, capture_output=True, timeout=15)
    assert result.stderr == b"" and len(result.stdout) <= 8192
    value = json.loads(result.stdout)
    assert result.stdout == _bytes(value) + b"\n"
    return result.returncode, value


def _script():
    spec = importlib.util.spec_from_file_location("dispatch_records_test_cli", CLI)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def _record(store, index, *, outcome="reported_success", complete=True, revision=1):
    session, dispatch = _id(7000 + index), _id(6000 + index)
    generation = revision - 1
    clock = _clock(index * 10)
    store.record_session(session_id=session, clock=clock,
        original_deadline_ns=clock["mono_after_ns"] + 60000000000,
        event_id=_id(10000 + index * 3), expected_revision=revision, expected_generation=generation)
    store.reserve(dispatch_id=dispatch, session_id=session, slot="http_identify",
        approval={"broker_id": _id(4000 + index), "consume_sequence": 1, "witness_sha256": "1" * 64},
        audit={"writer_id": _id(5000), "audit_sequence": index + 1, "event_sha256": "2" * 64},
        clock=_clock(index * 10 + 1), event_id=_id(10001 + index * 3),
        expected_revision=revision, expected_generation=generation)
    if complete:
        observation = ({"evidence_sha256": "3" * 64, "connections": 1,
                        "request_bytes": 10, "response_bytes": 20}
                       if outcome == "reported_success" else None)
        if outcome == "cancelled":
            observation = {"evidence_sha256": "4" * 64, "connections": 1,
                           "request_bytes": 5, "response_bytes": 0}
        store.complete(dispatch_id=dispatch, session_id=session, outcome=outcome,
            observation=observation, clock=_clock(index * 10 + 2), event_id=_id(10002 + index * 3))


def test_reports_exact_canonical_export(tmp_path, snapshot):
    path = tmp_path / "export"
    report = inspection.write_export(path, snapshot)
    assert path.read_bytes() == _bytes(snapshot) and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert inspection.inspect_export(path) == report
    assert set(report) == FIELDS and report["schema_version"] == "2"
    assert report["kind"] == "engagement_dispatch_report"
    assert report["counts"] == {"revisions": 1, "sessions": 0, "reservations": 0,
                                "completions": 0, "events": 1}
    assert report["authority"] == "none" and report["physical_delivery"] == "unverified"
    assert report["export_sha256"] == hashlib.sha256(_bytes(snapshot)).hexdigest()
    assert report["state_sha256"] == hashlib.sha256(
        b"recon-engagement-dispatch-state-v2\x00" + _bytes(snapshot["state"])).hexdigest()
    report["usage"]["actions"] = 999
    assert inspection.inspect_export(path)["usage"]["actions"] == 0


def test_rejects_caller_digest_mismatch(tmp_path, snapshot):
    digest = hashlib.sha256(_bytes(snapshot)).hexdigest()
    for value in (None, True, 1, "", digest.upper(), "g" * 64, "0" * 64, digest + "\n"):
        _refuses(inspection.report_export, snapshot, raw_sha256=value, code="invalid_export")
    expected = inspection.report_export(snapshot, raw_sha256=digest)
    assert inspection.inspect_export(_save(tmp_path / "good", _bytes(snapshot))) == expected
    _refuses(inspection.inspect_export, _save(tmp_path / "newline", _bytes(snapshot) + b"\n"))


def test_rejects_malformed_bounded_export(tmp_path, snapshot, monkeypatch):
    raw = _bytes(snapshot)
    changed = deepcopy(snapshot)
    changed["state"]["usage"]["actions"] = 1
    rows = [b"", raw[:-1], b'{"schema_version":"2","schema_version":"2"}',
            b'{"private":"secret-marker"}', b"\xff", b"[" * 14 + b"0" + b"]" * 14,
            b'{"x":"\\ud800"}', b" " * 2097152, b" " * 2097153, _bytes(changed)]
    for index, data in enumerate(rows):
        path = _save(tmp_path / str(index), data)
        before = _identity(path)
        code = _refuses(inspection.inspect_export, path)
        if len(data) > 2097152:
            assert code == "engagement_dispatch_limit_exceeded"
        assert _identity(path) == before
    path = _save(tmp_path / "grow", raw)
    original, grown = os.read, []
    def grow(fd, size):
        if not grown:
            grown.append(True)
            with path.open("ab") as output:
                output.write(b" " * 2097153)
        return original(fd, size)
    monkeypatch.setattr(inspection.os, "read", grow)
    assert _refuses(inspection.inspect_export, path) in {
        "engagement_dispatch_limit_exceeded", "engagement_dispatch_snapshot_changed"}


def test_refuses_nonprivate_input_types(tmp_path, snapshot):
    path = _save(tmp_path / "good", _bytes(snapshot))
    alias = tmp_path / "symlink"
    alias.symlink_to(path)
    _refuses(inspection.inspect_export, alias, code="invalid_input")
    link = tmp_path / "hardlink"
    os.link(path, link)
    _refuses(inspection.inspect_export, path, code="invalid_input")
    link.unlink()
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    for candidate in (fifo, tmp_path, Path(os.devnull)):
        _refuses(inspection.inspect_export, candidate, code="invalid_input")
    path.chmod(0o640)
    _refuses(inspection.inspect_export, path, code="invalid_input")
    path.chmod(0o600)
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    nested = _save(parent / "record", _bytes(snapshot))
    directory_alias = tmp_path / "parent-alias"
    directory_alias.symlink_to(parent, target_is_directory=True)
    assert inspection.inspect_export(directory_alias / nested.name) == inspection.inspect_export(nested)
    parent.chmod(0o750)
    _refuses(inspection.inspect_export, nested, code="invalid_input")


def test_detects_held_fd_input_races(tmp_path, snapshot, monkeypatch):
    original_decode, original_read, original_open = inspection.decode_export, os.read, os.open
    for kind in ("bytes", "file", "parent", "mode", "mtime", "nlink"):
        parent = tmp_path / kind
        parent.mkdir(mode=0o700)
        path = _save(parent / "record", _bytes(snapshot))
        touched, descriptors = [], []
        def mutate(raw):
            value = original_decode(raw)
            if not touched:
                touched.append(True)
                if kind == "bytes":
                    old = path.stat()
                    data = path.read_bytes().replace(b'"recorded"', b'"revoked!"')
                    assert data != raw and len(data) == len(raw)
                    path.write_bytes(data)
                    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
                elif kind == "file":
                    path.rename(parent / "old")
                    _save(path, raw)
                elif kind == "parent":
                    parent.rename(tmp_path / "retained-parent")
                    parent.mkdir(mode=0o700)
                    _save(path, raw)
                elif kind == "mode":
                    path.chmod(0o400)
                elif kind == "mtime":
                    old = path.stat()
                    os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns + 1000000))
                else:
                    os.link(path, parent / "second-link")
            return value
        def tracked(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            descriptors.append(fd)
            return fd
        with monkeypatch.context() as patch:
            patch.setattr(inspection, "decode_export", mutate)
            patch.setattr(inspection.os, "open", tracked)
            _refuses(inspection.inspect_export, path, code="snapshot_changed")
        assert touched
        for fd in descriptors:
            with pytest.raises(OSError):
                os.fstat(fd)
    good = _save(tmp_path / "short-read", _bytes(snapshot))
    reads = []
    def short(fd, count):
        data = original_read(fd, min(count, 7))
        reads.append(data)
        return data
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "read", short)
        inspection.inspect_export(good)
    assert reads.count(b"") >= 2 and len(reads) > len(good.read_bytes()) // 7


def test_refuses_store_directory_inputs(tmp_path, snapshot, monkeypatch):
    database = tmp_path / "store" / "records.sqlite3"
    child = '''import sqlite3,sys
c=sqlite3.connect(sys.argv[1],timeout=.05,isolation_level=None)
try:
    c.execute('BEGIN IMMEDIATE')
except sqlite3.OperationalError as e:
    assert e.sqlite_errorcode==sqlite3.SQLITE_BUSY
    print('blocked')
else:
    print('acquired')
    c.rollback()
finally:
    c.close()
'''
    def probe():
        result = subprocess.run([sys.executable, "-B", "-c", child, str(database)],
                                capture_output=True, timeout=10)
        assert result.returncode == 0 and result.stderr == b""
        return result.stdout
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("BEGIN IMMEDIATE")
        assert probe() == b"blocked\n"
        original_open = os.open
        def no_database(name, *args, **kwargs):
            assert os.fspath(name) != "records.sqlite3", "reader opened the live database"
            return original_open(name, *args, **kwargs)
        with monkeypatch.context() as patch:
            patch.setattr(inspection.os, "open", no_database)
            for reader in (inspection.read_roe_file, inspection.inspect_export):
                _refuses(reader, database, code="invalid_input")
                assert probe() == b"blocked\n"
        connection.rollback()
        assert probe() == b"acquired\n"
    finally:
        connection.close()


def test_creates_outputs_exclusively(tmp_path, snapshot):
    path = _save(tmp_path / "existing", b"preserve")
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    before = _identity(path)
    for target in (path, alias):
        _refuses(inspection.write_export, target, snapshot, code="output_exists")
        assert _identity(path) == before
    for target in (tmp_path / "records.sqlite3", tmp_path / "store" / "export"):
        _refuses(inspection.write_export, target, snapshot, code="invalid_input")
        assert not target.exists()
    malformed = deepcopy(snapshot)
    malformed["state"]["generation"] = 99
    target = tmp_path / "never-created"
    _refuses(inspection.write_export, target, malformed)
    assert not target.exists()


def test_retains_partial_output_failures(tmp_path, snapshot, monkeypatch):
    original_write, original_sync = os.write, os.fsync
    with monkeypatch.context() as patch:
        patch.setattr(inspection.os, "write", lambda fd, data: original_write(fd, data[:7]))
        report = inspection.write_export(tmp_path / "short", snapshot)
    assert report == inspection.inspect_export(tmp_path / "short")
    for kind in ("partial", "zero", "file-sync", "parent-sync", "replacement", "readback"):
        target = tmp_path / kind
        writes = []
        def write(fd, raw):
            if kind == "partial":
                if writes:
                    raise OSError("private-write-marker")
                writes.append(True)
                return original_write(fd, raw[:17])
            return 0 if kind == "zero" else original_write(fd, raw)
        def sync(fd):
            mode = os.fstat(fd).st_mode
            if ((kind == "file-sync" and stat.S_ISREG(mode))
                    or (kind == "parent-sync" and stat.S_ISDIR(mode))):
                raise OSError("private-fsync-marker")
            if kind == "replacement" and stat.S_ISREG(mode):
                target.rename(tmp_path / "retained-output")
                _save(target, b"replacement")
            return original_sync(fd)
        with monkeypatch.context() as patch:
            patch.setattr(inspection.os, "write", write)
            patch.setattr(inspection.os, "fsync", sync)
            if kind == "readback":
                patch.setattr(inspection, "_read_to_eof", lambda *_args: b"changed")
            assert _refuses(inspection.write_export, target, snapshot) in {
                "engagement_dispatch_store_unavailable", "engagement_dispatch_snapshot_changed"}
        assert target.exists()
        if kind == "partial":
            assert target.read_bytes() == _bytes(snapshot)[:17]
        if kind == "replacement":
            assert target.read_bytes() == b"replacement"
        before = _identity(target)
        _refuses(inspection.write_export, target, snapshot, code="output_exists")
        assert _identity(target) == before


def test_shares_deadline_through_cleanup(tmp_path, snapshot, monkeypatch):
    from recon_cockpit.secure_agent import engagement_contract as v1
    from recon_cockpit.secure_agent import engagement_dispatch_contract as contract
    path = tmp_path / "complete-but-expired"
    original_close, clock = os.close, [100.0]
    def slow_close(fd):
        original_close(fd)
        clock[0] = 102.01
    def fake_clock(patch):
        patch.setattr(v1, "time", SimpleNamespace(monotonic=lambda: clock[0]))
        if hasattr(contract, "time"):
            patch.setattr(contract, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    with monkeypatch.context() as patch:
        fake_clock(patch)
        patch.setattr(inspection.os, "close", slow_close)
        _refuses(inspection.write_export, path, snapshot, code="timeout")
    assert inspection.inspect_export(path)["authority"] == "none"
    original_decode, original_validate = inspection.decode_export, inspection.validate_export
    original_canonical = contract.canonical
    clock, late_work = [100.0], []
    def decode(raw):
        result = original_decode(raw)
        clock[0] = 101.9
        return result
    def validate(value):
        clock[0] = 102.01
        return original_validate(value)
    def canonical(value):
        if clock[0] >= 102:
            late_work.append(True)
        return original_canonical(value)
    with monkeypatch.context() as patch:
        fake_clock(patch)
        patch.setattr(inspection, "decode_export", decode)
        patch.setattr(inspection, "validate_export", validate)
        patch.setattr(contract, "canonical", canonical)
        _refuses(inspection.inspect_export, path, code="timeout")
    assert late_work == []
    assert inspection.inspect_export(path)["authority"] == "none"


def test_runs_finite_metadata_cli(tmp_path):
    path = tmp_path / "store"
    roe_path = _save(tmp_path / "roe", _bytes(_roe()))
    code, created = _call("create", "--directory", path, "--engagement-id", _id(1),
                          "--roe", roe_path, "--event-id", _id(101))
    assert code == 0 and set(created) == {"schema_version", "kind", "disposition", "receipt"}
    assert created["kind"] == "data_only" and created["disposition"] == "recorded"
    assert _call("receipt", "--directory", path, "--event-id", _id(101)) == (0, created["receipt"])
    revision = ("revise", "--directory", path, "--roe", roe_path, "--event-id", _id(102),
                "--expected-revision", "1", "--expected-generation", "0")
    code, revised = _call(*revision)
    assert code == 0 and revised["receipt"]["revision"] == 2
    code, revoked = _call("revoke", "--directory", path, "--event-id", _id(103),
                          "--expected-revision", "2", "--expected-generation", "1")
    assert code == 0 and revoked["receipt"]["status"] == "revoked"
    code, retried = _call(*revision)
    assert code == 0 and retried["disposition"] == "already_recorded"
    assert retried["receipt"] == revised["receipt"]
    assert _call("show", "--directory", path)[1]["counts"]["events"] == 3
    for command in ("session", "reserve", "complete", "run"):
        assert _call(command, "--directory", path)[0] == 2


def test_matches_cli_inspection_without_sqlite(tmp_path, snapshot):
    code, report = _call("export", "--directory", tmp_path / "store", "--output", tmp_path / "export")
    assert code == 0 and report == inspection.inspect_export(tmp_path / "export")
    assert _call("inspect", "--input", tmp_path / "export") == (0, report)
    child = '''import builtins,runpy,sys
original=builtins.__import__
def guarded(name,*args,**kwargs):
    if name=='sqlite3' or name.endswith(('engagement_store','engagement_dispatch_store')) or any(s in name for s in ('launcher','provider','controller','approval_worker','credential')):
        raise RuntimeError('forbidden import')
    return original(name,*args,**kwargs)
builtins.__import__=guarded
sys.argv=[sys.argv[1],'inspect','--input',sys.argv[2]]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, "-B", "-c", child, str(CLI), str(tmp_path / "export")],
                            cwd=ROOT, capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stderr == b"" and json.loads(result.stdout) == report


def test_closes_command_line_errors(tmp_path, monkeypatch, capsys):
    marker = "private-input-do-not-echo"
    rows = [[], [marker], ["inspect"], ["inspect", "--input", marker],
            ["inspect", "--input", marker, "--input", marker], ["inspect", "--inp", marker],
            ["inspect", "--input=" + marker, "--input=" + marker],
            ["inspect", "--input", marker, "--unknown", marker]]
    for value in ("0", "-1", "+1", "01", " 1", "١", "65", "9" * 1000):
        rows.append(["revoke", "--directory", marker, "--event-id", _id(5),
                     "--expected-revision", value, "--expected-generation", "0"])
    bad = _save(tmp_path / "private-name", ('{"secret":"' + marker + '"}').encode())
    rows.append(["create", "--directory", str(tmp_path / "absent"), "--engagement-id", _id(1),
                 "--event-id", _id(101), "--roe", str(bad)])
    errors = set(json.loads((ROOT / "docs/stage4-engagement-dispatch-ledger-gates.json").read_text())["error_codes"])
    for args in rows:
        code, result = _call(*args)
        assert code == 2 and set(result) == {"schema_version", "error"}
        assert result["schema_version"] == "2" and result["error"] in errors
        assert marker not in json.dumps(result) and str(tmp_path) not in json.dumps(result)
    assert not (tmp_path / "absent").exists()
    cli = _script()
    def fault(_args):
        raise RuntimeError(marker)
    monkeypatch.setattr(cli, "_run", fault)
    assert cli.main(["show", "--directory", marker]) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out) == {
        "schema_version": "2", "error": "engagement_dispatch_store_unavailable"}


def test_handles_closed_stdout_and_help(tmp_path, snapshot, monkeypatch, capsys):
    cli = _script()
    for phase in ("write", "flush", "short"):
        emitted, redirected = [], []
        class BrokenOutput:
            def write(self, value):
                if phase == "write":
                    raise OSError("private-output-marker")
                emitted.append(value)
                return len(value) - int(phase == "short")
            def flush(self):
                if phase == "flush":
                    raise RuntimeError("private-output-marker")
            def fileno(self):
                return 42  # An arbitrary user stream FD must never be redirected.
        with monkeypatch.context() as patch:
            patch.setattr(cli, "_run", lambda _args: {"authority": "none"})
            patch.setattr(cli.sys, "stdout", BrokenOutput())
            patch.setattr(cli.os, "dup2", lambda *args: redirected.append(args))
            assert cli.main(["show", "--directory", "unused"]) == 2
        assert not redirected and all("private-output-marker" not in x for x in emitted)
        captured = capsys.readouterr()
        assert captured.out == captured.err == ""
    # Positive writes can consume the budget without EAGAIN. Stop before the
    # next byte or success flush; do not wait for an eventual main() postcheck.
    clock, writes, flushes, flags = [100.0], [], [], []
    class ActualOutput:
        def fileno(self):
            return 1
        def flush(self):
            flushes.append(clock[0])
    def slow_write(fd, raw):
        assert fd == 1
        writes.append((clock[0], raw[:1]))
        clock[0] = 102.01
        return 1
    with monkeypatch.context() as patch:
        patch.setattr(cli.sys, "stdout", ActualOutput())
        patch.setattr(cli, "time", SimpleNamespace(monotonic=lambda: clock[0]))
        patch.setattr(cli.os, "get_blocking", lambda fd: True)
        patch.setattr(cli.os, "set_blocking", lambda fd, flag: flags.append((fd, flag)))
        patch.setattr(cli.os, "write", slow_write)
        patch.setattr(cli.os, "dup2", lambda *_args: None)
        assert cli._emit('{"authority":"none"}', 102.0) is False
    assert writes == [(100.0, b"{")] and flushes == [100.0]
    assert flags == [(1, False), (1, True)]
    result = subprocess.run([sys.executable, "-B", str(CLI), "--help"], capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stderr == b"" and len(result.stdout) <= 8192
    path = _save(tmp_path / "export", _bytes(snapshot))
    for args in (("inspect", "--input", str(path)), ("--help",)):
        child = subprocess.Popen([sys.executable, "-B", str(CLI), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            child.stdout.close()
            child.stdout = None
            _, stderr = child.communicate(timeout=10)
            assert child.returncode == 2 and stderr == b""
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    # The reader remains alive but never drains: a full real pipe must not hang
    # either a normal report or argparse's help flush past the original budget.
    for args in (("inspect", "--input", str(path)), ("--help",)):
        reader, writer = os.pipe()
        try:
            os.set_blocking(writer, False)
            while True:
                try:
                    os.write(writer, b"x" * 4096)
                except BlockingIOError:
                    break
            os.set_blocking(writer, True)
            result = subprocess.run([sys.executable, "-B", str(CLI), *args],
                                    stdout=writer, stderr=subprocess.PIPE, timeout=8)
            assert result.returncode == 2 and result.stderr == b""
            assert os.get_blocking(writer) is True
        finally:
            os.close(reader)
            os.close(writer)


def test_keeps_inspection_read_only(tmp_path, snapshot):
    path = _save(tmp_path / "export", _bytes(snapshot))
    database = tmp_path / "store" / "records.sqlite3"
    before = _identity(path), _identity(database)
    report = inspection.inspect_export(path)
    assert _call("show", "--directory", database.parent) == (0, report)
    assert _call("receipt", "--directory", database.parent, "--event-id", _id(101))[0] == 0
    assert _call("inspect", "--input", path) == (0, report)
    child = '''import runpy,sys
def audit(event,args):
    if event.startswith(('subprocess.','socket.','sqlite3.')):
        raise RuntimeError('forbidden execution')
sys.addaudithook(audit)
sys.argv=[sys.argv[1],'inspect','--input',sys.argv[2]]
runpy.run_path(sys.argv[0],run_name='__main__')
'''
    result = subprocess.run([sys.executable, "-B", "-c", child, str(CLI), str(path)],
                            cwd=ROOT, capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stderr == b"" and json.loads(result.stdout) == report
    assert (_identity(path), _identity(database)) == before


def test_separates_reported_and_physical_outcomes(tmp_path):
    with _store(tmp_path / "store") as store:
        for index, outcome in enumerate(("reported_success", "reported_failure", "cancelled", "unresolved")):
            _record(store, index, outcome=outcome)
        _record(store, 4, complete=False)
        value = store.snapshot()
    report = inspection.write_export(tmp_path / "export", value)
    assert report["reported_outcomes"] == {"reported_success": 1, "reported_failure": 1,
                                          "cancelled": 1, "unresolved": 1}
    assert report["uncompleted_reservations"] == 1
    assert report["usage"] == {"actions": 5, "connections": 15, "request_bytes": 20480,
                               "response_bytes": 20480, "runtime_ms": 150000}
    assert report["authority"] == "none" and report["physical_delivery"] == "unverified"
    assert value["completions"][1]["observation"] is None
    assert value["completions"][2]["observation"]["response_bytes"] == 0
    assert _call("inspect", "--input", tmp_path / "export") == (0, report)


def test_roundtrips_attainable_combined_maxima(tmp_path, monkeypatch, capsys):
    from recon_cockpit.secure_agent import engagement_dispatch_contract as contract
    # Construct the data fixture once. S33 independently proves persistence of
    # the full257 history; this case exercises all public inspection/replay work.
    engine = contract._Engine()
    def push(operation, body, number, revision=None, generation=None):
        engine.push(contract.validate_request({"schema_version": "2", "engagement_id": _id(1),
            "event_id": _id(number), "operation": operation, "expected_revision": revision,
            "expected_generation": generation, "body": body}))
    push("create", _roe(), 101)
    for revision in range(1, 64):
        push("revise", _roe(), 200 + revision, revision, revision - 1)
    for index in range(64):
        clock, session, dispatch = _clock(index * 10), _id(7000 + index), _id(6000 + index)
        common = {"owner_id": _id(2), "session_id": session}
        push("session", {**common, "clock": clock,
            "original_deadline_ns": clock["mono_after_ns"] + 60000000000}, 10000 + index * 3, 64, 63)
        push("reserve", {**common, "dispatch_id": dispatch, "slot": "http_identify",
            "approval": {"broker_id": _id(4000 + index), "consume_sequence": 1, "witness_sha256": "1" * 64},
            "audit": {"writer_id": _id(5000), "audit_sequence": index + 1, "event_sha256": "2" * 64},
            "clock": _clock(index * 10 + 1)}, 10001 + index * 3, 64, 63)
        push("complete", {**common, "dispatch_id": dispatch, "outcome": "reported_success",
            "observation": {"evidence_sha256": "3" * 64, "connections": 1,
                            "request_bytes": 10, "response_bytes": 20},
            "clock": _clock(index * 10 + 2)}, 10002 + index * 3)
    push("revoke", None, 30000, 64, 63)
    value = deepcopy(engine.export)
    assert contract.validate_export(value) == value
    assert len(value["events"]) == 257 and len(_bytes(value)) <= 2097152
    report = inspection.write_export(tmp_path / "maximum", value)
    assert report["counts"] == {"revisions": 64, "sessions": 64, "reservations": 64,
                                "completions": 64, "events": 257}
    assert report["usage"] == {"actions": 64, "connections": 192, "request_bytes": 262144,
                               "response_bytes": 262144, "runtime_ms": 1920000}
    assert report["reported_outcomes"]["reported_success"] == 64
    assert report["authority"] == "none" and len(_bytes(report)) + 1 <= 8192
    before = _identity(tmp_path / "maximum")
    assert inspection.inspect_export(tmp_path / "maximum") == report
    assert _call("inspect", "--input", tmp_path / "maximum") == (0, report)
    assert _identity(tmp_path / "maximum") == before
    # Independently install the exact data fixture for readonly CLI work. This
    # setup is not claimed as evidence of public mutation/transaction semantics.
    maximum_store = tmp_path / "maximum-store"
    maximum_store.mkdir(mode=0o700)
    database = maximum_store / "records.sqlite3"
    connection = sqlite3.connect(database, isolation_level=None)
    try:
        connection.execute("PRAGMA page_size=4096")
        connection.execute("BEGIN IMMEDIATE")
        for statement in contract.SCHEMA_SQL:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=2")
        for row in value["revisions"]:
            connection.execute("INSERT INTO revisions VALUES (?,?,?)",
                (row["revision"], _bytes(row["roe"]).decode(), row["roe_sha256"]))
        for row in value["sessions"]:
            connection.execute("INSERT INTO sessions VALUES (?,?,?,?,?)",
                (row["session_id"], row["owner_id"], row["revision"], row["generation"], _bytes(row).decode()))
        for row in value["reservations"]:
            connection.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?)", (
                row["dispatch_id"], row["session_id"], row["slot"], row["approval"]["broker_id"],
                row["approval"]["consume_sequence"], row["audit"]["writer_id"],
                row["audit"]["audit_sequence"], _bytes(row).decode()))
        for row in value["completions"]:
            connection.execute("INSERT INTO completions VALUES (?,?)", (row["dispatch_id"], _bytes(row).decode()))
        for row in value["events"]:
            connection.execute("INSERT INTO events VALUES (?,?,?,?,?)", (row["sequence"], row["event_id"],
                row["request_sha256"], _bytes(row["request"]).decode(), _bytes(row["receipt"]).decode()))
        state, usage = value["state"], value["state"]["usage"]
        connection.execute("INSERT INTO metadata VALUES (1,?,?,?,?,?,?,?,?,?,?,?)", (
            value["engagement_id"], state["revision"], state["generation"], state["status"],
            state["last_sequence"], usage["actions"], usage["connections"], usage["request_bytes"],
            usage["response_bytes"], usage["runtime_ms"], state["utc_high_water_ns"]))
        connection.commit()
    finally:
        connection.close()
    database.chmod(0o600)
    database_before = _identity(database)
    assert _call("show", "--directory", maximum_store) == (0, report)
    assert _call("export", "--directory", maximum_store, "--output", tmp_path / "maximum-cli") == (0, report)
    assert (tmp_path / "maximum-cli").read_bytes() == _bytes(value)
    assert _identity(database) == database_before
    # The CLI cannot grant fresh phase budgets between opening, reading and
    # reporting. Exercise the actual store and command, with a controlled clock.
    from recon_cockpit.secure_agent import engagement_contract as v1
    from recon_cockpit.secure_agent import engagement_dispatch_store as stores
    with _store(tmp_path / "small") as store:
        small = store.snapshot()
    small_report = inspection.report_export(small, raw_sha256=hashlib.sha256(_bytes(small)).hexdigest())
    cli, clock, handles = _script(), [100.0], []
    original_open = stores.DispatchLedger.open
    original_snapshot = stores.DispatchLedger.snapshot
    def slow_open(*args, **kwargs):
        handle = original_open(*args, **kwargs)
        handles.append(handle)
        clock[0] = 101.4
        return handle
    def slow_snapshot(handle):
        clock[0] = 102.01
        return original_snapshot(handle)
    with monkeypatch.context() as patch:
        fake = SimpleNamespace(monotonic=lambda: clock[0])
        patch.setattr(v1, "time", fake)
        patch.setattr(stores, "time", fake)
        patch.setattr(cli, "time", fake)
        patch.setattr(stores.DispatchLedger, "open", slow_open)
        patch.setattr(stores.DispatchLedger, "snapshot", slow_snapshot)
        assert cli.main(["show", "--directory", str(tmp_path / "small")]) == 2
    captured = capsys.readouterr()
    assert captured.err == "" and json.loads(captured.out) == {
        "schema_version": "2", "error": "engagement_dispatch_timeout"}
    assert handles and all(handle._db is None for handle in handles)
    assert _call("show", "--directory", tmp_path / "small") == (0, small_report)
