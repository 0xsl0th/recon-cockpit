"""Pin accepted implementations and the complete S4.2c validation inventory."""

import ast
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
GATES = json.loads((ROOT / 'docs/stage4-engagement-live-gates.json').read_text())

_ACCEPTED_MANIFEST_SHA256 = '3a2ae8d0150fbf6f44ca2630508fc7f4199844df9805ffba39a39b62df637e54'
_MAIN_SYNC_PATH = 'docs/stage4-engagement-live-main-sync-20261116.json'
_MAIN_SYNC_SHA256 = '7d9c537c03b4624c8a77ee50ec1e0922a128fe973deaccc56632257c880bc446'
_LOCK_PROBE_AMENDMENT = {'path': 'tests/test_secure_engagement_dispatch_store.py',
 'mode': '100644',
 'scope_sha256': 'e32c67303a824c21236145bff3ea8fa0a97509f6328274e602af16198fc525cc',
 'before': {'bytes': 52977,
            'sha256': '88bc6177831716174801f655c36c1e36c241ee4267eb1742cd4b16318d5fa1b4',
            'git_blob': 'd912f57d956d2f6c29a26af15c440089935b5a61'},
 'after': {'bytes': 57091,
           'sha256': 'e8256dfdbd56a16e84302e5cdd6dbff56df6cc6a7fb29c63247b499cdbd06bbd',
           'git_blob': '4cb52f74309ad688aaaa0069355508bfeafadc05'},
 'replacements': [{'before_text': 'from pathlib import Path\nimport sqlite3\n',
                   'after_text': 'from pathlib import Path\nimport select\nimport sqlite3\n'},
                  {'before_text': 'def test_preserves_real_external_sqlite_lock(store,tmp_path):\n'
                                  '    from '
                                  'recon_cockpit.secure_agent.engagement_dispatch_inspection '
                                  'import inspect_export,read_roe_file\n'
                                  '    from recon_cockpit.secure_agent.engagement_store import '
                                  'EngagementStore\n'
                                  '    from recon_cockpit.secure_agent.engagement_contract import '
                                  'EngagementError\n'
                                  '    script="""\n'
                                  'import sqlite3,sys\n'
                                  'c=sqlite3.connect(sys.argv[1],timeout=.05,isolation_level=None)\n'
                                  'try:\n'
                                  " c.execute('BEGIN IMMEDIATE')\n"
                                  'except sqlite3.OperationalError as e:\n'
                                  ' assert e.sqlite_errorcode==sqlite3.SQLITE_BUSY\n'
                                  " print('blocked')\n"
                                  'else:\n'
                                  " print('acquired');c.rollback()\n"
                                  'finally:c.close()\n'
                                  '"""\n'
                                  '    parent=tmp_path/"v1_parent";parent.mkdir(mode=0o700)\n'
                                  '    with '
                                  'EngagementStore.create(parent/"store",engagement_id=uid(),roe=ROE,event_id=uid()) '
                                  'as v1:\n'
                                  '        for active,own_class,foreign_class,foreign_error in '
                                  '((store,DispatchLedger,EngagementStore,EngagementError),\n'
                                  '                '
                                  '(v1,EngagementStore,DispatchLedger,DispatchLedgerError)):\n'
                                  '            path=active.directory/module.DATABASE\n'
                                  '            def probe():\n'
                                  '                '
                                  'r=subprocess.run([sys.executable,"-c",script,str(path)],capture_output=True,text=True,timeout=10)\n'
                                  '                assert r.returncode==0 and not r.stderr\n'
                                  '                return r.stdout.strip()\n'
                                  '            other=own_class.open(active.directory)\n'
                                  '            try:\n'
                                  '                with active._transaction(write=True):\n'
                                  '                    assert probe()=="blocked"\n'
                                  '                    other.close();assert probe()=="blocked"\n'
                                  '                    for reader in '
                                  '(read_roe_file,inspect_export):\n'
                                  '                        with '
                                  'pytest.raises(DispatchLedgerError):reader(path)\n'
                                  '                        assert probe()=="blocked"\n'
                                  '                    with '
                                  'pytest.raises(foreign_error):foreign_class.open(active.directory)\n'
                                  '                    assert probe()=="blocked"\n'
                                  '                assert probe()=="acquired"\n'
                                  '            finally:other.close()\n',
                   'after_text': '_LOCK_PROBE_SCRIPT = """\n'
                                 'import sqlite3,sys\n'
                                 "print('ready',flush=True)\n"
                                 "assert sys.stdin.buffer.read(2)==b'G'\n"
                                 'c=sqlite3.connect(sys.argv[1],timeout=.05,isolation_level=None)\n'
                                 'try:\n'
                                 " c.execute('BEGIN IMMEDIATE')\n"
                                 'except sqlite3.OperationalError as e:\n'
                                 ' assert e.sqlite_errorcode==sqlite3.SQLITE_BUSY\n'
                                 " result='blocked'\n"
                                 'else:\n'
                                 " c.rollback();result='acquired'\n"
                                 'finally:c.close()\n'
                                 'print(result,flush=True)\n'
                                 '"""\n'
                                 '\n'
                                 '\n'
                                 'def _read_lock_probe_ready(process, deadline):\n'
                                 '    ready = b""\n'
                                 '    while len(ready) < 6:\n'
                                 '        remaining = deadline - time.monotonic()\n'
                                 '        if remaining <= 0 or not select.select([process.stdout], '
                                 '[], [], remaining)[0]:\n'
                                 '            raise TimeoutError("lock probe readiness timed '
                                 'out")\n'
                                 '        chunk = os.read(process.stdout.fileno(), 7 - '
                                 'len(ready))\n'
                                 '        assert chunk, "lock probe EOF before readiness"\n'
                                 '        ready += chunk\n'
                                 '    assert ready == b"ready\\n", "malformed lock probe '
                                 'readiness"\n'
                                 '\n'
                                 '\n'
                                 'def _finish_lock_probe(process):\n'
                                 '    deadline = time.monotonic() + 10\n'
                                 '    assert process.stdin.write(b"G") == 1\n'
                                 '    process.stdin.close()\n'
                                 '    pending = {process.stdout: (32, bytearray()), '
                                 'process.stderr: (4096, bytearray())}\n'
                                 '    outputs = {stream: data for stream, (_, data) in '
                                 'pending.items()}\n'
                                 '    while pending:\n'
                                 '        remaining = deadline - time.monotonic()\n'
                                 '        if remaining <= 0:\n'
                                 '            raise TimeoutError("lock probe response timed out")\n'
                                 '        readable = select.select(list(pending), [], [], '
                                 'remaining)[0]\n'
                                 '        if not readable:\n'
                                 '            raise TimeoutError("lock probe response timed out")\n'
                                 '        for stream in readable:\n'
                                 '            limit, data = pending[stream]\n'
                                 '            chunk = os.read(stream.fileno(), limit + 1 - '
                                 'len(data))\n'
                                 '            if not chunk:\n'
                                 '                del pending[stream]\n'
                                 '            else:\n'
                                 '                data.extend(chunk)\n'
                                 '                assert len(data) <= limit, "oversized lock probe '
                                 'output"\n'
                                 '    remaining = deadline - time.monotonic()\n'
                                 '    if remaining <= 0:\n'
                                 '        raise TimeoutError("lock probe exit timed out")\n'
                                 '    assert process.wait(timeout=remaining) == 0, "nonzero lock '
                                 'probe exit"\n'
                                 '    assert not outputs[process.stderr], "unexpected lock probe '
                                 'stderr"\n'
                                 '    result = bytes(outputs[process.stdout])\n'
                                 '    assert result in (b"blocked\\n", b"acquired\\n"), '
                                 '"unexpected lock probe response"\n'
                                 '    return result.decode().rstrip("\\n")\n'
                                 '\n'
                                 '\n'
                                 '@contextmanager\n'
                                 'def _prestarted_external_lock_probes(path):\n'
                                 '    processes = []\n'
                                 '    failure = None\n'
                                 '    cleanup_failures = []\n'
                                 '    try:\n'
                                 '        deadline = time.monotonic() + 10\n'
                                 '        for _ in range(6):\n'
                                 '            process = subprocess.Popen(\n'
                                 '                [sys.executable, "-c", _LOCK_PROBE_SCRIPT, '
                                 'str(path)],\n'
                                 '                stdin=subprocess.PIPE, stdout=subprocess.PIPE, '
                                 'stderr=subprocess.PIPE,\n'
                                 '                close_fds=True, bufsize=0)\n'
                                 '            processes.append(process)\n'
                                 '            _read_lock_probe_ready(process, deadline)\n'
                                 '        consumed = 0\n'
                                 '\n'
                                 '        def probe():\n'
                                 '            nonlocal consumed\n'
                                 '            assert consumed < len(processes), "too many lock '
                                 'probes"\n'
                                 '            process = processes[consumed]\n'
                                 '            consumed += 1\n'
                                 '            return _finish_lock_probe(process)\n'
                                 '\n'
                                 '        yield probe\n'
                                 '        assert consumed == 6, "unconsumed lock probes"\n'
                                 '    except BaseException as exc:\n'
                                 '        failure = exc\n'
                                 '    finally:\n'
                                 '        for process in processes:\n'
                                 '            try:\n'
                                 '                if process.poll() is None:\n'
                                 '                    process.terminate()\n'
                                 '            except BaseException as exc:\n'
                                 '                cleanup_failures.append(exc)\n'
                                 '            try:\n'
                                 '                process.wait(timeout=2)\n'
                                 '            except subprocess.TimeoutExpired:\n'
                                 '                pass  # Escalate only this owned child to kill, '
                                 'then reap below.\n'
                                 '            except BaseException as exc:\n'
                                 '                cleanup_failures.append(exc)\n'
                                 '            if process.returncode is None:\n'
                                 '                try:\n'
                                 '                    process.kill()\n'
                                 '                except BaseException as exc:\n'
                                 '                    cleanup_failures.append(exc)\n'
                                 '                try:\n'
                                 '                    process.wait(timeout=2)\n'
                                 '                except BaseException as exc:\n'
                                 '                    cleanup_failures.append(exc)\n'
                                 '            for stream in (process.stdin, process.stdout, '
                                 'process.stderr):\n'
                                 '                try:\n'
                                 '                    stream.close()\n'
                                 '                except BaseException as exc:\n'
                                 '                    cleanup_failures.append(exc)\n'
                                 '    if cleanup_failures:\n'
                                 '        raise BaseExceptionGroup("lock probe cleanup failed",\n'
                                 '                                 ([failure] if failure is not '
                                 'None else []) + cleanup_failures)\n'
                                 '    if failure is not None:\n'
                                 '        raise failure\n'
                                 '\n'
                                 '\n'
                                 'def test_preserves_real_external_sqlite_lock(store,tmp_path):\n'
                                 '    from '
                                 'recon_cockpit.secure_agent.engagement_dispatch_inspection import '
                                 'inspect_export,read_roe_file\n'
                                 '    from recon_cockpit.secure_agent.engagement_store import '
                                 'EngagementStore\n'
                                 '    from recon_cockpit.secure_agent.engagement_contract import '
                                 'EngagementError\n'
                                 '    parent=tmp_path/"v1_parent";parent.mkdir(mode=0o700)\n'
                                 '    with '
                                 'EngagementStore.create(parent/"store",engagement_id=uid(),roe=ROE,event_id=uid()) '
                                 'as v1:\n'
                                 '        for active,own_class,foreign_class,foreign_error in '
                                 '((store,DispatchLedger,EngagementStore,EngagementError),\n'
                                 '                '
                                 '(v1,EngagementStore,DispatchLedger,DispatchLedgerError)):\n'
                                 '            path=active.directory/module.DATABASE\n'
                                 '            with _prestarted_external_lock_probes(path) as '
                                 'probe:\n'
                                 '                other=own_class.open(active.directory)\n'
                                 '                try:\n'
                                 '                    with active._transaction(write=True):\n'
                                 '                        assert probe()=="blocked"\n'
                                 '                        other.close();assert probe()=="blocked"\n'
                                 '                        for reader in '
                                 '(read_roe_file,inspect_export):\n'
                                 '                            with '
                                 'pytest.raises(DispatchLedgerError):reader(path)\n'
                                 '                            assert probe()=="blocked"\n'
                                 '                        with '
                                 'pytest.raises(foreign_error):foreign_class.open(active.directory)\n'
                                 '                        assert probe()=="blocked"\n'
                                 '                    assert probe()=="acquired"\n'
                                 '                finally:other.close()\n'}]}
_APPROVED_SOURCE_CHANGES = {'pyproject.toml': {'after_bytes': 745,
                    'after_git_blob': '3f2135c18703c6d8b8ffdb5dcce600c612839a2f',
                    'after_sha256': '3989fe11357acb3144ea7c5e0dc87aebe970e325f32e1a9fbbb1f82954574832',
                    'after_text': 'test = ["pytest==9.1.1"]\n',
                    'before_bytes': 741,
                    'before_git_blob': '1605ee799fa1690b2d0296d007bb41c3056970b3',
                    'before_sha256': '3af7f08a9be31b066518afbffcc72512ab6f10aa7ff18bc4489b19a08498c8d1',
                    'before_text': 'test = ["pytest>=8"]\n',
                    'id': 'S42C-A11',
                    'mode': '100644',
                    'path': 'pyproject.toml'},
 'tests/test_secure_engagement_dispatch_preservation.py': {'after_bytes': 12140,
                                                           'after_git_blob': 'da635c0265257b996363677cbd6347122e362dc3',
                                                           'after_sha256': '1b1c50e2d1d3738c5199951eba0ebb303d9de305dcbb3ea22035c0a39f01c16a',
                                                           'after_text': '        raw = '
                                                                         'path.read_bytes()\n'
                                                                         '        '
                                                                         'exact_dependency_changes = '
                                                                         "{'pyproject.toml': "
                                                                         "('3989fe11357acb3144ea7c5e0dc87aebe970e325f32e1a9fbbb1f82954574832',\n"
                                                                         '                            '
                                                                         "b'test = "
                                                                         '["pytest>=8"]\\n\',\n'
                                                                         '                            '
                                                                         "b'test = "
                                                                         '["pytest==9.1.1"]\\n\'),\n'
                                                                         "         'uv.lock': "
                                                                         "('51eb36224d55e0b365af284f76933350082f184f23a12d53b4c4dff3e3a62eb8',\n"
                                                                         "                     b'    { "
                                                                         'name = "pytest", marker = '
                                                                         '"extra == \\\'test\\\'", '
                                                                         'specifier = ">=8" },\\n\',\n'
                                                                         "                     b'    { "
                                                                         'name = "pytest", marker = '
                                                                         '"extra == \\\'test\\\'", '
                                                                         'specifier = "==9.1.1" '
                                                                         "},\\n')}\n"
                                                                         '        if name in '
                                                                         'exact_dependency_changes:\n'
                                                                         '            after_sha256, '
                                                                         'before, after = '
                                                                         'exact_dependency_changes[name]\n'
                                                                         '            assert '
                                                                         'hashlib.sha256(raw).hexdigest() '
                                                                         '== after_sha256\n'
                                                                         '            assert '
                                                                         'raw.count(after) == 1 and '
                                                                         'before not in raw\n'
                                                                         '            restored = '
                                                                         'raw.replace(after, before)\n'
                                                                         '            assert '
                                                                         'restored.count(before) == 1 '
                                                                         'and after not in restored\n'
                                                                         '            assert '
                                                                         'restored.replace(before, '
                                                                         'after) == raw\n'
                                                                         '            raw = restored\n'
                                                                         '        assert '
                                                                         'hashlib.sha256(raw).hexdigest() '
                                                                         '== expected["sha256"], name\n',
                                                           'before_bytes': 11132,
                                                           'before_git_blob': '3fdfa78356f85981a85b7f2c66aaa1f4967ca04c',
                                                           'before_sha256': 'f4bb2fbabceddc15e6d1ab33c9c8c8e3edf36cd26e14f21f9b2d3e9da053b003',
                                                           'before_text': '        assert '
                                                                          'hashlib.sha256(path.read_bytes()).hexdigest() '
                                                                          '== expected["sha256"], '
                                                                          'name\n',
                                                           'id': 'S42C-A11-preservation-check',
                                                           'mode': '100644',
                                                           'path': 'tests/test_secure_engagement_dispatch_preservation.py'},
 'uv.lock': {'after_bytes': 6991,
             'after_git_blob': 'a22aa0896ef455ecef53c55977763d742ca122e2',
             'after_sha256': '51eb36224d55e0b365af284f76933350082f184f23a12d53b4c4dff3e3a62eb8',
             'after_text': '    { name = "pytest", marker = "extra == \'test\'", specifier = "==9.1.1" '
                           '},\n',
             'before_bytes': 6987,
             'before_git_blob': 'd142ce204b9fef4cf8c7a10012e1563f5726bbba',
             'before_sha256': '10b4fdf0e79e5878ef92641f9537ea5068331de1d1599caa6ab3ab0267ba2b26',
             'before_text': '    { name = "pytest", marker = "extra == \'test\'", specifier = ">=8" '
                            '},\n',
             'id': 'S42C-A11-lock-metadata',
             'mode': '100644',
             'path': 'uv.lock'}}

def _restore_approved_source_change(raw, mode, change):
    # Exact literal transformations retain both original accepted-source pins.
    assert change == _APPROVED_SOURCE_CHANGES[change['path']]
    assert mode == change['mode']
    assert len(raw) == change['after_bytes']
    assert hashlib.sha256(raw).hexdigest() == change['after_sha256']
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == change['after_git_blob']
    before, after = change['before_text'].encode(), change['after_text'].encode()
    assert raw.count(after) == 1 and before not in raw
    restored = raw.replace(after, before)
    assert restored.count(before) == 1 and after not in restored
    assert restored.replace(before, after) == raw
    assert len(restored) == change['before_bytes']
    assert hashlib.sha256(restored).hexdigest() == change['before_sha256']
    assert hashlib.sha1(b'blob ' + str(len(restored)).encode() + b'\0' + restored).hexdigest() == change['before_git_blob']
    return restored



def _new_paths():
    allowed = GATES['change_allowlist']
    return set(allowed['proposed_new_production'] + allowed['confirmed_new_tests_and_helpers']
               + allowed['new_contracts'])


def _main_sync():
    path = ROOT / _MAIN_SYNC_PATH
    mode = path.lstat().st_mode
    assert stat.S_ISREG(mode) and not mode & 0o111
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == _MAIN_SYNC_SHA256
    amendment = json.loads(raw)
    assert amendment['accepted_manifest_sha256'] == _ACCEPTED_MANIFEST_SHA256
    return amendment


def _check_sync_bytes(raw, expected):
    assert len(raw) == expected['bytes']
    assert hashlib.sha256(raw).hexdigest() == expected['sha256']
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['git_blob']


def _restore_main_sync_dispatch(raw, mode, change):
    # Undo only the upstream documentation guard before applying original A11.
    assert mode == change['mode']
    _check_sync_bytes(raw, change['after'])
    before, after = change['before_text'].encode(), change['after_text'].encode()
    assert raw.count(after) == 1 and before not in raw
    restored = raw.replace(after, before)
    assert restored.count(before) == 1 and after not in restored
    assert restored.replace(before, after) == raw
    _check_sync_bytes(restored, change['before'])
    return restored


def _restore_fixture_change(raw, mode, change):
    # Reverse the separately pinned fixture/guard edits before historical checks.
    assert mode == change['mode']
    _check_sync_bytes(raw, change['after'])
    restored = raw
    for edit in reversed(change['replacements']):
        before, after = edit['before_text'].encode(), edit['after_text'].encode()
        assert restored.count(after) == 1
        original = restored.replace(after, before)
        assert original.count(before) == 1 and after not in original
        assert original.replace(before, after) == restored
        restored = original
    _check_sync_bytes(restored, change['before'])
    return restored


def test_exact_accepted_source_and_change_allowlist():
    baseline = GATES['source_baseline']['complete_tracked_manifest']
    allowed = GATES['change_allowlist']
    assert len(baseline) == 1101 and len(_new_paths()) == 39
    status = set(allowed['existing_status_only'])
    assert len(status) == 8 and 'pyproject.toml' not in status
    assert allowed['other_existing_changes'] is False
    changes = {row['path']: row for row in (allowed['approved_test_dependency_change'],
                                           allowed['approved_lock_metadata_change'],
                                           allowed['approved_preservation_test_change'])}
    assert changes == _APPROVED_SOURCE_CHANGES
    assert not status & changes.keys()
    assert GATES['source_baseline']['complete_tracked_manifest_sha256'] == _ACCEPTED_MANIFEST_SHA256
    encoded = json.dumps(baseline, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == _ACCEPTED_MANIFEST_SHA256
    assert GATES['source_baseline']['accepted_nonstatus_unchanged_required'] == 1090
    assert GATES['source_baseline']['accepted_nonstatus_approved_test_dependency_changes_required'] == 1
    assert GATES['source_baseline']['accepted_nonstatus_approved_preservation_test_changes_required'] == 1
    assert GATES['source_baseline']['accepted_nonstatus_approved_lock_metadata_changes_required'] == 1
    # Keep the historical manifest/A11 records intact; main synchronization is
    # separately pinned and never supplies acceptance credit for the new tree.
    sync = _main_sync()
    refreshed = {row['path']: row for row in sync['refreshed_documents']}
    assert len(refreshed) == 4 and not refreshed.keys() & (status | changes.keys())
    dispatch_change = sync['dispatch_preservation_change']
    assert dispatch_change['path'] == 'tests/test_secure_engagement_dispatch_preservation.py'
    fixture_change = sync['approval_failure_fixture_change']
    assert fixture_change['path'] == 'tests/test_name_tls_approval_failure.py'
    assert fixture_change['path'] not in status | changes.keys() | refreshed.keys()
    fixture_guard = sync['approval_failure_dispatch_guard_change']
    assert fixture_guard['path'] == dispatch_change['path']
    assert fixture_guard['before'] == dispatch_change['after']
    lock_change = _LOCK_PROBE_AMENDMENT
    assert lock_change['path'] == 'tests/test_secure_engagement_dispatch_store.py'
    assert lock_change['path'] not in status | changes.keys() | refreshed.keys() | {fixture_change['path']}
    checked = 0
    amended = set()
    refreshed_checked = set()
    fixture_checked = set()
    lock_fixture_checked = set()
    for row in baseline:
        path = ROOT / row['path']
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert ('100755' if info.st_mode & 0o111 else '100644') == row['mode']
        if row['path'] not in status:
            raw = path.read_bytes()
            if row['path'] in refreshed:
                change = refreshed[row['path']]
                assert change['mode'] == row['mode']
                assert change['before']['sha256'] == row['sha256']
                assert change['before']['git_blob'] == row['git_blob']
                _check_sync_bytes(raw, change['after'])
                refreshed_checked.add(row['path'])
                continue
            if row['path'] == fixture_change['path']:
                assert fixture_change['before']['sha256'] == row['sha256']
                assert fixture_change['before']['git_blob'] == row['git_blob']
                raw = _restore_fixture_change(raw, row['mode'], fixture_change)
                fixture_checked.add(row['path'])
            if row['path'] == lock_change['path']:
                assert lock_change['before']['sha256'] == row['sha256']
                assert lock_change['before']['git_blob'] == row['git_blob']
                raw = _restore_fixture_change(raw, row['mode'], lock_change)
                lock_fixture_checked.add(row['path'])
            if row['path'] == dispatch_change['path']:
                raw = _restore_fixture_change(raw, row['mode'], fixture_guard)
                raw = _restore_main_sync_dispatch(raw, row['mode'], dispatch_change)
            if row['path'] in changes:
                raw = _restore_approved_source_change(raw, row['mode'], changes[row['path']])
                amended.add(row['path'])
            elif row['path'] not in fixture_checked | lock_fixture_checked:
                checked += 1
            assert hashlib.sha256(raw).hexdigest() == row['sha256'], row['path']
            assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob']
    assert checked == 1084 and amended == set(_APPROVED_SOURCE_CHANGES)
    assert refreshed_checked == refreshed.keys()
    assert fixture_checked == {fixture_change['path']}
    assert lock_fixture_checked == {lock_change['path']}
    assert checked + len(lock_fixture_checked) + len(refreshed_checked) + len(fixture_checked) == 1090
    assert sync['source_accounting']['unchanged_nonstatus_files'] == checked + len(lock_fixture_checked)
    assert sync['source_accounting']['approved_portable_fixture_changes'] == len(fixture_checked)
    backup = sync['upstream_readme_backup']
    original = next(row for row in baseline if row['path'] == backup['original_baseline_path'])
    path = ROOT / backup['path']
    mode = path.lstat().st_mode
    assert stat.S_ISREG(mode)
    assert ('100755' if mode & 0o111 else '100644') == backup['mode'] == original['mode']
    _check_sync_bytes(path.read_bytes(), backup)
    assert backup['sha256'] == original['sha256'] and backup['git_blob'] == original['git_blob']
    sync_additions = {_MAIN_SYNC_PATH, backup['path']}
    assert len(sync_additions) == 2 and not sync_additions & _new_paths()
    # Admit only the reviewed S4.3 design documents; historical checks stay intact.
    s43_documents = {
        'docs/stage4-synthetic-custody.md': '9e6478a86c7213d4f5e8e3da24e919a5c30efcc8ca66153256457104412a079c',
        'docs/stage4-synthetic-custody-gates.json': '24f25a39b1492ae17376bd01c1eb2d795efe9990722b5e2a09fcd13f75fa313f',
    }
    for name, expected_sha256 in s43_documents.items():
        path = ROOT / name
        mode = path.lstat().st_mode
        assert stat.S_ISREG(mode) and not mode & 0o111
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256, name
    # Independently reviewed intrinsic codec slice: exact paths, never a package wildcard.
    s43_codec_files = {
        'recon_cockpit_synthetic/__init__.py': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'recon_cockpit_synthetic/contract.py': 'c2864df6eb91c56d85851af35eb9ddca036144cff1fd5063265250d2d1e3823a',
        'recon_cockpit_synthetic/codec.py': '6556ac856aaf3ab4376044dbfe66467aa75357b01b136412c3a56a7f8d847b74',
        'tests/test_secure_synthetic_custody_contract.py': 'b772e97f0caaea4ad7cff36eedc4269a45b6b283e197d587fc661d16d7004d73',
    }
    s43_codec_imports = {
        'recon_cockpit_synthetic/__init__.py': set(),
        'recon_cockpit_synthetic/contract.py': set(),
        'recon_cockpit_synthetic/codec.py': {'datetime', 'hashlib', 'json', 're', 'recon_cockpit_synthetic.contract'},
        'tests/test_secure_synthetic_custody_contract.py': {'json', 'pytest', 'recon_cockpit_synthetic.codec'},
    }
    forbidden = {'__import__', 'eval', 'exec', 'compile', 'globals', 'locals',
                 'vars', 'getattr', 'setattr', 'delattr', 'open', 'input'}
    for name, expected_sha256 in s43_codec_files.items():
        path = ROOT / name
        mode = path.lstat().st_mode
        assert stat.S_ISREG(mode) and not mode & 0o111
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_sha256, name
        tree = ast.parse(raw)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.level == 0 and all(alias.name != '*' for alias in node.names)
                imports.add(node.module)
            elif isinstance(node, ast.Name):
                assert node.id not in forbidden, (name, node.id)
            elif isinstance(node, ast.Attribute):
                assert node.attr not in forbidden, (name, node.attr)
        assert imports == s43_codec_imports[name], name
        for node in tree.body:
            if isinstance(node, ast.Assign):
                ast.literal_eval(node.value)  # No executable module-level initializers.
            elif isinstance(node, ast.Expr):
                assert isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
            else:
                assert isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
        if name == 'recon_cockpit_synthetic/__init__.py':
            assert raw == b''
    tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().rstrip('\0').split('\0'))
    assert tracked <= {row['path'] for row in baseline} | _new_paths() | sync_additions | s43_documents.keys() | s43_codec_files.keys()
    assert all((ROOT / name).is_file() for name in _new_paths())


def test_historical_contracts_and_profile_recipes_remain_pinned():
    historical = {row['path']: row for row in GATES['source_baseline']['complete_tracked_manifest']
                  if row['path'].startswith(('docs/stage4-', 'recon_cockpit/secure_agent/engagement_',
                                             'recon_cockpit/secure_agent/configurable_'))}
    assert historical
    assert 'recon_cockpit/secure_agent/engagement_dispatch_contract.py' in historical
    assert 'recon_cockpit/secure_agent/configurable_contract.py' in historical
    for name, row in historical.items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest() == row['sha256']
    from recon_cockpit.secure_agent import engagement_live_contract as live
    from test_secure_engagement_live_contract import opened, prepared
    from recon_cockpit.secure_agent import configurable_contract
    selected = opened()
    for slot, step in [('http_identify', 1), ('http_headers', 2)]:
        actual = prepared(slot, opened_value=selected)
        expected = configurable_contract.action(selected['scope'], step)
        assert actual['action'] == expected
        assert live.validate_prepared(actual) == actual


def test_exact_case_inventory_and_parent_mapping():
    cases = GATES['cases']
    assert len(cases) == len({r['id'] for r in cases}) == len({r['nodeid'] for r in cases}) == 288
    nodes = {r['nodeid'] for r in cases}
    files = sorted({node.split('::')[0] for node in nodes})
    result = subprocess.run([sys.executable, '-m', 'pytest', '-o', 'addopts=', '--collect-only', '-q', *files],
                            cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    collected = {line.strip() for line in result.stdout.splitlines() if line.startswith('tests/') and '::' in line}
    assert nodes <= collected
    new = {node for node in collected if node.split('::')[0] in GATES['change_allowlist']['confirmed_new_tests_and_helpers']}
    assert new == {r['nodeid'] for r in cases if r['group'] != 'accepted_integration_regression'}
    mappings = GATES['parent_mapping']
    assert len(mappings) == 26 and sum(r['physical_gate_required'] for r in mappings) == 18
    for parent in mappings:
        for case_id in parent['case_ids']:
            child = next(r for r in cases if r['id'] == case_id)
            assert parent['parent_id'] in child['parent_cases']
    for child in cases:
        for parent_id in child['parent_cases']:
            parent = next(r for r in mappings if r['parent_id'] == parent_id)
            assert child['id'] in parent['case_ids']


def test_inspection_and_runtime_imports_preserve_role_separation():
    from recon_cockpit.secure_agent import engagement_live_runtime as runtime
    assert runtime.SPEC['source_partitions'] == GATES['runtime_contract']['source_partitions']
    for leaf in ('headers_extra', 'nmap_extra', 'parser_extra', 'endpoint_extra'):
        names = set(runtime.SPEC['source_partitions']['common'] + runtime.SPEC['source_partitions'][leaf])
        assert not names & {'engagement_dispatch_store', 'engagement_live_broker_worker',
                            'engagement_live_approval_worker', 'engagement_live_audit'}
    # Inspectors may launch only the fixed parser. Imports of authority owners
    # cannot be hidden in helper functions or conditional import blocks.
    for name in ('recon_cockpit/secure_agent/engagement_live_evidence.py', 'scripts/engagement_live_inspect.py'):
        tree = ast.parse((ROOT/name).read_text())
        modules = {node.module.rsplit('.',1)[-1] for node in ast.walk(tree)
                   if isinstance(node, ast.ImportFrom) and node.module}
        assert not modules & {'engagement_dispatch_store', 'engagement_live_session',
            'engagement_live_broker', 'engagement_live_client', 'engagement_live_endpoint',
            'engagement_live_approval', 'engagement_live_launcher', 'sqlite3'}
