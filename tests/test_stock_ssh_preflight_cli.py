"""Private metadata receipts do not authorize daemon or authentication work."""

import importlib.util
import json
from pathlib import Path
import socket
import stat

import pytest


@pytest.fixture
def cli(monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'scripts/inspect_stock_ssh_runtime.py'
    entry = importlib.util.spec_from_file_location('stock_ssh_preflight_cli', path)
    module = importlib.util.module_from_spec(entry)
    entry.loader.exec_module(module)
    monkeypatch.setattr(socket, 'socket', lambda *_a, **_k: pytest.fail('preflight created a socket'))
    return module


def args(tmp_path, *extra):
    tmp_path.chmod(0o700)
    return ['--configuration', 'A', '--case', 'O1', '--output', str(tmp_path / 'receipt.json'), *extra]


def test_receipt_is_private_and_records_no_execution_or_authentication(cli, tmp_path, monkeypatch):
    seen, manifest = [], {'test': True}
    monkeypatch.setattr(cli.runtime, 'inspect_runtime', lambda config, case, control:
                        seen.append((config, case, control)) or manifest)
    monkeypatch.setattr(cli.runtime, 'verify_current', lambda value, control: seen.append((value, control)))
    monkeypatch.setattr(cli.runtime, 'manifest_digest', lambda value: 'a' * 64)
    assert cli.main(args(tmp_path)) == 0
    path = tmp_path / 'receipt.json'
    value = json.loads(path.read_text())
    assert value['status'] == 'runtime_inspected' and value['preflight_only'] is True
    assert value['service_execution_verified'] is value['authority_issued'] is False
    assert all(value[key] == 0 for key in ('native_services_started', 'helper_executions_performed',
        'authentication_attempts', 'keys_generated', 'tool_actions_executed',
        'actual_provider_calls', 'actual_cost_microusd'))
    assert value['runtime_manifest'] == manifest and value['runtime_sha256'] == 'a' * 64
    assert seen[0][:2] == ('A', 'O1') and seen[1] == (manifest, seen[0][2])
    assert 0 < seen[0][2].remaining() <= 15
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize('extra', [['--execute'], ['--sshd', '/tmp/sshd'], ['--user', 'root'],
    ['--key', '/tmp/key'], ['--target', '127.0.0.1'], ['--configuration', 'host'],
    ['--case', 'O1;cmd'], ['--approval', 'yes'], ['--config', 'B']])
def test_execution_or_unreviewed_options_refuse_before_output(cli, tmp_path, monkeypatch, extra):
    monkeypatch.setattr(cli.runtime, 'inspect_runtime', lambda *_: pytest.fail('invalid CLI reached runtime'))
    with pytest.raises(SystemExit) as error: cli.main(args(tmp_path, *extra))
    assert error.value.code == 2 and not list(tmp_path.iterdir())


@pytest.mark.parametrize('kind', ['existing', 'file_symlink', 'parent_symlink', 'public_parent'])
def test_output_refusal_precedes_inspection_and_preserves_existing_data(cli, tmp_path, monkeypatch, kind):
    monkeypatch.setattr(cli.runtime, 'inspect_runtime', lambda *_: pytest.fail('unsafe output reached runtime'))
    selected = args(tmp_path)
    original = tmp_path / 'original'; original.write_bytes(b'preserve')
    output = tmp_path / 'receipt.json'
    if kind == 'existing': output.write_bytes(b'preserve')
    elif kind == 'file_symlink': output.symlink_to(original)
    elif kind == 'parent_symlink':
        link = tmp_path / 'link'; link.symlink_to(tmp_path, target_is_directory=True)
        selected[-1] = str(link / 'receipt.json')
    else: tmp_path.chmod(0o755)
    assert cli.main(selected) == 2 and original.read_bytes() == b'preserve'
    if kind in ('existing', 'file_symlink'): assert output.read_bytes() == b'preserve'
    else: assert not output.exists()


def test_runtime_change_retains_failure_without_readiness_claim(cli, tmp_path, monkeypatch):
    monkeypatch.setattr(cli.runtime, 'inspect_runtime', lambda *_: {'test': True})
    def changed(*_): raise ValueError('changed runtime')
    monkeypatch.setattr(cli.runtime, 'verify_current', changed)
    assert cli.main(args(tmp_path)) == 2
    value = json.loads((tmp_path / 'receipt.json').read_text())
    assert value['status'] == 'inspection_failed' and value['failure_type'] == 'ValueError'
    assert 'runtime_manifest' not in value and 'runtime_sha256' not in value
    assert value['service_execution_verified'] is value['authority_issued'] is False
