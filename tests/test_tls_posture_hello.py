"""The shared ClientHello grammar needs no owner, keys or networking runtime."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from recon_cockpit.secure_agent import tls_posture_hello as grammar
from recon_cockpit.secure_agent import tls_posture_diagnostic_fixture as fixture
from recon_cockpit.secure_agent import tls_posture_mediated_trace as trace
from test_tls_posture_diagnostic_fixture import hello


def test_owner_and_replay_use_one_grammar_with_unchanged_wire_constants():
    assert fixture.validate_client_hello is trace.validate_client_hello is grammar.validate_client_hello
    assert fixture._Reader is grammar._Reader
    assert grammar.VERSIONS == {version: (wire, cipher)
                               for version, (wire, _, cipher) in fixture.VERSIONS.items()}
    assert grammar.TLS_NAME == fixture.public.TLS_NAME == "harbordesk.test"
    assert grammar.MAX_CLIENT_HELLO == fixture.MAX_CLIENT_HELLO == 4096
    assert grammar.COOKIE == fixture.COOKIE == b"T02-HRR-ONLY"


@pytest.mark.parametrize("version", grammar.VERSIONS)
def test_replay_modules_load_and_validate_without_owner_or_key_files(tmp_path, version):
    package = tmp_path / "pure_replay"
    package.mkdir()
    (package / "__init__.py").write_text("")
    source = Path(grammar.__file__).parent
    for name in ("tls_posture_hello", "tls_posture_mediator", "tls_posture_diagnostic_trace",
                 "tls_posture_mediated_trace"):
        (package / (name + ".py")).write_bytes((source / (name + ".py")).read_bytes())
    code = """
import json, sys
sys.path.insert(0, sys.argv[1])
from pure_replay import tls_posture_mediated_trace as replay
from pure_replay import tls_posture_hello as grammar
value = json.loads(sys.stdin.read())
raw = bytes.fromhex(value['raw_hex'])
result = replay.validate_client_hello(raw, value['version'])
try:
    replay.validate_client_hello(raw + b'x', value['version'])
except ValueError:
    pass
else:
    raise AssertionError('trailing input accepted')
assert replay.validate_client_hello is grammar.validate_client_hello
assert not any(name == 'ssl' or name == 'socket' or 'fixture' in name or 'material' in name
               or 'owner' in name for name in sys.modules)
print(json.dumps(result, sort_keys=True))
"""
    raw = hello(version)
    result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(tmp_path)],
                            input=json.dumps({"raw_hex": raw.hex(), "version": version}),
                            text=True, capture_output=True, timeout=10, check=True)
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "version": version, "session_id_hex": "", "cipher": grammar.VERSIONS[version][1],
        "random_hex": (b"r" * 32).hex(),
        "extension_types": [0, 10, 13, 43, 51] if version == "tls1_3" else [0, 10],
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_owned_diagnostic_mounts_shared_grammar_for_standalone_owner(monkeypatch):
    from recon_cockpit.secure_agent import tls_posture_diagnostic as diagnostic

    monkeypatch.setattr(diagnostic.OwnedLab, "_owner_command", lambda *args:
                        ["bwrap", "--remount-ro", "/", "/app/owned_lab_worker.py"])
    lab = diagnostic.DiagnosticLab("modern", "tls1_3")
    command = lab._owner_command("unused", [], 11)
    destination = command.index("/app/tls_posture_hello.py")
    assert command[destination - 2] == "--ro-bind"
    assert command[destination - 1] == grammar.__file__
    assert command[-1] == "/app/tls_posture_diagnostic_fixture.py"
