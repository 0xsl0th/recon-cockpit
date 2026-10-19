"""Sixteen parser/evidence gates and four parser-boundary native witnesses.

Fault workers are sealed, explicitly test-only mutations of the parser worker.
They are never presented as ordinary DNS/HTTP/TLS daemon output or a useful run.
"""

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from recon_cockpit.secure_agent import name_tls as diagnostic
from recon_cockpit.secure_agent import name_tls_context as context
from recon_cockpit.secure_agent import name_tls_evidence as evidence
from recon_cockpit.secure_agent import name_tls_parser as parser
from recon_cockpit.secure_agent import name_tls_parser_runtime as runtime
from recon_cockpit.secure_agent import name_tls_python_runtime as sources
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def owned_only():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for isolated name/TLS parser gates")
    assert sys.platform == "linux" and os.geteuid() != 0


@pytest.fixture(scope="module")
def native_bundles(tmp_path_factory):
    cache = {}
    def obtain(configuration):
        if configuration not in cache:
            directory = tmp_path_factory.mktemp("name-tls-parser-" + configuration) / "trial"
            report = diagnostic.run_trial(directory, configuration=configuration, case="O4",
                execute=True, unattended_owned_lab_test=True)
            assert report["case_passed"] and report["useful_task_completed"], report
            manifest = json.loads((directory / "manifest.json").read_bytes())
            results = {json.loads(path.read_bytes())["name_tls_service"]["slot"]: json.loads(path.read_bytes())
                       for path in directory.glob("result-*.json")}
            assert set(results) == {"dns_1", "http", "tls"}
            cache[configuration] = directory, manifest, results, report
        return cache[configuration]
    return obtain


def raw_input(result):
    return base64.b64decode(result["name_tls_service"]["parser_input_base64"], validate=True)


def changed_input(raw, change):
    header, streams = parser.decode_input(raw)
    change(streams)
    return parser.encode_input(header["operation"], configuration=header["configuration"], case=header["case"],
        **streams, exit_code=header["exit_code"], stop_reason=header["stop_reason"], truncated=header["truncated"])


def record(tmp_path, record_property, gate_id, payload):
    path = tmp_path / "native-gate.json"
    path.write_text(json.dumps({"schema_version": "1", "gate_id": gate_id, **payload}, sort_keys=True))
    path.chmod(0o600)
    record_property("gate_id", gate_id)
    record_property("evidence_sha256", hashlib.sha256(path.read_bytes()).hexdigest())
    record_property("useful_daemon_claim", False)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("operation", ("dns", "http", "tls"))
def test_native_wire_disagreement(tmp_path, record_property, native_bundles, configuration, operation):
    _, manifest, results, _ = native_bundles(configuration)
    result = results["dns_1" if operation == "dns" else operation]
    raw = raw_input(result)
    def mutate(streams):
        if operation == "dns":
            address = b"10.77.0.10" if configuration == "A" else b"172.23.0.10"
            assert address in streams["stdout"]
            streams["stdout"] = streams["stdout"].replace(address, address[:-2] + b"99", 1)
        elif operation == "http":
            assert b"HarborDesk" in streams["stdout"]
            streams["stdout"] = streams["stdout"].replace(b"HarborDesk", b"HarborDask", 1)
        else:
            server = bytearray(streams["original_response"])
            assert server[0] == 22 and server[5] == 2
            cipher_offset = 44 + server[43]
            assert server[cipher_offset:cipher_offset + 2] == b"\x13\x02"
            server[cipher_offset + 1] = 1
            for name in ("original_response", "proposed_response", "delivered_response"):
                streams[name] = bytes(server)
    mutated = changed_input(raw, mutate)
    with pytest.raises(ValueError, match="name_tls_invalid_native_observation"):
        runtime.parse_isolated_operation(mutated, bundle=manifest["runtime"])
    record(tmp_path, record_property, f"parser_evidence/{configuration}/{operation}_native_wire_disagreement",
           {"original_input_sha256": hashlib.sha256(raw).hexdigest(), "mutated_input_base64": base64.b64encode(mutated).decode("ascii"),
            "isolated_parser_refused": True})


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_parser_input_cap(tmp_path, monkeypatch, record_property, native_bundles, configuration):
    _, manifest, _, _ = native_bundles(configuration)
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail("oversized input reached parser launch")
    monkeypatch.setattr(runtime, "_capture", forbidden)
    monkeypatch.setattr(sources, "snapshot_sources", forbidden)
    with pytest.raises(ValueError, match="name_tls_parser_input_limit"):
        runtime.parse_isolated_operation(b"x" * (parser.MAX_INPUT_BYTES + 1), bundle=manifest["runtime"])
    assert calls == []
    record(tmp_path, record_property, f"parser_evidence/{configuration}/parser_input_cap",
           {"input_bytes": parser.MAX_INPUT_BYTES + 1, "parser_launches": 0, "source_staging_calls": 0})


@contextmanager
def staged_fault(bundle, fault, control):
    descriptors = sources.snapshot_sources(bundle, runtime.SOURCE_MODULES, control)
    source = Path(runtime.__file__).with_name("name_tls_parser_worker.py").read_bytes()
    needle = b"        raw = sys.stdin.buffer.read(parser.MAX_INPUT_BYTES + 1)\n"
    assert source.count(needle) == 1
    injection = (b"        sys.stdout.buffer.write(b'x' * (parser.MAX_OUTPUT_BYTES + 1))\n        sys.stdout.buffer.flush()\n        return 0\n"
                 if fault == "parser_output_cap" else b"        import time\n        time.sleep(10)\n")
    altered = source.replace(needle, needle + injection)
    destination = "/app/recon_cockpit/secure_agent/name_tls_parser_worker.py"
    descriptor = os.memfd_create("name-tls-declared-parser-fault", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        assert os.write(descriptor, altered) == len(altered)
        os.lseek(descriptor, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        assert fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == seals
        os.close(descriptors[destination])
        descriptors[destination] = descriptor
        yield descriptors, {"test_only_fault": fault, "original_worker_sha256": hashlib.sha256(source).hexdigest(),
                            "sealed_fault_worker_sha256": hashlib.sha256(altered).hexdigest(), "seals": seals}
    finally:
        for current in set(descriptors.values()) | {descriptor}:
            try:
                os.close(current)
            except OSError:
                pass


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("fault", ("parser_output_cap", "parser_wall_deadline"))
def test_sealed_fault_worker(tmp_path, monkeypatch, record_property, native_bundles, configuration, fault):
    _, manifest, results, _ = native_bundles(configuration)
    raw = raw_input(results["dns_1"])
    bootstrap = runtime._runtime_files("/usr/bin/python3", None, control=ExecutionControl(time.monotonic() + 10))
    processes, observed = [], []
    original_popen, original_observe = runtime.subprocess.Popen, runtime._observe_process
    def launch(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        processes.append(process)
        return process
    def observe(*args, **kwargs):
        result = original_observe(*args, **kwargs)
        observed.append(result)
        return result
    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(runtime, "_observe_process", observe)
    with staged_fault(manifest["runtime"], fault, ExecutionControl(time.monotonic() + 5)) as (descriptors, receipt):
        info_read, info_write = os.pipe2(os.O_CLOEXEC)
        started = time.monotonic()
        control = ExecutionControl(started + 1)
        try:
            if fault == "parser_output_cap":
                with pytest.raises(ValueError, match="name_tls_parser_output_limit"):
                    runtime._capture(runtime._command(bootstrap, descriptors, info_write), raw, control, descriptors, info_read, info_write)
            else:
                with pytest.raises(ExecutionStopped) as stopped:
                    runtime._capture(runtime._command(bootstrap, descriptors, info_write), raw, control, descriptors, info_read, info_write)
                assert stopped.value.reason == "session_timeout"
                assert time.monotonic() - started >= .9
        finally:
            os.close(info_read)
    assert len(processes) == len(observed) == 1
    assert processes[0].poll() is not None
    assert not Path("/proc", str(observed[0]["payload_pid"])).exists()
    elapsed = time.monotonic() - started
    assert elapsed <= 3.1
    record(tmp_path, record_property, f"parser_evidence/{configuration}/{fault}",
           {**receipt, "parent_observation": observed[0], "wrapper_pid": processes[0].pid,
            "returncode": processes[0].returncode, "process_reaped": True, "elapsed_ms": round(elapsed * 1000)})


def hashes(directory):
    return {path.name: [hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode, path.stat().st_mtime_ns]
            for path in directory.iterdir()}


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_saved_raw_artifact_tamper(tmp_path, record_property, native_bundles, configuration):
    directory, _, _, _ = native_bundles(configuration)
    original = hashes(directory)
    copy = tmp_path / "tampered"
    shutil.copytree(directory, copy)
    path = copy / "result-1.json"
    result = json.loads(path.read_bytes())
    result["raw_output_base64"] = base64.b64encode(base64.b64decode(result["raw_output_base64"]) + b"x").decode("ascii")
    path.write_text(json.dumps(result, sort_keys=True))
    with pytest.raises(ValueError):
        evidence.inspect_trial(copy)
    command = subprocess.run([sys.executable, "scripts/name_tls_native.py", "inspect", str(copy)], capture_output=True, timeout=45)
    assert command.returncode != 0
    assert hashes(directory) == original
    record(tmp_path, record_property, f"parser_evidence/{configuration}/saved_raw_artifact_tamper",
           {"original_artifacts": original, "changed_artifact": "result-1.json", "cli_returncode": command.returncode,
            "cli_stdout_base64": base64.b64encode(command.stdout).decode("ascii"),
            "cli_stderr_base64": base64.b64encode(command.stderr).decode("ascii")})


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_python_cli_read_only_replay(tmp_path, monkeypatch, record_property, native_bundles, configuration):
    directory, _, _, report = native_bundles(configuration)
    original = hashes(directory)
    from recon_cockpit.secure_agent.name_tls_lab import NameTLSLab
    monkeypatch.setattr(NameTLSLab, "start", lambda *_a, **_kw: pytest.fail("replay recreated an owner"))
    assert evidence.inspect_trial(directory) == report
    command = subprocess.run([sys.executable, "scripts/name_tls_native.py", "inspect", str(directory)], capture_output=True, timeout=45)
    assert command.returncode == 0 and json.loads(command.stdout) == report
    assert hashes(directory) == original
    record(tmp_path, record_property, f"parser_evidence/{configuration}/python_cli_read_only_replay",
           {"artifacts": original, "actions": 3, "cli_returncode": command.returncode,
            "report_sha256": hashlib.sha256(evidence._encode(report)).hexdigest()})


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("witness", ("server_key_and_daemon_runtime_absent", "parser_network_filesystem_and_process_witnesses"))
def test_parser_architecture_witnesses(tmp_path, record_property, native_bundles, configuration, witness):
    _, manifest, results, _ = native_bundles(configuration)
    raw = raw_input(results["dns_1"])
    parsed, receipt = runtime.parse_isolated_operation(raw, bundle=manifest["runtime"], return_receipt=True)
    context.validate_parser_receipt(receipt, parsed, raw)
    assert receipt["readiness"]["runtime_absence_verified"] is True
    assert all(receipt["readiness"]["boundary_checks"].values())
    assert receipt["parent_observation"]["retained_descriptors"] == [0, 1, 2]
    case = "parser/" + witness if witness == "server_key_and_daemon_runtime_absent" else witness
    record(tmp_path, record_property, f"architecture/{configuration}/native_process_runtime_and_mount/{case}",
           {"parser_receipt": receipt, "input_sha256": hashlib.sha256(raw).hexdigest()})
