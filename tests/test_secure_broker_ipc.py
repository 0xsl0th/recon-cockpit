"""Portable framed-dialogue tests with real bounded subprocesses, no API calls."""

import io
import os
import select
import signal
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import broker_ipc as ipc
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped


CHILD = '''
import os,sys,time
def exact(n):
    data=b''
    while len(data)<n:
        part=sys.stdin.buffer.read(n-len(data))
        if not part: raise ValueError('truncated test input')
        data+=part
    return data
def read():
    count=int.from_bytes(exact(4),'big')
    kind=exact(1)[0]
    return kind,exact(count-1)
def send(kind,payload):
    data=(len(payload)+1).to_bytes(4,'big')+bytes([kind])+payload
    os.write(1,data)
'''


def command(code):
    return [sys.executable, "-I", "-S", "-c", CHILD + code]


def control(seconds=5, cancelled=None):
    return ExecutionControl(time.monotonic() + seconds, cancelled)


@pytest.fixture
def processes(monkeypatch):
    children = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    yield children
    alive = [child for child in children if child.poll() is None]
    try:
        for child in alive:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=2)
    finally:
        assert not alive, "production must reap its child before returning"


@pytest.mark.parametrize("kind", [ipc.INIT, ipc.REQUEST, ipc.RESPONSE, ipc.RESULT])
def test_frames_include_kind_in_length_and_accept_inclusive_payload_limit(kind):
    payload = b"x" * ipc.LIMITS[kind]
    framed = ipc.frame(kind, payload)
    assert int.from_bytes(framed[:4], "big") == len(payload) + 1
    assert ipc.read_frame(io.BytesIO(framed), kind) == payload
    with pytest.raises(ipc.IPCError):
        ipc.frame(kind, payload + b"x")


@pytest.mark.parametrize("raw", [b"", b"\0", b"\0\0\0\0", b"\0\0\0\x01\x04",
                                 b"\0\0\0\x04\x02x", b"\xff\xff\xff\xff"])
def test_frame_reader_refuses_wrong_kind_truncation_and_oversized_headers(raw):
    with pytest.raises(ipc.IPCError):
        ipc.read_frame(io.BytesIO(raw), ipc.REQUEST)


def test_frame_reader_handles_one_byte_reads_without_consuming_next_frame():
    class Fragmented(io.BytesIO):
        def read(self, count):
            return super().read(min(count, 1))

    stream = Fragmented(ipc.frame(ipc.REQUEST, b"one") + ipc.frame(ipc.RESULT, b"two"))
    assert ipc.read_frame(stream, ipc.REQUEST) == b"one"
    assert ipc.read_frame(stream, ipc.RESULT) == b"two"


def test_cleanup_reaps_zombie_leader_before_signalling_but_still_kills_descendants(monkeypatch):
    # Model Darwin's EPERM when a process group contains only an unreaped
    # zombie. A live descendant still needs a group signal after leader reap.
    class Process:
        pid = 123
        zombie = True
        waited = False
        stdin, stdout, stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()

        def poll(self):
            self.zombie = False
            return 0

        def wait(self, timeout):
            self.waited = True
            return 0

    process = Process()
    signals = []

    def killpg(pid, sig):
        if process.zombie:
            raise PermissionError("unreaped zombie group")
        signals.append((pid, sig))

    monkeypatch.setattr(os, "killpg", killpg)
    ipc._kill_and_reap(process, failed=True)
    assert signals == [(process.pid, signal.SIGKILL)]
    assert process.waited
    assert all(stream.closed for stream in (process.stdin, process.stdout, process.stderr))


def test_fragmented_request_and_result_with_maximum_nonblocking_response(processes):
    calls = []
    code = '''
assert read()==(1,b'init')
for byte in b'\\x00\\x00\\x00\\x04\\x02req':
    os.write(1,bytes([byte])); time.sleep(0.001)
kind,response=read()
assert kind==3 and response==b'x'*65536
assert sys.stdin.buffer.read(1)==b''
for byte in b'\\x00\\x00\\x00\\x07\\x04result':
    os.write(1,bytes([byte])); time.sleep(0.001)
'''

    def exchange(request, *, control):
        calls.append(request)
        control.check()
        return b"x" * 65536

    assert ipc.supervise(command(code), b"init", exchange, control=control()) == b"result"
    assert calls == [b"req"]
    assert len(processes) == 1 and processes[0].returncode == 0


@pytest.mark.parametrize("payload", [
    b"", b"\0\0", b"\0\0\0\0", b"\0\0\0\x03\x02x",
    ipc.frame(ipc.RESULT, b"premature"),
    ipc.frame(ipc.REQUEST, b"one") + ipc.frame(ipc.REQUEST, b"two"),
    (ipc.MAX_REQUEST_BYTES + 2).to_bytes(4, "big") + b"\x02",
])
def test_invalid_first_frame_never_dispatches_exchange(processes, payload):
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(f"read(); os.write(1,{payload!r})"), b"init",
                      lambda *_a, **_k: pytest.fail("invalid request must not be exchanged"), control=control())
    assert processes[0].poll() is not None


@pytest.mark.parametrize("tail", [
    b"", b"\0\0", ipc.frame(ipc.REQUEST, b"again"),
    ipc.frame(ipc.RESULT, b"valid") + b"x",
    ipc.frame(ipc.RESULT, b"valid") + ipc.frame(ipc.RESULT, b"again"),
    (ipc.MAX_RESULT_BYTES + 2).to_bytes(4, "big") + b"\x04",
])
def test_result_order_completeness_and_trailing_bytes_are_enforced(processes, tail):
    calls = []

    def exchange(request, *, control):
        calls.append(request)
        return b"response"

    code = f"read(); send(2,b'request'); read(); os.write(1,{tail!r})"
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(code), b"init", exchange, control=control())
    assert calls == [b"request"]
    assert processes[0].poll() is not None


def test_stderr_flood_is_bounded_and_never_echoed(processes):
    code = "read(); os.write(2,b'PRIVATE-DIAGNOSTIC'*1000); time.sleep(30)"
    with pytest.raises(ipc.IPCError, match="^ipc_output_limit$"):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: b"", control=control())
    assert processes[0].poll() is not None


def test_valid_result_followed_by_failed_exit_is_not_success(processes):
    code = "read(); send(2,b'request'); read(); send(4,b'result'); sys.exit(78)"
    with pytest.raises(ipc.IPCError, match="^ipc_process_failed$"):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: b"response", control=control())


@pytest.mark.parametrize("code", [
    "time.sleep(30)",
    "read(); send(2,b'request'); time.sleep(30)",
    "read(); send(2,b'request'); read(); send(4,b'result'); time.sleep(30)",
    "read(); send(2,b'request'); read(); send(4,b'result'); os.close(1); os.close(2); time.sleep(30)",
])
def test_deadline_covers_blocked_input_response_missing_eof_and_exit(processes, code):
    with pytest.raises(ExecutionStopped, match="session_timeout"):
        ipc.supervise(command(code), b"x" * ipc.MAX_INIT_BYTES,
                      lambda *_a, **_k: b"x" * ipc.MAX_RESPONSE_BYTES, control=control(0.2))
    assert processes[0].poll() is not None


def test_cancellation_while_large_response_cannot_be_consumed_reaps_child(processes):
    cancelled = threading.Event()
    timer = threading.Timer(0.15, cancelled.set)
    timer.start()
    try:
        with pytest.raises(ExecutionStopped, match="session_cancelled"):
            ipc.supervise(command("read(); send(2,b'request'); time.sleep(30)"), b"init",
                          lambda *_a, **_k: b"x" * 65536, control=control(cancelled=cancelled))
    finally:
        timer.cancel()
        timer.join(timeout=1)
    assert processes[0].poll() is not None


def test_cancelled_control_never_creates_a_process(monkeypatch):
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("must not launch"))
    with pytest.raises(ExecutionStopped):
        ipc.supervise(command("pass"), b"init", lambda *_a, **_k: b"", control=control(cancelled=cancelled))


def test_exchange_audit_failure_is_preserved_after_child_cleanup(processes):
    failure = AuditUnavailable("private audit details")

    def exchange(*_args, **_kwargs):
        raise failure

    with pytest.raises(AuditUnavailable) as error:
        ipc.supervise(command("read(); send(2,b'request'); read()"), b"init", exchange, control=control())
    assert error.value is failure
    assert processes[0].poll() is not None


def test_callback_cancellation_prevents_response_release(processes):
    cancelled = threading.Event()

    def exchange(*_args, **_kwargs):
        cancelled.set()
        return b"response"

    code = "read(); send(2,b'request'); read(); sys.exit(42)"
    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        ipc.supervise(command(code), b"init", exchange, control=control(cancelled=cancelled))
    assert processes[0].returncode != 42


def test_cancellation_kills_descendant_holding_output_after_direct_child_exits(processes, monkeypatch):
    readers = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        readers.append(os.dup(child.stdout.fileno()))
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    holder = [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"]
    code = f"read(); send(2,b'request'); read(); send(4,b'result'); import subprocess; subprocess.Popen({holder!r}); os._exit(0)"
    holder_closed = False
    try:
        with pytest.raises(ExecutionStopped, match="session_timeout"):
            ipc.supervise(command(code), b"init", lambda *_a, **_k: b"response", control=control(0.3))
        assert processes[0].returncode == 0
        assert select.select(readers, [], [], 1)[0]
        assert os.read(readers[0], 1) == b""
        holder_closed = True
    finally:
        try:
            if not holder_closed:
                for child in processes:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        finally:
            for reader in readers:
                os.close(reader)
