"""Portable persistent IPC adversarial tests using real local subprocesses."""

import io
import json
import os
import select
import signal
import subprocess
import sys
import threading
import time

import pytest

from recon_cockpit.secure_agent import coordinator_ipc as ipc
from recon_cockpit.secure_agent.audit import AuditUnavailable
from recon_cockpit.secure_agent.execution import ExecutionControl, ExecutionStopped


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")


READY = encode({"schema_version": "1", "boundary_checks": dict.fromkeys(ipc.BOUNDARY_NAMES, True)})
STOP = encode({"stop": True})
CONTINUE = encode({"stop": False})
CHILD = '''
import json,os,sys,time
def exact(n):
    result=b''
    while len(result)<n:
        part=sys.stdin.buffer.read(n-len(result))
        if not part: raise ValueError('truncated test input')
        result+=part
    return result
def read():
    n=int.from_bytes(exact(4),'big')
    return exact(1)[0],exact(n-1)
def frame(kind,payload):
    return (len(payload)+1).to_bytes(4,'big')+bytes([kind])+payload
def send(kind,payload):
    data=frame(kind,payload)
    while data:
        data=data[os.write(1,data):]
'''


def command(code):
    return [sys.executable, "-I", "-S", "-c", CHILD + f"\nREADY={READY!r}\n" + code]


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
        assert not alive, "supervisor must reap before returning"


@pytest.mark.parametrize("kind", ipc.LIMITS)
def test_frame_limits_and_fragmented_reads(kind):
    class Fragmented(io.BytesIO):
        def read(self, count):
            return super().read(min(count, 1))

    payload = b"x" * ipc.LIMITS[kind]
    framed = ipc.frame(kind, payload)
    assert int.from_bytes(framed[:4], "big") == len(payload) + 1
    stream = Fragmented(framed + ipc.frame(ipc.RESULT, b"next"))
    assert ipc.read_frame(stream, kind) == payload
    assert ipc.read_frame(stream, ipc.RESULT) == b"next"
    with pytest.raises(ipc.IPCError):
        ipc.frame(kind, payload + b"x")


@pytest.mark.parametrize("raw", [b"", b"\0", b"\0\0\0\0", b"\0\0\0\x04\x02x",
                                 b"\xff\xff\xff\xff", ipc.frame(ipc.RESULT, b"wrong")])
def test_invalid_frame_reader_inputs(raw):
    with pytest.raises(ipc.IPCError):
        ipc.read_frame(io.BytesIO(raw), ipc.REQUEST)


def test_fragmented_persistent_dialogue_and_large_response(processes):
    calls = []
    code = '''
assert read()==(1,b'init')
for byte in frame(5,READY):
    os.write(1,bytes([byte]))
for n in range(3):
    for byte in frame(2,str(n).encode()):
        os.write(1,bytes([byte])); time.sleep(0.001)
    kind,raw=read()
    response=json.loads(raw)
    assert kind==3 and response['body']=='x'*12000
    assert response['stop']==(n==2)
assert sys.stdin.buffer.read(1)==b''
send(4,b'closed')
'''

    def exchange(request, *, control):
        control.check()
        calls.append(request)
        return encode({"stop": len(calls) == 3, "body": "x" * 12000})

    assert ipc.supervise(command(code), b"init", exchange, control=control()) == b"closed"
    assert calls == [b"0", b"1", b"2"]
    assert processes[0].returncode == 0


def test_ready_and_first_request_may_share_one_read(processes):
    code = "read(); os.write(1,frame(5,READY)+frame(2,b'request')); read(); send(4,b'closed')"
    assert ipc.supervise(command(code), b"init", lambda *_a, **_k: STOP, control=control()) == b"closed"


@pytest.mark.parametrize("ready", [
    b"invalid", b"[]", b'{"schema_version":"1","schema_version":"1","boundary_checks":{}}',
    encode({"schema_version": "2", "boundary_checks": dict.fromkeys(ipc.BOUNDARY_NAMES, True)}),
    encode({"schema_version": "1", "boundary_checks": dict.fromkeys(ipc.BOUNDARY_NAMES, 1)}),
    encode({"schema_version": "1", "boundary_checks": {}}),
])
def test_unverified_ready_never_reaches_authority(processes, ready):
    code = f"read(); send(5,{ready!r}); send(2,b'request')"
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: pytest.fail("no authority call"), control=control())


@pytest.mark.parametrize("wire", [
    b"", b"\0\0", ipc.frame(ipc.REQUEST, b"early"), ipc.frame(ipc.RESULT, b"early"),
    ipc.frame(ipc.READY, READY) + ipc.frame(ipc.REQUEST, b"one") + ipc.frame(ipc.REQUEST, b"two"),
    ipc.frame(ipc.READY, READY) + (ipc.MAX_REQUEST_BYTES + 2).to_bytes(4, "big") + b"\x02",
    ipc.frame(ipc.READY, READY) + b"\0\0\0\x04\x02x",
])
def test_missing_out_of_order_and_pipelined_frames_are_rejected(processes, wire):
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(f"read(); os.write(1,{wire!r})"), b"init",
                      lambda *_a, **_k: pytest.fail("no authority call"), control=control())


@pytest.mark.parametrize("tail", [
    b"", b"\0\0", ipc.frame(ipc.REQUEST, b"after stop"),
    ipc.frame(ipc.RESULT, b"closed") + b"x",
    ipc.frame(ipc.RESULT, b"closed") + ipc.frame(ipc.RESULT, b"again"),
    (ipc.MAX_RESULT_BYTES + 2).to_bytes(4, "big") + b"\x04",
])
def test_stop_requires_one_complete_final_result_and_clean_eof(processes, tail):
    calls = []

    def exchange(request, *, control):
        calls.append(request)
        return STOP

    code = f"read(); send(5,READY); send(2,b'request'); read(); os.write(1,{tail!r})"
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(code), b"init", exchange, control=control())
    assert calls == [b"request"]


def test_result_without_host_stop_is_rejected(processes):
    code = "read(); send(5,READY); send(2,b'request'); read(); send(4,b'closed')"
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: CONTINUE, control=control())


@pytest.mark.parametrize("stop", [True, False])
def test_hard_request_limit_cannot_be_reset_by_worker(processes, stop):
    calls = []
    code = '''
read(); send(5,READY)
for n in range(18):
    send(2,str(n).encode())
    kind,raw=read()
    if json.loads(raw)['stop']:
        send(4,b'closed'); sys.exit(0)
'''

    def exchange(request, *, control):
        calls.append(request)
        return STOP if stop and len(calls) == 17 else CONTINUE

    if stop:
        assert ipc.supervise(command(code), b"init", exchange, control=control()) == b"closed"
    else:
        with pytest.raises(ipc.IPCError, match="ipc_request_limit"):
            ipc.supervise(command(code), b"init", exchange, control=control())
    assert len(calls) == 17


@pytest.mark.parametrize("response", [b"invalid", b"{}", b'{"stop":1}', b'{"stop":true,"stop":false}',
                                      b"x" * (ipc.MAX_RESPONSE_BYTES + 1), "not bytes"])
def test_invalid_trusted_responses_fail_closed(processes, response):
    code = "read(); send(5,READY); send(2,b'request'); read()"
    with pytest.raises(ipc.IPCError):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: response, control=control())


def test_stderr_and_failed_exit_are_static_errors(processes):
    with pytest.raises(ipc.IPCError, match="^ipc_output_limit$"):
        ipc.supervise(command("read(); os.write(2,b'PRIVATE-DIAGNOSTIC'*1000); time.sleep(30)"), b"init",
                      lambda *_a, **_k: STOP, control=control())
    code = "read(); send(5,READY); send(2,b'request'); read(); send(4,b'closed'); sys.exit(78)"
    with pytest.raises(ipc.IPCError, match="^ipc_process_failed$"):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: STOP, control=control())


@pytest.mark.parametrize("code", [
    "time.sleep(30)",
    "read(); send(5,READY); send(2,b'request'); time.sleep(30)",
    "read(); send(5,READY); send(2,b'request'); read(); send(4,b'closed'); time.sleep(30)",
    "read(); send(5,READY); send(2,b'request'); read(); send(4,b'closed'); os.close(1); os.close(2); time.sleep(30)",
])
def test_shared_deadline_covers_input_missing_eof_and_exit(processes, code):
    response = encode({"stop": True, "body": "x" * 12000})
    with pytest.raises(ExecutionStopped, match="session_timeout"):
        ipc.supervise(command(code), b"init", lambda *_a, **_k: response, control=control(0.2))
    assert processes[0].poll() is not None


def test_cancellation_while_response_is_unread_reaps_worker(processes):
    cancelled = threading.Event()
    timer = threading.Timer(0.15, cancelled.set)
    timer.start()
    try:
        with pytest.raises(ExecutionStopped, match="session_cancelled"):
            ipc.supervise(command("read(); send(5,READY); send(2,b'request'); time.sleep(30)"), b"init",
                          lambda *_a, **_k: encode({"stop": True, "body": "x" * 12000}),
                          control=control(cancelled=cancelled))
    finally:
        timer.cancel()
        timer.join(timeout=1)
    assert processes[0].poll() is not None


def test_audit_failure_and_callback_cancellation_are_preserved(processes):
    failure = AuditUnavailable("private audit details")

    def failed(*_a, **_k):
        raise failure

    code = "read(); send(5,READY); send(2,b'request'); read(); sys.exit(42)"
    with pytest.raises(AuditUnavailable) as error:
        ipc.supervise(command(code), b"init", failed, control=control())
    assert error.value is failure
    cancelled = threading.Event()

    def cancel(*_a, **_k):
        cancelled.set()
        return STOP

    with pytest.raises(ExecutionStopped, match="session_cancelled"):
        ipc.supervise(command(code), b"init", cancel, control=control(cancelled=cancelled))
    assert all(child.returncode != 42 for child in processes)


def test_pre_cancelled_control_never_launches(monkeypatch):
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("must not launch"))
    with pytest.raises(ExecutionStopped):
        ipc.supervise(command("pass"), b"init", lambda *_a, **_k: STOP, control=control(cancelled=cancelled))


def test_cancellation_kills_pipe_holder_after_direct_child_exit(processes, monkeypatch):
    readers = []
    original = subprocess.Popen

    def launch(*args, **kwargs):
        child = original(*args, **kwargs)
        readers.append(os.dup(child.stdout.fileno()))
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    holder = [sys.executable, "-I", "-S", "-c", "import time; time.sleep(30)"]
    code = ("read(); send(5,READY); send(2,b'request'); read(); send(4,b'closed'); "
            f"import subprocess; subprocess.Popen({holder!r}); os._exit(0)")
    closed = False
    try:
        with pytest.raises(ExecutionStopped, match="session_timeout"):
            ipc.supervise(command(code), b"init", lambda *_a, **_k: STOP, control=control(0.3))
        assert processes[0].returncode == 0
        assert select.select(readers, [], [], 1)[0]
        assert os.read(readers[0], 1) == b""
        closed = True
    finally:
        try:
            if not closed:
                for child in processes:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        finally:
            for reader in readers:
                os.close(reader)
