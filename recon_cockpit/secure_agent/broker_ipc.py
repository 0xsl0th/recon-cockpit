"""Bounded typed frames and a trusted one-exchange subprocess supervisor.

Frame helpers are data-only and may be mounted inside the planner sandbox.
Host-only supervisor imports stay local: the sandbox receives no execution API
dependencies. Its trusted synchronous exchange callback must honor the shared
execution control; this is not a sandbox for arbitrary Python callbacks.
"""

INIT, REQUEST, RESPONSE, RESULT = 1, 2, 3, 4
MAX_INIT_BYTES = 12288
MAX_REQUEST_BYTES = 16384
MAX_RESPONSE_BYTES = 65536
MAX_RESULT_BYTES = 20480
MAX_STDERR_BYTES = 4096
LIMITS = {INIT: MAX_INIT_BYTES, REQUEST: MAX_REQUEST_BYTES,
          RESPONSE: MAX_RESPONSE_BYTES, RESULT: MAX_RESULT_BYTES}
MAX_OUTPUT_BYTES = MAX_REQUEST_BYTES + MAX_RESULT_BYTES + 10 + MAX_STDERR_BYTES


class IPCError(RuntimeError):
    """A static protocol failure, never containing child or broker text."""


def frame(kind, payload):
    if type(kind) is not int or kind not in LIMITS or type(payload) is not bytes or len(payload) > LIMITS[kind]:
        raise IPCError("invalid_ipc_frame")
    return (len(payload) + 1).to_bytes(4, "big") + bytes((kind,)) + payload


def _read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        data = stream.read(count - len(result))
        if type(data) is not bytes or not data or len(data) > count - len(result):
            raise IPCError("truncated_ipc_frame")
        result.extend(data)
    return bytes(result)


def read_frame(stream, expected):
    if type(expected) is not int or expected not in LIMITS:
        raise IPCError("invalid_ipc_kind")
    size = int.from_bytes(_read_exact(stream, 4), "big")
    if not 1 <= size <= LIMITS[expected] + 1:
        raise IPCError("ipc_frame_limit")
    kind = _read_exact(stream, 1)[0]
    if kind != expected:
        raise IPCError("unexpected_ipc_frame")
    return _read_exact(stream, size - 1)


def _kill_and_reap(proc, *, failed):
    # Kill the group on failure even if the direct child exited: a descendant
    # may still own a captured pipe. Avoid redundant signalling after success.
    import os
    import signal

    try:
        # Reap an already-exited leader before signalling: Darwin may return
        # EPERM for a group whose only remaining member is that zombie. Still
        # signal on failure after reaping, since live descendants can own pipes.
        alive = proc.poll() is None
        if failed or alive:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    finally:
        try:
            proc.wait(timeout=2)
        finally:
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None and not stream.closed:
                    stream.close()


def supervise(argv, init_payload, exchange, *, control):
    """Run exactly INIT -> REQUEST -> RESPONSE -> RESULT -> clean output EOF.

Only trusted host code chooses argv and supplies exchange. All stdin writes
are nonblocking, including a response larger than pipe capacity. No result is
returned until both output pipes close and the child exits successfully.
"""
    import os
    import selectors
    import subprocess

    pending = frame(INIT, init_payload)
    if not callable(exchange):
        raise IPCError("invalid_ipc_exchange")
    control.check()
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            close_fds=True, start_new_session=True, bufsize=0,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    completed = False
    phase = "sending_init"
    incoming = bytearray()
    output_total = stderr_total = 0
    result = request = None
    eof = set()
    try:
        with selectors.DefaultSelector() as selector:
            for stream, events, name in ((proc.stdin, selectors.EVENT_WRITE, "stdin"),
                                         (proc.stdout, selectors.EVENT_READ, "stdout"),
                                         (proc.stderr, selectors.EVENT_READ, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, events, name)
            offset = 0
            while True:
                control.check()
                # Inspect already-readable output before releasing more input;
                # a premature RESULT must not be legitimized by a ready write.
                ready = selector.select(min(0.05, control.remaining()))
                for key, _ in sorted(ready, key=lambda item: item[0].data == "stdin"):
                    control.check()
                    if key.data == "stdin":
                        try:
                            offset += os.write(key.fd, memoryview(pending)[offset:offset + 4096])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            raise IPCError("ipc_input_closed") from None
                        if offset == len(pending):
                            selector.unregister(proc.stdin)
                            pending = b""
                            offset = 0
                            if phase == "sending_init":
                                phase = "waiting_request"
                            elif phase == "sending_response":
                                proc.stdin.close()
                                phase = "waiting_result"
                            else:
                                raise IPCError("unexpected_ipc_state")
                        continue
                    try:
                        data = os.read(key.fd, min(8192, MAX_OUTPUT_BYTES - output_total + 1))
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        eof.add(key.data)
                        if key.data == "stdout" and (phase != "waiting_eof" or incoming):
                            raise IPCError("truncated_ipc_dialogue")
                        continue
                    output_total += len(data)
                    if output_total > MAX_OUTPUT_BYTES:
                        raise IPCError("ipc_output_limit")
                    if key.data == "stderr":
                        stderr_total += len(data)
                        if stderr_total > MAX_STDERR_BYTES:
                            raise IPCError("ipc_output_limit")
                        continue
                    if phase not in {"waiting_request", "waiting_result"}:
                        raise IPCError("unexpected_ipc_output")
                    incoming.extend(data)
                    expected = REQUEST if phase == "waiting_request" else RESULT
                    if len(incoming) < 4:
                        continue
                    size = int.from_bytes(incoming[:4], "big")
                    if not 1 <= size <= LIMITS[expected] + 1:
                        raise IPCError("ipc_frame_limit")
                    if len(incoming) >= 5 and incoming[4] != expected:
                        raise IPCError("unexpected_ipc_frame")
                    if len(incoming) < size + 4:
                        continue
                    if len(incoming) != size + 4:
                        raise IPCError("extra_ipc_output")
                    payload = bytes(incoming[5:])
                    incoming.clear()
                    if expected == REQUEST:
                        request = payload
                        phase = "exchanging"
                    else:
                        result = payload
                        phase = "waiting_eof"
                if phase == "exchanging":
                    control.check()
                    response = exchange(request, control=control)
                    control.check()
                    pending = frame(RESPONSE, response)
                    request = None
                    phase = "sending_response"
                    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                if eof == {"stdout", "stderr"}:
                    if phase != "waiting_eof" or result is None:
                        raise IPCError("truncated_ipc_dialogue")
                    # Output EOF does not imply process exit. Keep cancellation
                    # active while waiting for a child that closed its pipes.
                    try:
                        code = proc.wait(timeout=min(0.05, control.remaining()))
                    except subprocess.TimeoutExpired:
                        continue
                    if code != 0:
                        raise IPCError("ipc_process_failed")
                    control.check()
                    completed = True
                    return result
    finally:
        _kill_and_reap(proc, failed=not completed)
