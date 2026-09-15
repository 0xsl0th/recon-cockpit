"""Bounded persistent coordinator frames; no authority is carried by framing.

Only the trusted host chooses argv and the synchronous exchange callback. That
callback must honor the shared control. Sandbox imports need only the data
helpers; all subprocess machinery is imported locally by the supervisor.
"""

INIT, REQUEST, RESPONSE, RESULT, READY = 1, 2, 3, 4, 5
MAX_REQUESTS = 17
MAX_INIT_BYTES = 512
MAX_REQUEST_BYTES = 20480
MAX_RESPONSE_BYTES = 12288
MAX_RESULT_BYTES = 512
MAX_READY_BYTES = 1024
MAX_STDERR_BYTES = 4096
LIMITS = {INIT: MAX_INIT_BYTES, REQUEST: MAX_REQUEST_BYTES,
          RESPONSE: MAX_RESPONSE_BYTES, RESULT: MAX_RESULT_BYTES, READY: MAX_READY_BYTES}
MAX_OUTPUT_BYTES = MAX_REQUESTS * (MAX_REQUEST_BYTES + 5) + MAX_READY_BYTES + MAX_RESULT_BYTES + 10 + MAX_STDERR_BYTES
BOUNDARY_NAMES = frozenset({
    "namespaces_private", "capabilities_dropped", "no_new_privs",
    "socket_creation_blocked", "process_creation_blocked",
    "namespace_creation_blocked", "root_read_only",
})


class IPCError(RuntimeError):
    """Static local errors, never untrusted diagnostic text."""


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
    if _read_exact(stream, 1)[0] != expected:
        raise IPCError("unexpected_ipc_frame")
    return _read_exact(stream, size - 1)


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IPCError("invalid_ipc_object")
        result[key] = value
    return result


def _reject_constant(_value):
    raise IPCError("invalid_ipc_object")


def object_payload(raw):
    import json

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_fields, parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError):
        raise IPCError("invalid_ipc_object") from None
    if type(value) is not dict:
        raise IPCError("invalid_ipc_object")
    return value


def _ready(raw):
    value = object_payload(raw)
    if set(value) != {"schema_version", "boundary_checks"} or value["schema_version"] != "1":
        raise IPCError("unverified_coordinator_boundary")
    checks = value["boundary_checks"]
    if (type(checks) is not dict or set(checks) != BOUNDARY_NAMES
            or any(value is not True for value in checks.values())):
        raise IPCError("unverified_coordinator_boundary")


def _kill_and_reap(proc, *, failed):
    import os
    import signal

    try:
        # Poll first to reap a zombie leader (Darwin can reject signalling it).
        # Failed dialogues still require a group kill for descendants' pipes.
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
    """Validate READY, mediate <=17 requests, require stop and RESULT plus EOF.

Requests are opaque bounded data for the authority callback. Responses must
contain a boolean stop; only that trusted flag permits a final RESULT. Neither
successful framing nor coordinator evidence confers tool execution authority.
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
    output_total = stderr_total = requests = offset = 0
    result = request = None
    stopping = False
    eof = set()
    try:
        with selectors.DefaultSelector() as selector:
            for stream, events, name in ((proc.stdin, selectors.EVENT_WRITE, "stdin"),
                                         (proc.stdout, selectors.EVENT_READ, "stdout"),
                                         (proc.stderr, selectors.EVENT_READ, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, events, name)
            while True:
                control.check()
                ready = selector.select(min(0.05, control.remaining()))
                # Reject premature output before releasing a newly ready write.
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
                            pending, offset = b"", 0
                            if phase == "sending_init":
                                phase = "waiting_ready"
                            elif phase == "sending_response":
                                if stopping:
                                    proc.stdin.close()
                                phase = "waiting_result" if stopping else "waiting_request"
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
                    if phase not in {"waiting_ready", "waiting_request", "waiting_result"}:
                        raise IPCError("unexpected_ipc_output")
                    incoming.extend(data)
                    while incoming:
                        expected = {"waiting_ready": READY, "waiting_request": REQUEST,
                                    "waiting_result": RESULT}[phase]
                        if len(incoming) < 4:
                            break
                        size = int.from_bytes(incoming[:4], "big")
                        if not 1 <= size <= LIMITS[expected] + 1:
                            raise IPCError("ipc_frame_limit")
                        if len(incoming) >= 5 and incoming[4] != expected:
                            raise IPCError("unexpected_ipc_frame")
                        if len(incoming) < size + 4:
                            break
                        payload = bytes(incoming[5:size + 4])
                        del incoming[:size + 4]
                        if expected == READY:
                            _ready(payload)
                            phase = "waiting_request"
                            # READY needs no ACK, so the first request may be
                            # coalesced with it. Requests themselves cannot be.
                            continue
                        if incoming:
                            raise IPCError("extra_ipc_output")
                        if expected == REQUEST:
                            requests += 1
                            if requests > MAX_REQUESTS:
                                raise IPCError("ipc_request_limit")
                            request, phase = payload, "exchanging"
                        else:
                            result, phase = payload, "waiting_eof"
                if phase == "exchanging":
                    control.check()
                    # A complete request can end exactly at an os.read boundary.
                    # Inspect queued diagnostics and stdout before dispatching it;
                    # checking only `incoming` misses an already-buffered next
                    # frame or EOF. These reads never wait for future output and
                    # cannot predict what the coordinator will send afterward.
                    while "stderr" not in eof:
                        control.check()
                        try:
                            queued = os.read(proc.stderr.fileno(), min(
                                8192, MAX_STDERR_BYTES - stderr_total + 1,
                                MAX_OUTPUT_BYTES - output_total + 1,
                            ))
                        except BlockingIOError:
                            break
                        if not queued:
                            selector.unregister(proc.stderr)
                            eof.add("stderr")
                            break
                        stderr_total += len(queued)
                        output_total += len(queued)
                        if stderr_total > MAX_STDERR_BYTES or output_total > MAX_OUTPUT_BYTES:
                            raise IPCError("ipc_output_limit")
                    try:
                        queued = os.read(proc.stdout.fileno(), 1)
                    except BlockingIOError:
                        pass
                    else:
                        raise IPCError("extra_ipc_output" if queued else "truncated_ipc_dialogue")
                    control.check()
                    response = exchange(request, control=control)
                    control.check()
                    pending = frame(RESPONSE, response)
                    value = object_payload(response)
                    if type(value.get("stop")) is not bool:
                        raise IPCError("invalid_ipc_response")
                    stopping = value["stop"]
                    if requests == MAX_REQUESTS and not stopping:
                        raise IPCError("ipc_request_limit")
                    request, phase = None, "sending_response"
                    selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                if eof == {"stdout", "stderr"}:
                    if phase != "waiting_eof" or result is None:
                        raise IPCError("truncated_ipc_dialogue")
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
