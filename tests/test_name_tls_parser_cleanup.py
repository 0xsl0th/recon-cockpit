"""Portable parser process-lifetime regressions using simulated kernel events."""

from types import SimpleNamespace
import subprocess

import pytest

from recon_cockpit.secure_agent import name_tls_parser_runtime as runtime
from recon_cockpit.secure_agent.execution import ExecutionStopped
from recon_cockpit.secure_agent.isolation import IsolationUnavailable


class Kernel:
    """Every OS interaction is simulated; no pidfd or procfs is required."""

    def __init__(self, monkeypatch, *, mode="reap", fault="output", child_pid=17):
        self.now, self.flags, self.events = 10.0, 0, []
        self.mode, self.fault, self.child_pid = mode, fault, child_pid
        self.input_released, self.reads, self.poll_events = False, {}, None
        self.saved_error = ExecutionStopped("session_timeout")
        self.close_error = None
        kernel = self

        class Stream:
            def __init__(self, descriptor):
                self.descriptor, self.closed = descriptor, False

            def fileno(self):
                return self.descriptor

            def close(self):
                kernel.events.append(("stream_close", self.descriptor))
                self.closed = True
                if kernel.close_error == self.descriptor:
                    raise OSError("simulated stream close failure")

        class Process:
            pid, returncode = 31, None
            stdin, stdout, stderr = Stream(11), Stream(12), Stream(13)

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                kernel.events.append(("wait", timeout, kernel.now))
                if self.returncode is not None:
                    return self.returncode
                if kernel.mode == "stuck" or (kernel.mode == "fallback" and not kernel.was_killed):
                    kernel.now += timeout
                    raise subprocess.TimeoutExpired("simulated bwrap", timeout)
                self.returncode = 0 if kernel.mode.startswith("success") else -9
                if kernel.mode in ("reap", "fallback", "success"):
                    kernel.flags = 17
                elif kernel.mode == "payload_first":
                    kernel.flags = 17 if any(event[0] == "pidfd_signal" for event in kernel.events) else 1
                elif kernel.mode == "success_delayed_reap":
                    kernel.flags = 1
                return self.returncode

        class Poll:
            def register(self, descriptor, flags):
                assert descriptor == 77 and flags == 1

            def poll(self, timeout):
                assert timeout == 0
                kernel.events.append(("poll", kernel.flags))
                if kernel.poll_events is not None:
                    return kernel.poll_events
                return [(77, kernel.flags)] if kernel.flags else []

        class Selector:
            def __init__(self):
                self.keys, self.stage = {}, 0

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def register(self, stream, _events, tag):
                descriptor = stream if type(stream) is int else stream.fileno()
                self.keys[descriptor] = SimpleNamespace(fd=descriptor, data=tag, fileobj=stream)

            def unregister(self, stream):
                descriptor = stream if type(stream) is int else stream.fileno()
                del self.keys[descriptor]

            def get_map(self):
                return self.keys

            def select(self, _timeout):
                self.stage += 1
                if self.stage == 1:
                    return [(self.keys[14], 1), (self.keys[12], 1)]
                if self.stage == 2:
                    return [(self.keys[11], 2)]
                if self.stage == 3:
                    return [(self.keys[12], 1)]
                if self.stage == 4 and kernel.mode.startswith("success"):
                    return [(key, 1) for key in self.keys.values()]
                raise AssertionError("unexpected capture continuation")

        self.was_killed = False
        self.process = Process()
        monkeypatch.setattr(runtime, "os", SimpleNamespace(
            pidfd_open=self.open_pid, close=self.close, killpg=self.killpg,
            read=self.read, write=self.write, set_blocking=lambda *_: None))
        monkeypatch.setattr(runtime, "signal", SimpleNamespace(SIGKILL=9, pidfd_send_signal=self.signal))
        monkeypatch.setattr(runtime, "select", SimpleNamespace(poll=Poll, POLLIN=1, POLLHUP=16), raising=False)
        monkeypatch.setattr(runtime, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1, EVENT_WRITE=2))
        monkeypatch.setattr(runtime, "subprocess", SimpleNamespace(
            Popen=lambda *_args, **_kwargs: self.process, PIPE=-1, TimeoutExpired=subprocess.TimeoutExpired))
        monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: self.now, sleep=self.sleep))
        monkeypatch.setattr(runtime, "_observe_process", self.observe)
        monkeypatch.setattr(runtime, "_readiness", lambda raw: {"synthetic_readiness": raw.decode()})
        self.control = SimpleNamespace(check=self.check, remaining=lambda: 1)

    def open_pid(self, pid):
        self.events.append(("pidfd_open", pid))
        assert type(pid) is int and pid == 17
        return 77

    def observe(self, pid, readiness):
        self.events.append(("observe", pid))
        assert readiness == {"synthetic_readiness": "{}"}
        if self.fault == "observation_race":
            self.flags = 1
        return {"payload_pid": pid, "synthetic_observation": True}

    def close(self, descriptor):
        self.events.append(("close", descriptor))
        if self.close_error == descriptor:
            raise OSError("simulated descriptor close failure")

    def signal(self, descriptor, number):
        self.events.append(("pidfd_signal", descriptor, number))
        assert descriptor == 77 and number == 9
        if self.mode == "signal_denied":
            raise PermissionError("simulated signal denial")
        self.flags = 1

    def killpg(self, pid, number):
        self.events.append(("killpg", pid, number))
        assert pid == 31 and number == 9
        self.was_killed = True

    def sleep(self, seconds):
        assert 0 < seconds <= .01
        self.events.append(("sleep", seconds))
        self.now += seconds
        if self.mode in ("delayed_reap", "success_delayed_reap") and self.now >= 10.7:
            self.flags = 17

    def read(self, descriptor, maximum):
        assert maximum == 8193
        count = self.reads.get(descriptor, 0)
        self.reads[descriptor] = count + 1
        if descriptor == 14:
            import json
            return json.dumps({"child-pid": self.child_pid}).encode() if count == 0 else b""
        if descriptor == 13:
            return b""
        assert descriptor == 12
        if count == 0:
            return runtime.READY + b"{}\n"
        if self.mode.startswith("success"):
            return b"reply" if count == 1 else b""
        return b"x" * 8193

    def write(self, descriptor, raw):
        self.events.append(("input", descriptor, raw))
        assert descriptor == 11 and raw == b"request"
        self.input_released = True
        return len(raw)

    def check(self):
        if self.fault == "deadline" and self.input_released:
            raise self.saved_error

    def capture(self):
        return runtime._capture(["synthetic-bwrap"], b"request", self.control, {}, 14, 15)

    def assert_closed(self, *, pin=True):
        assert [event for event in self.events if event == ("close", 77)] == ([("close", 77)] if pin else [])
        for descriptor in (11, 12, 13):
            assert self.events.count(("stream_close", descriptor)) == 1


@pytest.mark.parametrize("fault", ("output", "deadline"))
def test_capture_pins_before_observation_and_input_then_reaps_payload_before_wrapper(monkeypatch, fault):
    kernel = Kernel(monkeypatch, mode="payload_first", fault=fault)
    with pytest.raises((ValueError, ExecutionStopped)) as caught:
        kernel.capture()
    if fault == "deadline":
        assert caught.value is kernel.saved_error
    else:
        assert str(caught.value) == "name_tls_parser_output_limit"
    assert kernel.flags == 17, "capture returned before the actual parser payload was reaped"
    events = [event[0] for event in kernel.events]
    assert events.index("pidfd_open") < events.index("observe") < events.index("input") < events.index("pidfd_signal") < events.index("wait")
    assert "killpg" not in events
    assert kernel.flags == 17 and kernel.process.returncode is not None
    assert kernel.events.count(("close", 15)) == 1
    kernel.assert_closed()


@pytest.mark.parametrize("child_pid", (True, False, 0, -1, "17", None))
def test_invalid_info_pid_cannot_open_or_signal_any_payload(monkeypatch, child_pid):
    kernel = Kernel(monkeypatch, child_pid=child_pid)
    with pytest.raises(ValueError, match="name_tls_parser_process_identity"):
        kernel.capture()
    assert not any(event[0] in ("pidfd_open", "observe", "input", "pidfd_signal") for event in kernel.events)
    assert ("killpg", 31, 9) in kernel.events
    kernel.assert_closed(pin=False)


@pytest.mark.parametrize("race", ("before", "during"))
def test_exit_around_proc_observation_prevents_input_and_payload_signal(monkeypatch, race):
    kernel = Kernel(monkeypatch, fault="observation_race" if race == "during" else "output")
    if race == "before":
        kernel.flags = 1
    with pytest.raises(ValueError, match="name_tls_parser_payload_exited"):
        kernel.capture()
    assert not any(event[0] in ("input", "pidfd_signal") for event in kernel.events)
    assert sum(event[0] == "observe" for event in kernel.events) == (1 if race == "during" else 0)
    kernel.assert_closed()


@pytest.mark.parametrize("owner, name", (("os", "pidfd_open"), ("signal", "pidfd_send_signal"), ("select", "poll")))
def test_missing_pidfd_api_fails_before_input_and_still_cleans_wrapper(monkeypatch, owner, name):
    kernel = Kernel(monkeypatch)
    delattr(getattr(runtime, owner), name)
    with pytest.raises(IsolationUnavailable, match="process pin unavailable"):
        kernel.capture()
    assert not any(event[0] in ("observe", "input", "pidfd_signal") for event in kernel.events)
    assert ("killpg", 31, 9) in kernel.events
    kernel.assert_closed(pin=False)


def test_signal_api_disappearing_after_verified_pin_still_reaps_wrapper_and_closes_everything(monkeypatch):
    kernel = Kernel(monkeypatch)
    del runtime.signal.pidfd_send_signal
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed"):
        runtime._cleanup(kernel.process, 77, True)
    assert ("killpg", 31, 9) in kernel.events and kernel.process.returncode is not None
    kernel.assert_closed()


def test_exited_payload_is_not_signalled_and_waits_for_hup_not_just_pollin(monkeypatch):
    kernel = Kernel(monkeypatch, mode="delayed_reap")
    kernel.flags = 1
    runtime._cleanup(kernel.process, 77, True)
    assert not any(event[0] == "pidfd_signal" for event in kernel.events)
    assert kernel.flags == 17 and 10.7 <= kernel.now < 12
    assert any(event[0] == "sleep" for event in kernel.events)
    kernel.assert_closed()


@pytest.mark.parametrize("flags", (0, 1))
def test_live_or_exited_unreaped_payload_cannot_report_cleanup_success(monkeypatch, flags):
    kernel = Kernel(monkeypatch, mode="unreaped")
    kernel.flags = flags
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed"):
        runtime._cleanup(kernel.process, 77, True)
    assert kernel.now == pytest.approx(12) and kernel.flags == 1
    kernel.assert_closed()


def test_wrapper_fallback_shares_single_two_second_budget_after_payload_signal(monkeypatch):
    kernel = Kernel(monkeypatch, mode="fallback")
    runtime._cleanup(kernel.process, 77, True)
    operations = [event[0] for event in kernel.events]
    assert operations.index("pidfd_signal") < operations.index("wait") < operations.index("killpg")
    waits = [event for event in kernel.events if event[0] == "wait"]
    assert waits == [("wait", 1, 10.0), ("wait", 1.0, 11.0)]
    assert all(start + timeout <= 12 for _, timeout, start in waits)
    kernel.assert_closed()


def test_wrapper_that_never_exits_is_fail_closed_at_same_deadline(monkeypatch):
    kernel = Kernel(monkeypatch, mode="stuck")
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed"):
        runtime._cleanup(kernel.process, 77, True)
    assert kernel.now == 12
    assert [event[1] for event in kernel.events if event[0] == "wait"] == [1, 1]
    kernel.assert_closed()


@pytest.mark.parametrize("poll_events", ([(77, 32)], [(77, 0)], [(78, 1)], [(77, 1), (77, 16)]))
def test_invalid_pidfd_poll_result_is_fail_closed_and_does_not_signal(monkeypatch, poll_events):
    kernel = Kernel(monkeypatch)
    kernel.poll_events = poll_events
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed"):
        runtime._cleanup(kernel.process, 77, True)
    assert not any(event[0] == "pidfd_signal" for event in kernel.events)
    kernel.assert_closed()


def test_signal_failure_is_explicit_even_when_wrapper_is_reaped(monkeypatch):
    kernel = Kernel(monkeypatch, mode="signal_denied")
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed"):
        runtime._cleanup(kernel.process, 77, True)
    assert ("killpg", 31, 9) in kernel.events and kernel.process.returncode is not None
    kernel.assert_closed()


@pytest.mark.parametrize("descriptor", (77, 11, 12, 13))
def test_one_close_failure_cannot_skip_remaining_descriptor_closures(monkeypatch, descriptor):
    kernel = Kernel(monkeypatch)
    kernel.close_error = descriptor
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed"):
        runtime._cleanup(kernel.process, 77, True)
    kernel.assert_closed()


def test_cleanup_failure_replaces_output_error_with_explicit_isolation_failure(monkeypatch):
    kernel = Kernel(monkeypatch, mode="unreaped")
    with pytest.raises(IsolationUnavailable, match="parser cleanup failed") as caught:
        kernel.capture()
    assert isinstance(caught.value.__context__, ValueError)
    assert str(caught.value.__context__) == "name_tls_parser_output_limit"
    kernel.assert_closed()


def test_successful_capture_preserves_receipt_and_checks_reaped_payload_without_signalling(monkeypatch):
    kernel = Kernel(monkeypatch, mode="success")
    reply, receipt = kernel.capture()
    assert reply == b"reply"
    assert set(receipt) == {"readiness", "parent_observation", "wrapper_pid", "exit_code",
                            "input_sha256", "reply_sha256", "elapsed_ms", "process_reaped"}
    assert receipt["parent_observation"] == {"payload_pid": 17, "synthetic_observation": True}
    assert receipt["process_reaped"] is True and receipt["exit_code"] == 0
    assert not any(event[0] in ("pidfd_signal", "killpg") for event in kernel.events)
    assert kernel.flags == 17
    kernel.assert_closed()


@pytest.mark.parametrize("reaped", (True, False))
def test_failed_proc_observation_never_signals_unverified_pin_but_still_requires_reaping(monkeypatch, reaped):
    kernel = Kernel(monkeypatch, mode="reap" if reaped else "unreaped")
    original = ValueError("simulated namespace observation refusal")
    def refuse(*_):
        raise original
    monkeypatch.setattr(runtime, "_observe_process", refuse)
    with pytest.raises(ValueError if reaped else IsolationUnavailable) as caught:
        kernel.capture()
    if reaped:
        assert caught.value is original
    else:
        assert caught.value.__context__ is original
        assert kernel.now == pytest.approx(12)
    assert not any(event[0] in ("input", "pidfd_signal") for event in kernel.events)
    assert ("killpg", 31, 9) in kernel.events
    kernel.assert_closed()


def test_success_receipt_elapsed_includes_waiting_for_actual_payload_reap(monkeypatch):
    kernel = Kernel(monkeypatch, mode="success_delayed_reap")
    reply, receipt = kernel.capture()
    assert reply == b"reply" and receipt["elapsed_ms"] >= 700
    assert kernel.flags == 17 and kernel.now < 12
    kernel.assert_closed()


def test_successful_work_cannot_return_receipt_when_reaping_crosses_existing_bound(monkeypatch):
    from recon_cockpit.secure_agent.execution import ExecutionControl
    kernel = Kernel(monkeypatch, mode="success_delayed_reap")
    kernel.control = ExecutionControl(10.4, clock=lambda: kernel.now)
    with pytest.raises(ExecutionStopped, match="session_timeout"):
        kernel.capture()
    assert kernel.flags == 17 and 10.7 <= kernel.now < 12
    kernel.assert_closed()


def test_expired_work_still_gets_bounded_emergency_reaping_and_keeps_original_error(monkeypatch):
    kernel = Kernel(monkeypatch, mode="delayed_reap", fault="deadline")
    with pytest.raises(ExecutionStopped) as caught:
        kernel.capture()
    assert caught.value is kernel.saved_error
    assert 10.7 <= kernel.now < 12 and kernel.flags == 17
    kernel.assert_closed()


@pytest.mark.parametrize("bound", ("owner", "caller", "parser"))
@pytest.mark.parametrize("expires_during", ("cleanup", "validation", "receipt", None))
def test_success_never_escapes_original_deadline_after_cleanup_or_reply_validation(monkeypatch, bound, expires_during):
    import hashlib
    from recon_cockpit.secure_agent.execution import ExecutionControl
    clock, events, closed = [10.0], [], []
    expired = 11.01 if bound == "parser" else 10.76
    raw = b"synthetic request"
    result = {"input_sha256": hashlib.sha256(raw).hexdigest()}
    readiness = {"parser_version": "synthetic", "boundary_checks": {name: True for name in runtime.BOUNDARY_NAMES},
                 "identity": {}, "namespaces": {}, "runtime_absence_verified": True}
    value = {**readiness, "status": "parsed", "result": result}
    receipt = {"readiness": readiness}

    def capture(*_):
        events.append("capture_and_cleanup")
        clock[0] = expired if expires_during == "cleanup" else 10.5
        return b"synthetic reply", receipt

    def validate(value):
        events.append("validate")
        if expires_during == "validation":
            clock[0] = expired
        return value

    def source_digest(_):
        events.append("receipt")
        if expires_during == "receipt":
            clock[0] = expired
        return "0" * 64

    monkeypatch.setattr(runtime, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(runtime, "os", SimpleNamespace(pipe2=lambda _: (80, 81), O_CLOEXEC=1, close=closed.append))
    monkeypatch.setattr(runtime, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(runtime, "sources", SimpleNamespace(snapshot_sources=lambda *_: {}, source_digest=source_digest))
    monkeypatch.setattr(runtime, "parser", SimpleNamespace(MAX_INPUT_BYTES=131072, PARSER_VERSION="synthetic",
                        load_json=lambda _: value, validate_result=validate))
    monkeypatch.setattr(runtime, "_command", lambda *_: ["synthetic-bwrap"])
    monkeypatch.setattr(runtime, "_capture", capture)
    options = {"control": ExecutionControl(10.75, clock=lambda: clock[0])} if bound == "owner" else {"deadline": 15 if bound == "parser" else 10.75}
    options.update(closure={"stdlib": "/synthetic", "files": ["/synthetic/runtime"]}, bundle={"python_sources": {}}, return_receipt=True)
    if expires_during is None:
        assert runtime.parse_isolated_operation(raw, **options) == (result, receipt)
    else:
        with pytest.raises(ExecutionStopped, match="session_timeout"):
            runtime.parse_isolated_operation(raw, **options)
        if expires_during == "cleanup":
            assert events == ["capture_and_cleanup"]
    assert closed == [80]
