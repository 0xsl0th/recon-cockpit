"""Test-only observation of the real approval failure after owner closure.

No reply is manufactured and no witness endpoint is retained or reconnected.
The fixed worker's generic failure is evidence of transport unavailability;
the closed-witness write is an inference from source, not a syscall trace.
"""

import base64
from copy import deepcopy
import os
import select
import time

from recon_cockpit.secure_agent.approvals import ApprovalUnavailable
from name_tls_owner_liveness import ApprovalPin


MAX_DIAGNOSTIC_BYTES = 4096


def drain_natural_exit(approvals):
    """Observe EOF and natural exit before the unchanged cleanup can kill."""
    supervisor, process = approvals._supervisor, approvals._process
    names = {'worker_out': process.stdout, 'worker_err': process.stderr}
    pending = {name: stream for name, stream in names.items() if name not in supervisor.eof}
    deadline = min(approvals._control.deadline, time.monotonic() + 1)
    while True:
        total = sum(len(supervisor.buffers[name]) for name in names)
        assert total <= MAX_DIAGNOSTIC_BYTES, 'approval failure diagnostic limit'
        code = process.poll()
        if not pending and code is not None:
            assert code == 78, 'approval failure did not exit naturally with status 78'
            return {'worker_stdout_base64': base64.b64encode(bytes(supervisor.buffers['worker_out'])).decode('ascii'),
                    'worker_stderr_base64': base64.b64encode(bytes(supervisor.buffers['worker_err'])).decode('ascii'),
                    'supervised_pid': process.pid, 'supervised_returncode': code,
                    'capture_source': 'existing_supervisor_pipes',
                    'capture_limit_bytes': MAX_DIAGNOSTIC_BYTES, 'capture_complete': True}
        remaining = deadline - time.monotonic()
        assert remaining > 0, 'approval failure natural-exit observation timed out'
        ready = select.select(list(pending.values()), [], [], min(remaining, .05))[0]
        for name, stream in list(pending.items()):
            if stream not in ready:
                continue
            raw = os.read(stream.fileno(), MAX_DIAGNOSTIC_BYTES - total + 1)
            if not raw:
                pending.pop(name)
                supervisor.eof.add(name)
                continue
            supervisor.total += len(raw)
            assert supervisor.total <= supervisor.limit, 'approval supervisor output limit'
            supervisor.buffers[name].extend(raw)
            total += len(raw)


class ClosedApprovalFailure:
    def __init__(self, session):
        self.session = session
        self.pin = ApprovalPin(session.approvals._process.pid)
        session.stack.callback(self.pin.close)
        self.pin.observe(alive=True)

    def submit(self, action, reference):
        session = self.session
        approvals = session.approvals
        assert session.backend._closed and session.backend._process.poll() is not None
        process_before = self.pin.observe(alive=True)
        process_binding = self.pin.binding(session.approval_messages[0]['request'], session.control,
                                          session.approval_supervised_start_time_ticks)
        original_cleanup = approvals._cleanup
        captured = []
        def observed_cleanup():
            try:
                assert not captured, 'approval cleanup repeated'
                captured.append(drain_natural_exit(approvals))
            finally:
                original_cleanup()
        approvals._cleanup = observed_cleanup
        try:
            try:
                session.controller.submit(action, execute=True, interactive=True,
                    approval_reference=reference, execution_control=session.control, session_step=2)
            except ApprovalUnavailable as error:
                assert str(error) == 'approval_unavailable'
            else:
                raise AssertionError('closed-owner consume unexpectedly returned an action outcome')
        finally:
            approvals._cleanup = original_cleanup
        assert len(captured) == 1 and len(session.approval_pending) == 1
        return {'stage': 'approval_consume_after_owner_close', 'exception_type': 'ApprovalUnavailable',
                'exception_code': 'approval_unavailable', 'pending_request': deepcopy(session.approval_pending[0]),
                'reply': None, **captured[0], 'process_before': process_before,
                'process_after': self.pin.observe(alive=False), 'process_binding': process_binding}
