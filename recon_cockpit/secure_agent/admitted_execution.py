"""Mandatory permit redemption in front of existing owned executor adapters."""

import threading

from .admission_isolation import LinuxLaunchAdmission
from .authorized_execution import AuthorizedFixtureBackend, AuthorizedDiscoveryFixtureBackend
from .isolation import IsolationUnavailable
from .owned_lab import AuthorizedOwnedLabBackend


class AdmissionGatedBackend:
    """Trusted launcher wrapper; permit contents never select executable or scope.

    Human consent and audit ordering remain Controller preconditions. This
    independently checks policy/profile and budgets, not the truth of consent.
    """

    def __init__(self, backend):
        if type(backend) not in {AuthorizedFixtureBackend, AuthorizedDiscoveryFixtureBackend, AuthorizedOwnedLabBackend}:
            raise ValueError('unsupported_admission_backend')
        self._backend = backend
        self.name = backend.name  # Existing evidence/capability schema is unchanged.
        owned = type(backend) is AuthorizedOwnedLabBackend
        self._admission = LinuxLaunchAdmission(
            backend._policy, backend._session_id, backend._limits, execute=backend._execute,
            profile='owned_lab' if owned else backend.launch_mode,
            case=backend._lab_identity['scenario'] if owned else None)
        self._lock = threading.Lock()
        self._stopped = threading.Event()

    @property
    def snapshot(self):
        return self._backend.snapshot

    @property
    def admission_snapshot(self):
        return self._admission.snapshot

    def _check_open(self):
        if self._stopped.is_set():
            raise IsolationUnavailable('Launch admission gate closed')

    def check_available(self, action=None):
        self._check_open()
        self._backend.check_available(action)

    def run(self, action, policy, *, control=None):
        if not self._lock.acquire(blocking=False):
            self._stopped.set()
            raise IsolationUnavailable('Launch admission already running')
        try:
            self._check_open()
            admission = self._admission.admit(action, policy, control=control)
            if admission['reason'] is not None:
                raise IsolationUnavailable('Launch admission denied')
            redemption = self._admission.redeem(admission['permit'], action, policy, control=control)
            if redemption['reason'] is not None:
                raise IsolationUnavailable('Launch permit redemption denied')
            # Cancellation or a concurrent caller can invalidate even a consumed
            # permit before the existing executor receives the action.
            self._check_open()
            control.check()
            result = self._backend.run(action, policy, control=control)
            control.check()
            return result
        except BaseException:
            self._stopped.set()
            self._admission.close()
            raise
        finally:
            self._lock.release()

    def close(self):
        self._stopped.set()
        with self._lock:
            self._admission.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
