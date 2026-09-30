"""Authority-bound Nmap sibling profile; accepted owned executors stay intact."""
from dataclasses import asdict
import secrets
import time

from .execution import ExecutionControl
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _namespaces
from .models import Action, Policy, parse_action, parse_policy
from .nmap_contract import BACKEND, TOOL_ID, profile_allows, validate_result_context
from .owned_lab import AuthorizedOwnedLabBackend


class AuthorizedNmapOwnedBackend(AuthorizedOwnedLabBackend):
    name = BACKEND
    supported_tools = (TOOL_ID, 'http_probe')
    launch_mode = 'owned_nmap_lab'
    _nmap_closure = None
    _nmap_mode = 'owned_nmap_lab'
    _nmap_launch_mode = 'nmap_owned'

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity['scenario'])):
            raise IsolationUnavailable('Owned Nmap profile denied')
        LinuxFixtureBackend.check_available(self, action)
        self.lab._check_available()

    def _validate_result_context(self, result, *, action):
        return validate_result_context(result, self._lab_identity, previous=self._previous_context,
            tool_id=action.tool_id, execution_status=result['status'])

    def run(self, action, policy, *, control=None):
        if type(action) is Action and action.tool_id == 'http_probe':
            return super().run(action, policy, control=control)
        if not self._lock.acquire(blocking=False):
            raise IsolationUnavailable('Executor authority is already running')
        try:
            if (not self._execute or type(control) is not ExecutionControl or control.clock is not time.monotonic
                    or type(action) is not Action or type(policy) is not Policy):
                raise IsolationUnavailable('Invalid Nmap executor authority context')
            control.check()
            action, policy = parse_action(action.to_dict()), parse_policy(policy.to_dict())
            if (policy.digest != self._policy_digest or self._policy.digest != self._policy_digest
                    or self._limits.digest != self._limits_digest or self._policy.evaluate(action).decision == 'deny'
                    or self.lab.identity != self._lab_identity):
                raise IsolationUnavailable('Nmap executor authority changed')
            if self._control is None:
                if control.remaining() > self._limits.max_runtime_seconds:
                    raise IsolationUnavailable('Nmap deadline exceeds authority')
                self._control = control
            elif control is not self._control:
                raise IsolationUnavailable('Nmap authority cannot be replaced')
            if (self._sequence >= self._limits.max_steps
                    or self._output + action.parameters.max_output_bytes > self._limits.max_output_bytes):
                raise IsolationUnavailable('Nmap executor budget exhausted')
            self.check_available(action)
            before = self._output
            self._sequence += 1
            self._output += action.parameters.max_output_bytes
            self.lab.start(control)
            nonce = secrets.token_hex(32)
            launch = {'schema_version': '1', 'mode': self._nmap_launch_mode, 'execute': True,
                'session_id': self._session_id, 'nonce': nonce, 'sequence': self._sequence,
                'action': action.to_dict(), 'action_digest': action.digest,
                'policy': self._policy.to_dict(), 'policy_digest': self._policy_digest,
                'limits': asdict(self._limits), 'limits_digest': self._limits_digest,
                'deadline': control.deadline, 'output_reserved_before': before,
                'output_reserved_after': self._output, 'host_namespaces': _namespaces()}
            from .nmap_runtime import run_nmap_owned
            result = run_nmap_owned(lab=self.lab, launch={'mode': self._nmap_mode, 'launch': launch,
                'identity': self._lab_identity, 'namespaces': self.lab._lab_namespaces},
                control=control, closure=self._nmap_closure)
            result['backend'] = self.name
            result['owned_lab'] = {'identity': self._lab_identity, **self.lab.snapshot(control)}
            self._previous_context = self._validate_result_context(result, action=action)
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise
        finally:
            self._lock.release()


class ConfinedNmapBackend(AuthorizedNmapOwnedBackend):
    def __init__(self, config, closure):
        from .owned_launcher_runtime import _ConfinedOwnedLab
        from .session_limits import SessionLimits
        self._config = config
        self._closure = self._nmap_closure = closure
        lab = _ConfinedOwnedLab(config, closure)
        super().__init__(parse_policy(config['policy']), config['session_id'], SessionLimits(**config['limits']),
                         lab, execute=config['execute'])

    def _accept_lab(self, lab):
        from .owned_launcher_runtime import _ConfinedOwnedLab
        return type(lab) is _ConfinedOwnedLab

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=False)

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity['scenario'])):
            raise IsolationUnavailable('Confined Nmap profile denied')
        self.lab._check_available()
