"""Fixed HarborDesk sibling of the reviewed owned Nmap/HTTP executor."""
from pathlib import Path

from .isolation import IsolationUnavailable, LinuxFixtureBackend, _trusted_program
from .models import parse_policy
from .nmap_backend import AuthorizedNmapOwnedBackend
from .session_limits import SessionLimits
from .web_assessment_contract import BACKEND, profile_allows, validate_result_context
from .web_lab import WebLab
from .web_lab_contract import validate_identity


class AuthorizedWebLabBackend(AuthorizedNmapOwnedBackend):
    name = BACKEND
    launch_mode = _envelope_mode = _nmap_mode = 'owned_web_lab'
    _nmap_launch_mode = 'nmap_web_owned'

    def _accept_lab(self, lab):
        return type(lab) is WebLab

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity['scenario'])):
            raise IsolationUnavailable('Owned web profile denied')
        LinuxFixtureBackend.check_available(self, action)
        self.lab._check_available()

    def _validate_result_context(self, result, *, action):
        return validate_result_context(result, self._lab_identity, previous=self._previous_context,
            tool_id=action.tool_id, execution_status=result['status'])

    def _command(self, stdlib, files, nonce, context_digest):
        argv = super()._command(stdlib, files, nonce, context_digest)
        mounts = []
        for name in ('web_lab_contract', 'web_fixture'):
            mounts += ['--ro-bind', str(Path(__file__).with_name(name+'.py').resolve()),
                       '/app/recon_cockpit/secure_agent/'+name+'.py']
        index = argv.index('--remount-ro')
        argv[index:index] = mounts
        return argv


class ConfinedWebLab(WebLab):
    def __init__(self, config, closure):
        super().__init__(config['case'], config['session_id'], SessionLimits(**config['limits']), execute=config['execute'])
        self._identity = validate_identity(config['owned_lab'], case=config['case'])
        self._closure = closure

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=True)

    def _check_available(self):
        for name in ('bwrap', 'nft', 'nsenter'):
            _trusted_program(name)


class ConfinedWebBackend(AuthorizedWebLabBackend):
    def __init__(self, config, closure):
        self._config = config
        self._closure = self._nmap_closure = closure
        lab = ConfinedWebLab(config, closure)
        super().__init__(parse_policy(config['policy']), config['session_id'], SessionLimits(**config['limits']),
                         lab, execute=config['execute'])

    def _accept_lab(self, lab):
        return type(lab) is ConfinedWebLab

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=False)

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity['scenario'])):
            raise IsolationUnavailable('Confined web profile denied')
        self.lab._check_available()
