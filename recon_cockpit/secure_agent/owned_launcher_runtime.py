"""Fixed nested adapters for the existing lab lifecycle and executor contract."""

from . import launch_admission as admission
from .isolation import IsolationUnavailable, _trusted_program
from .models import parse_policy
from .owned_lab import OwnedLab, AuthorizedOwnedLabBackend
from .owned_lab_contract import validate_identity
from .session_limits import SessionLimits


def runtime(closure, *, owner):
    excluded = {'/usr/bin/bwrap', '/usr/bin/nsenter'}
    if not owner:
        excluded.add('/usr/sbin/nft')
    return closure['stdlib'], [(p, p) for p in closure['files'] if p not in excluded]


class _ConfinedOwnedLab(OwnedLab):
    def __init__(self, config, closure):
        super().__init__(config['case'], config['session_id'], SessionLimits(**config['limits']), execute=config['execute'])
        # Identity was fixed by the trusted bootstrap before any process started.
        self._identity = validate_identity(config['owned_lab'], case=config['case'])
        self._closure = closure

    def _runtime(self, control):
        control.check()
        return runtime(self._closure, owner=True)

    def _check_available(self):
        # The outer worker already verified nonroot namespaces/capabilities and
        # the exact runtime manifest. No runtime inspection shell is mounted.
        for name in ('bwrap', 'nft', 'nsenter'):
            _trusted_program(name)


class ConfinedOwnedBackend(AuthorizedOwnedLabBackend):
    def __init__(self, config, closure):
        self._config = config
        self._closure = closure
        lab = _ConfinedOwnedLab(config, closure)
        super().__init__(parse_policy(config['policy']), config['session_id'], SessionLimits(**config['limits']),
                         lab, execute=config['execute'])

    def _accept_lab(self, lab):
        return type(lab) is _ConfinedOwnedLab

    def _runtime(self, control):
        control.check()
        return runtime(self._closure, owner=False)

    def check_available(self, action=None):
        if not self._execute or (action is not None and not admission.profile_allows(action, self._config)):
            raise IsolationUnavailable('Confined lab profile denied')
        self.lab._check_available()
