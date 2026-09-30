"""Fixed HarborDesk owner using the existing single-session isolated lifecycle."""

from __future__ import annotations

from pathlib import Path

from .owned_lab import OwnedLab
from .session_limits import SessionLimits
from .web_lab_contract import identity, validate_context


class WebLab(OwnedLab):
    """A new lab profile; the legacy owner, identity and fixtures stay separate."""

    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 3
                or limits.max_runtime_seconds > 60 or limits.max_output_bytes > 18432):
            raise ValueError("invalid_web_lab_limits")
        super().__init__(case, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(case, instance_id)

    def _validate_context(self, value, expected):
        return validate_context(value, expected)

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).resolve().parent
        index = argv.index("--remount-ro")
        mounts = []
        for module in ("web_lab_worker.py", "web_fixture.py"):
            mounts.extend(("--ro-bind", str(directory / module), "/app/" + module))
        argv[index:index] = mounts
        argv[-1] = "/app/web_lab_worker.py"
        return argv
