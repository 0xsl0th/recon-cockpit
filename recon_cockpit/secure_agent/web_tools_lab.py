"""One disposable reviewed web service for one practical-tool action."""

from pathlib import Path

from .owned_lab import OwnedLab
from .session_limits import SessionLimits
from .web_tools_lab_contract import identity, validate_context


class WebToolsLab(OwnedLab):
    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 1
                or limits.max_runtime_seconds > 60 or limits.max_output_bytes > 8192):
            raise ValueError("invalid_web_tools_lab_limits")
        super().__init__(case, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(case, instance_id)

    def _validate_context(self, value, expected):
        return validate_context(value, expected)

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).resolve().parent
        mounts = []
        for name in ("web_tools_lab_worker.py", "web_tools_fixture.py", "web_tools_tls_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-1] = "/app/web_tools_lab_worker.py"
        return argv
