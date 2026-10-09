"""Finite three-capability lab using the accepted disposable owner lifecycle."""

from pathlib import Path

from .owned_lab import OwnedLab
from .session_limits import SessionLimits
from .service_web_lab_contract import identity, validate_context


class ServiceWebLab(OwnedLab):
    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 3
                or limits.max_runtime_seconds > 60 or limits.max_output_bytes > 18432):
            raise ValueError("invalid_service_web_lab_limits")
        super().__init__(case, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(case, instance_id)

    def _validate_context(self, value, expected):
        return validate_context(value, expected)

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).resolve().parent
        mounts = []
        for name in ("service_web_lab_worker.py", "service_web_fixture.py",
                     "http_headers_fixture.py", "network_tools_fixture.py", "web_tools_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-1] = "/app/service_web_lab_worker.py"
        return argv
