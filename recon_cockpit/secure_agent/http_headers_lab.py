"""Fixed HTTP-header fixture with the reviewed disposable owner lifecycle."""

from pathlib import Path

from .owned_lab import OwnedLab
from .session_limits import SessionLimits
from .http_headers_lab_contract import identity, validate_context


class HTTPHeadersLab(OwnedLab):
    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 3
                or limits.max_runtime_seconds > 60 or limits.max_output_bytes > 18432):
            raise ValueError("invalid_http_headers_lab_limits")
        super().__init__(case, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(case, instance_id)

    def _validate_context(self, value, expected):
        return validate_context(value, expected)

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).resolve().parent
        mounts = []
        for name in ("http_headers_lab_worker.py", "http_headers_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-1] = "/app/http_headers_lab_worker.py"
        return argv
