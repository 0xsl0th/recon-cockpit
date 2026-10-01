"""Separate owned Nmap/header capability; accepted HTTP profiles stay fixed."""

import base64
from pathlib import Path
import threading

from .http_headers_contract import BACKEND, profile_allows, validate_result_context
from .http_headers_lab import HTTPHeadersLab
from .http_headers_lab_contract import validate_identity
from .isolation import IsolationUnavailable, LinuxFixtureBackend, _trusted_program
from .models import Action, parse_policy
from .nmap_backend import AuthorizedNmapOwnedBackend
from .owned_lab import AuthorizedOwnedLabBackend
from .session_limits import SessionLimits


class AuthorizedHTTPHeadersBackend(AuthorizedNmapOwnedBackend):
    name = BACKEND
    supported_tools = ("nmap_tcp_connect_v1", "http_headers_v1")
    launch_mode = _envelope_mode = _nmap_mode = "owned_http_headers_lab"
    _nmap_launch_mode = "nmap_http_headers_owned"
    _executor_mode = "http_headers_owned"
    _http_tools = ("http_headers_v1",)
    _closure = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._operation_lock = threading.Lock()

    def _accept_lab(self, lab):
        return type(lab) is HTTPHeadersLab

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity["scenario"])):
            raise IsolationUnavailable("Owned HTTP headers profile denied")
        LinuxFixtureBackend.check_available(self, action)
        self.lab._check_available()

    def _validate_result_context(self, result, *, action):
        return validate_result_context(result, self._lab_identity, previous=self._previous_context,
                                       tool_id=action.tool_id, execution_status=result["status"])

    def _command(self, stdlib, files, nonce, context_digest):
        argv = super()._command(stdlib, files, nonce, context_digest)
        mounts = []
        for name in ("http_headers_lab_contract", "http_headers_fixture", "http_headers_operation"):
            mounts += ["--ro-bind", str(Path(__file__).with_name(name + ".py").resolve()),
                       "/app/recon_cockpit/secure_agent/" + name + ".py"]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        return argv

    def run(self, action, policy, *, control=None):
        if not self._operation_lock.acquire(blocking=False):
            raise IsolationUnavailable("HTTP headers executor is already running")
        try:
            return self._run(action, policy, control=control)
        finally:
            self._operation_lock.release()

    def _run(self, action, policy, *, control):
        if type(action) is Action and action.tool_id == "nmap_tcp_connect_v1":
            return super().run(action, policy, control=control)
        if type(action) is not Action or action.tool_id != "http_headers_v1":
            raise IsolationUnavailable("Unsupported HTTP headers capability")
        try:
            result = AuthorizedOwnedLabBackend.run(self, action, policy, control=control)
            result["http_headers"] = None
            if result["status"] == "succeeded" and result["truncated"] is False:
                from .http_headers_parser_runtime import parse_isolated_headers
                raw = base64.b64decode(result["results"][0]["raw_response"], validate=True)
                try:
                    result["http_headers"] = parse_isolated_headers(raw, control=control, closure=self._closure)
                except ValueError:
                    # Transport success alone says nothing about HTTP validity.
                    result["http_headers"] = None
            control.check()
            return result
        except BaseException:
            self.lab.close()
            raise


class ConfinedHTTPHeadersLab(HTTPHeadersLab):
    def __init__(self, config, closure):
        super().__init__(config["case"], config["session_id"], SessionLimits(**config["limits"]),
                         execute=config["execute"])
        self._identity = validate_identity(config["owned_lab"], case=config["case"])
        self._closure = closure

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=True)

    def _check_available(self):
        for name in ("bwrap", "nft", "nsenter"):
            _trusted_program(name)


class ConfinedHTTPHeadersBackend(AuthorizedHTTPHeadersBackend):
    def __init__(self, config, closure):
        self._config = config
        self._closure = self._nmap_closure = closure
        lab = ConfinedHTTPHeadersLab(config, closure)
        super().__init__(parse_policy(config["policy"]), config["session_id"], SessionLimits(**config["limits"]),
                         lab, execute=config["execute"])

    def _accept_lab(self, lab):
        return type(lab) is ConfinedHTTPHeadersLab

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=False)

    def check_available(self, action=None):
        if not self._execute or (action is not None and not profile_allows(action, self._lab_identity["scenario"])):
            raise IsolationUnavailable("Confined HTTP headers profile denied")
        self.lab._check_available()
