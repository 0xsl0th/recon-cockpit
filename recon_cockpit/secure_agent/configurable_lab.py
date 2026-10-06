"""Two bounded endpoint owners reuse the accepted disposable lab lifecycle."""

import copy
from pathlib import Path

from .configurable_lab_contract import (assessment_identity, identity, validate_assessment_identity,
                                        validate_context, validate_identity)
from .configurable_scope import validate_scope
from .isolation import IsolationUnavailable, _trusted_program
from .owned_lab import OwnedLab
from .session_limits import SessionLimits


class ConfigurableEndpointLab(OwnedLab):
    def __init__(self, scope, endpoint_name, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 4
                or limits.max_runtime_seconds > 60 or limits.max_output_bytes > 26624):
            raise ValueError("invalid_configurable_lab_limits")
        self.scope = validate_scope(scope)
        self.endpoint_name = endpoint_name
        super().__init__(endpoint_name, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(self.scope, case, instance_id)

    def _validate_context(self, value, expected):
        validate_identity(expected, scope=self.scope, endpoint_name=self.endpoint_name)
        return validate_context(value, expected)

    def _check(self, control):
        super()._check(control)
        try:
            validate_identity(self._identity, scope=self.scope, endpoint_name=self.endpoint_name)
        except ValueError as exc:
            raise IsolationUnavailable("Configurable endpoint scope changed") from exc

    def _owner_request(self, host, control):
        return {"scope": validate_scope(self.scope), "endpoint": self.endpoint_name,
                "deadline": control.deadline, "host_namespaces": host}

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        directory = Path(__file__).resolve().parent
        mounts = []
        for name in ("configurable_lab_worker.py", "configurable_scope.py", "http_headers_fixture.py",
                     "network_tools_fixture.py", "network_tools_ssh_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        index = argv.index("--remount-ro")
        argv[index:index] = mounts
        argv[-1] = "/app/configurable_lab_worker.py"
        return argv


class ConfigurableLab:
    """Metadata-only construction; actions start only their selected endpoint."""

    def __init__(self, scope, session_id, limits, *, execute=True):
        self.scope = validate_scope(scope)
        self.session_id, self.limits, self.execute = session_id, limits, execute
        self._endpoints = {name: ConfigurableEndpointLab(self.scope, name, session_id, limits, execute=execute)
                           for name in ("http", "ssh")}
        self._identity = assessment_identity(self.scope, {name: lab.identity for name, lab in self._endpoints.items()})
        self._closed = False
        self._receipt = None

    @property
    def identity(self):
        return copy.deepcopy(self._identity)

    @property
    def started(self):
        return any(lab.started for lab in self._endpoints.values())

    def endpoint_lab(self, name):
        if self._closed or type(name) is not str or name not in self._endpoints:
            raise IsolationUnavailable("Configurable lab endpoint is unavailable")
        if validate_assessment_identity(self._identity)["scope"] != validate_scope(self.scope):
            raise IsolationUnavailable("Configurable lab scope changed")
        lab = self._endpoints[name]
        if lab.identity != self._identity["endpoints"][name]:
            raise IsolationUnavailable("Configurable endpoint identity changed")
        return lab

    def __enter__(self):
        if self._closed:
            raise IsolationUnavailable("Configurable lab is permanently closed")
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if self._receipt is not None:
            return copy.deepcopy(self._receipt)
        self._closed = True
        receipts, failure = {}, None
        for name, lab in self._endpoints.items():
            try:
                receipts[name] = lab.close()
            except BaseException as exc:
                failure = exc
        if failure is not None:
            raise failure
        self._receipt = {"identity": self.identity, "status": "closed", "endpoints": receipts}
        return copy.deepcopy(self._receipt)


class ConfinedConfigurableEndpointLab(ConfigurableEndpointLab):
    def __init__(self, scope, endpoint_name, config, closure):
        super().__init__(scope, endpoint_name, config["session_id"], SessionLimits(**config["limits"]),
                         execute=config["execute"])
        self._identity = validate_identity(config["owned_lab"]["endpoints"][endpoint_name],
                                           scope=scope, endpoint_name=endpoint_name)
        self._closure = closure

    def _runtime(self, control):
        from .owned_launcher_runtime import runtime
        control.check()
        return runtime(self._closure, owner=True)

    def _check_available(self):
        for name in ("bwrap", "nft", "nsenter"):
            _trusted_program(name)


class ConfinedConfigurableLab(ConfigurableLab):
    def __init__(self, config, closure):
        fixed = validate_assessment_identity(config["owned_lab"])
        self.scope = fixed["scope"]
        self.session_id, self.limits = config["session_id"], SessionLimits(**config["limits"])
        self.execute = config["execute"]
        self._endpoints = {name: ConfinedConfigurableEndpointLab(self.scope, name, config, closure)
                           for name in ("http", "ssh")}
        self._identity = fixed
        self._closed = False
        self._receipt = None
