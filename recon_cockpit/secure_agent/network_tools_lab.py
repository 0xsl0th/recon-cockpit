"""Disposable owned service for one reviewed network metadata tool action."""

from pathlib import Path
import copy

from .owned_lab import OwnedLab, encode
from .isolation import IsolationUnavailable
from .session_limits import SessionLimits
from .network_tools_lab_contract import identity, validate_context, decode_owner_response
from .network_tools_tls_posture_spec import CASES as TLS_POSTURE_CASES


class NetworkToolsLab(OwnedLab):
    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 1
                or limits.max_runtime_seconds > (30 if case in TLS_POSTURE_CASES else 60)
                or limits.max_output_bytes > 8192):
            raise ValueError("invalid_network_tools_lab_limits")
        super().__init__(case, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(case, instance_id)

    def _validate_context(self, value, expected):
        return validate_context(value, expected)

    def _read_message(self):
        if self._identity["scenario"] in TLS_POSTURE_CASES:
            from .network_tools_tls_posture_lab import read_message
            return read_message(self)
        if not self._identity["scenario"].startswith("nuclei-"):
            return super()._read_message()
        supervisor = self._supervisor
        supervisor.wait_for(lambda: b"\n" in supervisor.buffers["lab_out"][self._offset:])
        buffered = supervisor.buffers["lab_out"]
        end = buffered.index(b"\n", self._offset) + 1
        raw = bytes(buffered[self._offset:end])
        # Only this profile transports <=4096 original owner bytes in base64.
        if len(raw) > 8192:
            raise IsolationUnavailable("Nuclei owner receipt exceeds its bound")
        self._offset = end
        try:
            from .models import load_json
            return load_json(raw)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise IsolationUnavailable("Nuclei owner returned invalid management evidence") from exc

    def start(self, control):
        if self._identity["scenario"] in TLS_POSTURE_CASES:
            from .network_tools_tls_posture_lab import start
            return start(self, control)
        return super().start(control)

    def snapshot(self, control, *, minimum_connections=None, minimum_requests=None):
        if self._identity["scenario"] in TLS_POSTURE_CASES:
            from .network_tools_tls_posture_lab import snapshot
            return snapshot(self, control, minimum_connections=minimum_connections,
                            minimum_requests=minimum_requests)
        if not self._identity["scenario"].startswith("nuclei-"):
            return super().snapshot(control, minimum_connections=minimum_connections, minimum_requests=minimum_requests)
        with self._lock:
            try:
                self._check(control)
                if not self._started:
                    raise IsolationUnavailable("Owned lab has not started")
                self._verify_pins()
                minimum_connections = self._counts["connection_count"] if minimum_connections is None else minimum_connections
                minimum_requests = self._counts["request_count"] if minimum_requests is None else minimum_requests
                if any(type(value) is not int or not 0 <= value <= 1 for value in (minimum_connections, minimum_requests)):
                    raise IsolationUnavailable("Nuclei owner counter barrier is invalid")
                self._sequence += 1
                self._supervisor.processes["lab"].stdin.write(encode({"sequence": self._sequence,
                    "minimum_connections": minimum_connections, "minimum_requests": minimum_requests}) + b"\n")
                value = self._read_message()
                if (type(value) is not dict or set(value) != {"sequence", "connection_count", "request_count", "owner_response"}
                        or type(value["sequence"]) is not int or value["sequence"] != self._sequence):
                    raise IsolationUnavailable("Nuclei owner acknowledgement is invalid")
                context = validate_context({"identity": self.identity,
                    **{key: item for key, item in value.items() if key != "sequence"}}, self.identity)
                if (any(context[key] < self._counts[key] for key in self._counts)
                        or context["connection_count"] < minimum_connections or context["request_count"] < minimum_requests):
                    raise IsolationUnavailable("Nuclei owner counters regressed or did not settle")
                receipt = context["owner_response"]
                previous = getattr(self, "_owner_response", None)
                if previous is not None:
                    before, after = decode_owner_response(previous), decode_owner_response(receipt)
                    if (not after.startswith(before)
                            or any(previous[key] and not receipt[key] for key in ("send_complete", "connection_closed"))
                            or (previous["connection_closed"] and receipt != previous)):
                        raise IsolationUnavailable("Nuclei owner response receipt regressed")
                self._counts = {key: context[key] for key in self._counts}
                self._owner_response = copy.deepcopy(receipt)
                self._check(control)
                return {**self._counts, "owner_response": copy.deepcopy(receipt)}
            except BaseException:
                self.close()
                raise

    def _owner_command(self, stdlib, files, info_fd):
        argv = super()._owner_command(stdlib, files, info_fd)
        if self._identity["scenario"].startswith(("rpc-", "nfs-")):
            # Only the owner needs to bind fixed ports 111/112 in its fresh
            # network namespace. Owner.run drops every capability before
            # starting the service; native clients never receive this grant.
            index = argv.index("--die-with-parent")
            argv[index:index] = ["--cap-add", "CAP_NET_BIND_SERVICE"]
        directory = Path(__file__).resolve().parent
        mounts = []
        for name in ("network_tools_lab_worker.py", "network_tools_fixture.py", "web_tools_tls_fixture.py",
                     "network_tools_ssh_fixture.py", "network_tools_smb_fixture.py", "network_tools_rpc_fixture.py",
                     "network_tools_ftp_smtp_fixture.py", "network_tools_http_metadata_fixture.py",
                     "network_tools_nmap_fixture.py", "network_tools_kerberos_fixture.py",
                     "network_tools_redis_snmp_fixture.py", "network_tools_database_tls_fixture.py",
                     "network_tools_whatweb_fixture.py", "network_tools_dns_mx_fixture.py", "network_tools_dns_srv_fixture.py", "network_tools_dns_nsid_fixture.py", "network_tools_dns_axfr_fixture.py", "network_tools_http_options_fixture.py", "network_tools_snmp_next_fixture.py", "network_tools_nuclei_fixture.py", "network_tools_nuclei_git_fixture.py", "network_tools_tls_certificate_fixture.py", "network_tools_tls_certificate_material.py", "network_tools_ssh_algorithms_fixture.py", "network_tools_rdp_fixture.py", "network_tools_smb2_fixture.py", "network_tools_smtp_tls_fixture.py", "network_tools_ldap_tls_fixture.py", "network_tools_ftp_tls_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        argv[argv.index("--remount-ro"):argv.index("--remount-ro")] = mounts
        argv[-1] = "/app/network_tools_lab_worker.py"
        if self._identity["scenario"] in TLS_POSTURE_CASES:
            additional = []
            for name in ("network_tools_tls_posture_owner.py", "network_tools_tls_posture_spec.py",
                         "network_tools_tls_posture_receipt.py", "tls_posture_mediated_owner.py",
                         "tls_posture_diagnostic_fixture.py", "tls_posture_mediator.py", "tls_posture_hello.py"):
                additional += ["--ro-bind", str(directory / name), "/app/" + name]
            index = argv.index("--remount-ro")
            argv[index:index] = additional
            argv[-1] = "/app/network_tools_tls_posture_owner.py"
        return argv
