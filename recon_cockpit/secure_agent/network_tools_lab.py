"""Disposable owned service for one reviewed network metadata tool action."""

from pathlib import Path

from .owned_lab import OwnedLab
from .session_limits import SessionLimits
from .network_tools_lab_contract import identity, validate_context


class NetworkToolsLab(OwnedLab):
    def __init__(self, case, session_id, limits, *, execute=True):
        if (type(limits) is not SessionLimits or limits.max_steps > 1
                or limits.max_runtime_seconds > 60 or limits.max_output_bytes > 8192):
            raise ValueError("invalid_network_tools_lab_limits")
        super().__init__(case, session_id, limits, execute=execute)

    def _make_identity(self, case, instance_id):
        return identity(case, instance_id)

    def _validate_context(self, value, expected):
        return validate_context(value, expected)

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
                     "network_tools_whatweb_fixture.py", "network_tools_dns_srv_fixture.py", "network_tools_dns_nsid_fixture.py", "network_tools_dns_axfr_fixture.py", "network_tools_rdp_fixture.py", "network_tools_smb2_fixture.py", "network_tools_smtp_tls_fixture.py", "network_tools_ldap_tls_fixture.py", "network_tools_ftp_tls_fixture.py"):
            mounts += ["--ro-bind", str(directory / name), "/app/" + name]
        argv[argv.index("--remount-ro"):argv.index("--remount-ro")] = mounts
        argv[-1] = "/app/network_tools_lab_worker.py"
        return argv
