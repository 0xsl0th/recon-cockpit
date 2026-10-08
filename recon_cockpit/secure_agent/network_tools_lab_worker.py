"""Fixed DNS/TLS owner; no upstream queries, credentials or application sessions."""

import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import ssl
import struct
import time

if __package__:
    from . import owned_lab_worker as owner, network_tools_fixture as fixture, web_tools_tls_fixture as tls_material
    from . import network_tools_ssh_fixture as ssh_fixture
    from . import network_tools_smb_fixture as smb_fixture
    from . import network_tools_rpc_fixture as rpc_fixture
    from . import network_tools_ftp_smtp_fixture as ftp_smtp_fixture
    from . import network_tools_http_metadata_fixture as http_metadata_fixture
    from . import network_tools_nmap_fixture as nmap_service_fixture
    from . import network_tools_kerberos_fixture as kerberos_fixture
    from . import network_tools_redis_snmp_fixture as redis_snmp_fixture
    from . import network_tools_database_tls_fixture as database_tls_fixture
    from . import network_tools_whatweb_fixture as whatweb_fixture
    from . import network_tools_dns_srv_fixture as dns_srv_fixture
    from . import network_tools_dns_nsid_fixture as dns_nsid_fixture
    from . import network_tools_snmp_next_fixture as snmp_next_fixture
    from . import network_tools_http_options_fixture as http_options_fixture
    from . import network_tools_dns_axfr_fixture as dns_axfr_fixture
    from . import network_tools_rdp_fixture as rdp_fixture
    from . import network_tools_smb2_fixture as smb2_fixture
    from . import network_tools_smtp_tls_fixture as smtp_tls_fixture
    from . import network_tools_ldap_tls_fixture as ldap_tls_fixture
    from . import network_tools_ftp_tls_fixture as ftp_tls_fixture
else:
    def _load(name, filename):
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    owner = _load("network_tools_fixed_owner", "owned_lab_worker.py")
    fixture = _load("network_tools_fixed_fixture", "network_tools_fixture.py")
    tls_material = _load("network_tools_fixed_tls", "web_tools_tls_fixture.py")
    ssh_fixture = _load("network_tools_fixed_ssh", "network_tools_ssh_fixture.py")
    smb_fixture = _load("network_tools_fixed_smb", "network_tools_smb_fixture.py")
    rpc_fixture = _load("network_tools_fixed_rpc", "network_tools_rpc_fixture.py")
    ftp_smtp_fixture = _load("network_tools_fixed_ftp_smtp", "network_tools_ftp_smtp_fixture.py")
    http_metadata_fixture = _load("network_tools_fixed_http_metadata", "network_tools_http_metadata_fixture.py")
    nmap_service_fixture = _load("network_tools_fixed_nmap_service", "network_tools_nmap_fixture.py")
    kerberos_fixture = _load("network_tools_fixed_kerberos", "network_tools_kerberos_fixture.py")
    redis_snmp_fixture = _load("network_tools_fixed_redis_snmp", "network_tools_redis_snmp_fixture.py")
    database_tls_fixture = _load("network_tools_fixed_database_tls", "network_tools_database_tls_fixture.py")
    whatweb_fixture = _load("network_tools_fixed_whatweb", "network_tools_whatweb_fixture.py")
    dns_srv_fixture = _load("network_tools_fixed_dns_srv", "network_tools_dns_srv_fixture.py")
    dns_nsid_fixture = _load("network_tools_fixed_dns_nsid", "network_tools_dns_nsid_fixture.py")
    snmp_next_fixture = _load("network_tools_fixed_snmp_next", "network_tools_snmp_next_fixture.py")
    http_options_fixture = _load("network_tools_fixed_http_options", "network_tools_http_options_fixture.py")
    dns_axfr_fixture = _load("network_tools_fixed_dns_axfr", "network_tools_dns_axfr_fixture.py")
    rdp_fixture = _load("network_tools_fixed_rdp", "network_tools_rdp_fixture.py")
    smb2_fixture = _load("network_tools_fixed_smb2", "network_tools_smb2_fixture.py")
    smtp_tls_fixture = _load("network_tools_fixed_smtp_tls", "network_tools_smtp_tls_fixture.py")
    ldap_tls_fixture = _load("network_tools_fixed_ldap_tls", "network_tools_ldap_tls_fixture.py")
    ftp_tls_fixture = _load("network_tools_fixed_ftp_tls", "network_tools_ftp_tls_fixture.py")


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_network_tools_lab_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in fixture.CASES
            or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("invalid_network_tools_lab_request")
    return value


def tls_context(case):
    if (fixture.tool_for_case(case) != "openssl_tls_handshake_v1"
            and case not in fixture.DATABASE_TLS_CASES + fixture.SMTP_TLS_CASES + fixture.LDAP_TLS_CASES + fixture.FTP_TLS_CASES):
        raise ValueError("invalid_network_tools_tls_case")
    untrusted = case == "openssl-untrusted" or case in ("postgresql-tls-untrusted", "mysql-tls-untrusted", "smtp-tls-untrusted", "ldap-tls-untrusted", "ftp-tls-untrusted")
    cert = tls_material.UNTRUSTED_SERVER_CERT_PEM if untrusted else tls_material.SERVER_CERT_PEM
    expected = fixture.UNTRUSTED_SERVER_CERT_SHA256 if untrusted else fixture.SERVER_CERT_SHA256
    if hashlib.sha256(cert).hexdigest() != expected:
        raise ValueError("network_tools_tls_certificate_mismatch")
    descriptors = []
    try:
        for label, data in (("public-lab-cert", cert), ("public-lab-key", tls_material.SERVER_KEY_PEM)):
            fd = os.memfd_create(label, os.MFD_CLOEXEC)
            descriptors.append(fd)
            if os.write(fd, data) != len(data):
                raise ValueError("network_tools_tls_material_truncated")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(*(f"/proc/self/fd/{fd}" for fd in descriptors))
        return context
    finally:
        for fd in descriptors:
            os.close(fd)


def _read_exact(connection, count):
    result = bytearray()
    while len(result) < count:
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise ValueError("network_tools_dns_incomplete")
        result.extend(chunk)
    return bytes(result)


def read_dns_query(connection):
    size = struct.unpack("!H", _read_exact(connection, 2))[0]
    if not 12 <= size <= fixture.MAX_DNS_BYTES:
        raise ValueError("network_tools_dns_frame_limit")
    return fixture.validate_dns_query(_read_exact(connection, size))


def _ber(tag, body):
    size = len(body)
    if not size <= 4096:
        raise ValueError("ldap_fixture_size_limit")
    length = bytes([size]) if size < 128 else b"\x82" + struct.pack("!H", size)
    return bytes([tag]) + length + body


def _ldap_tlv(raw, offset=0):
    if offset + 2 > len(raw):
        raise ValueError("ldap_fixture_incomplete")
    tag, size = raw[offset:offset + 2]
    offset += 2
    if size & 0x80:
        count = size & 0x7f
        if not 1 <= count <= 2 or offset + count > len(raw):
            raise ValueError("ldap_fixture_length")
        size = int.from_bytes(raw[offset:offset + count], "big")
        offset += count
    if size > 4096 or offset + size > len(raw):
        raise ValueError("ldap_fixture_size_limit")
    return tag, raw[offset:offset + size], offset + size


def _ldap_message(connection):
    header = _read_exact(connection, 2)
    if header[0] != 0x30:
        raise ValueError("ldap_fixture_sequence")
    size = header[1]
    if size & 0x80:
        count = size & 0x7f
        if not 1 <= count <= 2:
            raise ValueError("ldap_fixture_length")
        size = int.from_bytes(_read_exact(connection, count), "big")
    if not 1 <= size <= 4096:
        raise ValueError("ldap_fixture_size_limit")
    raw = _read_exact(connection, size)
    tag, message_id, offset = _ldap_tlv(raw)
    if (tag != 2 or not 1 <= len(message_id) <= 4 or message_id[0] & 0x80
            or not 1 <= int.from_bytes(message_id, "big") <= 0x7fffffff):
        raise ValueError("ldap_fixture_message_id")
    operation, body, end = _ldap_tlv(raw, offset)
    if end != len(raw):
        raise ValueError("ldap_fixture_controls_forbidden")
    return message_id, operation, body


def _ldap_reply(message_id, operation, body):
    return _ber(0x30, _ber(2, message_id) + _ber(operation, body))


def _ldap_search_valid(body):
    expected = ((4, b""), (10, b"\x00"), (10, b"\x00"), (2, b"\x01"), (2, b"\x02"),
                (1, b"\x00"), (0x87, b"objectClass"))
    offset = 0
    for wanted_tag, wanted_body in expected:
        tag, value, offset = _ldap_tlv(body, offset)
        if (tag, value) != (wanted_tag, wanted_body):
            raise ValueError("ldap_fixture_search_scope")
    tag, attributes, offset = _ldap_tlv(body, offset)
    if tag != 0x30 or offset != len(body):
        raise ValueError("ldap_fixture_attributes")
    offset, names = 0, []
    while offset < len(attributes):
        tag, name, offset = _ldap_tlv(attributes, offset)
        if tag != 4:
            raise ValueError("ldap_fixture_attribute")
        names.append(name)
    if tuple(names) != tuple(name.encode("ascii") for name in fixture.LDAP_ATTRIBUTES):
        raise ValueError("ldap_fixture_attributes")


def _ldap_entry(case):
    values = {} if case == "ldap-empty" else dict(fixture.LDAP_VALUES)
    if case == "ldap-injected":
        values["description"] = (fixture.HOSTILE_NOTE,)
    attributes = b"".join(_ber(0x30, _ber(4, name.encode("ascii")) + _ber(0x31,
        b"".join(_ber(4, value.encode("ascii")) for value in entries))) for name, entries in values.items())
    return _ber(4, b"") + _ber(0x30, attributes)


class NetworkToolsService(owner.Service):
    def __init__(self, request, listener):
        self.deadline = request["deadline"]
        self.context = (tls_context(request["case"]) if request["case"].startswith("openssl-")
                        or request["case"] in fixture.DATABASE_TLS_CASES + fixture.SMTP_TLS_CASES + fixture.LDAP_TLS_CASES + fixture.FTP_TLS_CASES else None)
        self.rpc = (rpc_fixture.Exchange(request["case"], self._smb_enumerated)
                    if request["case"].startswith(("rpc-", "nfs-")) else None)
        self.kerberos = (kerberos_fixture.Exchange(request["case"], self._smb_enumerated)
                         if request["case"].startswith("kerberos-") else None)
        super().__init__(request["case"], listener)

    def _smb_enumerated(self):
        with self.condition:
            self.requests += 1
            self.condition.notify_all()

    def _ftp_data_connected(self):
        with self.condition:
            if self.connections != 1:
                raise ValueError("ftp_fixture_data_connection_limit")
            self.connections += 1
            self.condition.notify_all()

    def _ldap(self, connection):
        message_id, operation, body = _ldap_message(connection)
        if operation != 0x60 or body != b"\x02\x01\x03\x04\x00\x80\x00":
            raise ValueError("ldap_fixture_anonymous_bind_only")
        success = b"\x0a\x01\x00\x04\x00\x04\x00"
        connection.sendall(_ldap_reply(message_id, 0x61, success))
        search_id, operation, body = _ldap_message(connection)
        if operation != 0x63 or search_id == message_id:
            raise ValueError("ldap_fixture_single_search")
        _ldap_search_valid(body)
        with self.condition:
            self.requests += 1
            self.condition.notify_all()
        if self.case == "ldap-stalled":
            time.sleep(owner.worker._remaining(self.deadline, 60))
            return
        if self.case == "ldap-malformed":
            connection.sendall(b"\x30\x80\x02\x01\x02")  # Indefinite/incomplete BER is unsupported.
            return
        if self.case == "ldap-referral":
            result = b"\x0a\x01\x0a\x04\x00\x04\x00" + _ber(0xa3, _ber(4, fixture.LDAP_REFERRAL.encode("ascii")))
            connection.sendall(_ldap_reply(search_id, 0x65, result))
        else:
            connection.sendall(_ldap_reply(search_id, 0x64, _ldap_entry(self.case))
                               + _ldap_reply(search_id, 0x65, success))
        # One optional unbind closes the connection. No second query, SASL,
        # StartTLS, authentication or controls are accepted.
        unbind_id, operation, body = _ldap_message(connection)
        if operation != 0x42 or body or unbind_id in (message_id, search_id):
            raise ValueError("ldap_fixture_unbind_only")

    def _serve(self):
        try:
            while True:
                raw, _ = self.listener.accept()
                if self.case.startswith("kerberos-") and (self.connections >= fixture.KERBEROS_MAX_CONNECTIONS
                        or self.requests >= fixture.KERBEROS_MAX_REQUESTS):
                    raw.close()
                    raise RuntimeError("kerberos_fixture_exchange_limit")
                if self.rpc is not None and self.connections >= rpc_fixture.MAX_CONNECTIONS:
                    raw.close()
                    raise RuntimeError("rpc_fixture_connection_limit")
                if self.case.startswith("nmap-service-") and self.connections >= fixture.NMAP_SERVICE_MAX_CONNECTIONS:
                    raw.close()
                    raise RuntimeError("nmap_service_fixture_connection_limit")
                if self.case.startswith("nmap-service-") and self.requests >= 1:
                    raw.close()
                    raise RuntimeError("nmap_service_fixture_request_limit")
                if self.case.startswith(("ftp-", "smtp-", "docker-ping-", "docker-version-", "winrm-", "redis-", "snmp-",
                                         "postgresql-tls-", "mysql-tls-", "whatweb-", "dig-srv-", "dig-nsid-", "dig-axfr-", "http-options-", "rdp-", "smb2-", "ldap-tls-")) and self.connections:
                    raw.close()
                    raise RuntimeError("single_metadata_fixture_connection_limit")
                with self.condition:
                    self.connections += 1
                    self.condition.notify_all()
                connection = raw
                try:
                    raw.settimeout(owner.worker._remaining(self.deadline, 2))
                    if self.case in fixture.FTP_TLS_CASES:
                        ftp_tls_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            context=self.context, on_request=self._smb_enumerated)
                    elif self.case in fixture.LDAP_TLS_CASES:
                        ldap_tls_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            context=self.context, on_request=self._smb_enumerated)
                    elif self.case in fixture.SMTP_TLS_CASES:
                        smtp_tls_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            context=self.context, on_request=self._smb_enumerated)
                    elif self.case in fixture.SMB2_CASES:
                        smb2_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.RDP_CASES:
                        rdp_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.SNMP_NEXT_CASES:
                        snmp_next_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.HTTP_OPTIONS_CASES:
                        http_options_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.DNS_AXFR_CASES:
                        dns_axfr_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.DNS_NSID_CASES:
                        dns_nsid_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.DNS_SRV_CASES:
                        dns_srv_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.WHATWEB_CASES:
                        whatweb_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case in fixture.DATABASE_TLS_CASES:
                        database_tls_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            context=self.context, on_request=self._smb_enumerated)
                    elif self.case in fixture.REDIS_SNMP_CASES:
                        redis_snmp_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case.startswith("kerberos-"):
                        kerberos_fixture.serve(connection, self.kerberos, self.deadline)
                    elif self.case.startswith("nmap-service-"):
                        nmap_service_fixture.serve(connection, case=self.case, connection_index=self.connections,
                            deadline=self.deadline, on_metadata=self._smb_enumerated)
                    elif self.case.startswith(("docker-ping-", "docker-version-", "winrm-")):
                        http_metadata_fixture.serve(connection, case=self.case, deadline=self.deadline,
                            on_request=self._smb_enumerated)
                    elif self.case.startswith("ftp-"):
                        ftp_smtp_fixture.serve_ftp(connection, self.listener, case=self.case,
                            deadline=self.deadline, on_listing=self._smb_enumerated,
                            on_data_connection=self._ftp_data_connected)
                    elif self.case.startswith("smtp-"):
                        ftp_smtp_fixture.serve_smtp(connection, case=self.case, deadline=self.deadline,
                            on_ehlo=self._smb_enumerated)
                    elif self.rpc is not None:
                        if self.connections > rpc_fixture.MAX_CONNECTIONS:
                            raise ValueError("rpc_fixture_connection_limit")
                        rpc_fixture.serve(connection, self.rpc, self.deadline)
                    elif self.case.startswith("smb-"):
                        smb_fixture.serve(connection, case=self.case, shares=fixture.smb_shares(self.case),
                            deadline=self.deadline, on_enumeration=self._smb_enumerated)
                    elif self.case.startswith("ssh-"):
                        if self.case == "ssh-stalled":
                            time.sleep(owner.worker._remaining(self.deadline, 60))
                        elif self.case == "ssh-malformed":
                            connection.sendall(b"SSH-2.0-HarborDesk_owned_fixture\r\n\xff\xff\xff\xff")
                        else:
                            banner = fixture.SSH_BANNER + (b" " + fixture.HOSTILE_NOTE.encode("ascii")
                                if self.case == "ssh-injected" else b"")
                            ssh_fixture.serve(connection, banner=banner, deadline=self.deadline)
                            with self.condition:
                                self.requests += 1
                                self.condition.notify_all()
                    elif self.case.startswith("ldap-"):
                        self._ldap(connection)
                    elif self.context is None:
                        query = read_dns_query(connection)
                        with self.condition:
                            self.requests += 1
                            self.condition.notify_all()
                        if self.case.endswith("-stalled"):
                            time.sleep(owner.worker._remaining(self.deadline, 60))
                        else:
                            reply = fixture.dns_response(self.case, query)
                            connection.sendall(struct.pack("!H", len(reply)) + reply)
                    elif self.case == "openssl-stalled":
                        time.sleep(owner.worker._remaining(self.deadline, 60))
                    elif self.case == "openssl-malformed":
                        connection.sendall(fixture.TLS_MALFORMED_BYTES)
                    else:
                        connection = self.context.wrap_socket(raw, server_side=True)
                        with self.condition:
                            self.requests += 1  # Completed server handshake, not HTTP.
                            self.condition.notify_all()
                        # Send close_notify without sending or accepting application data.
                        connection = connection.unwrap()
                except (OSError, ValueError, UnicodeError):
                    pass
                finally:
                    connection.close()
                    raw.close()
        except BaseException:
            with self.condition:
                self.failed = True
                self.condition.notify_all()


class NetworkToolsOwner(owner.Owner):
    def read_request(self, source):
        return read_request(source)

    def service_port(self, request):
        return rpc_fixture.PORT if request["case"].startswith(("rpc-", "nfs-")) else super().service_port(request)

    def firewall_rules(self, request):
        return rpc_fixture.firewall_rules() if request["case"].startswith(("rpc-", "nfs-")) else super().firewall_rules(request)

    def create_service(self, request, listener):
        return NetworkToolsService(request, listener)


def main():
    return NetworkToolsOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
