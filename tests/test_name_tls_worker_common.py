"""Private 65534 payload mappings cannot be confused with host or setup root."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from recon_cockpit.secure_agent import name_tls_worker_common as common


@pytest.fixture
def private(monkeypatch):
    identity = {"uid": 65534, "gid": 65534, "uid_map": [[65534, 1000, 1]],
                "gid_map": [[65534, 1000, 1]], "groups": [65534]}
    host = {name: name + ":[10]" for name in ("user", "net", "mnt", "pid")}
    monkeypatch.setattr(common.sys, "platform", "linux")
    monkeypatch.setattr(common, "namespace_identity", lambda: deepcopy(identity))
    monkeypatch.setattr(common.os, "readlink", lambda path: path.rsplit("/", 1)[-1] + ":[20]")
    monkeypatch.setattr(common.os, "statvfs", lambda _: SimpleNamespace(f_flag=common.os.ST_RDONLY))
    monkeypatch.setattr(common.socket, "if_nameindex", lambda: [(1, "lo")])
    return host, identity


def test_private_check_accepts_only_exact_nonroot_mapping(private):
    host, identity = private
    assert common.assert_private_namespaces(host) == identity


@pytest.mark.parametrize("change", ("host_net", "host_user", "attached", "writable", "extra_namespace"))
def test_host_or_attached_namespace_refused_before_setup(monkeypatch, private, change):
    host, identity = private
    if change.startswith("host_"):
        name = change[5:]
        host[name] = name + ":[20]"
    elif change == "attached":
        monkeypatch.setattr(common.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    elif change == "writable":
        monkeypatch.setattr(common.os, "statvfs", lambda _: SimpleNamespace(f_flag=0))
    else: host["uts"] = "uts:[10]"
    with pytest.raises(ValueError):
        common.assert_private_namespaces(host)


def test_self_mapping_keeps_bubblewrap_intermediary_distinct_from_host_identity(private):
    host, identity = private
    identity["uid_map"][0][1] = identity["gid_map"][0][1] = 0
    identity["groups"] = [65534] * 17
    assert common.assert_private_namespaces(host) == identity


@pytest.mark.parametrize("groups", ([65534] * 65, [0], [65534, 1000], [True]))
def test_supplementary_groups_remain_bounded_unprivileged_and_exact(groups):
    from recon_cockpit.secure_agent.name_tls_topology_spec import validate_namespace_identity
    value = {"uid": 65534, "gid": 65534, "uid_map": [[65534, 0, 1]], "gid_map": [[65534, 0, 1]], "groups": groups}
    with pytest.raises(ValueError):
        validate_namespace_identity(value)


def test_group_mutation_must_be_physically_refused(monkeypatch, private):
    _, identity = private
    monkeypatch.setattr(common.os, "setgroups", lambda _: None)
    with pytest.raises(ValueError, match="groups_mutable"):
        common.seal_group_identity(identity)
    def refused(_):
        raise PermissionError()
    monkeypatch.setattr(common.os, "setgroups", refused)
    assert common.seal_group_identity(identity) == identity
    changed = deepcopy(identity)
    changed["groups"] = []
    with pytest.raises(ValueError, match="identity_changed"):
        common.seal_group_identity(changed)


def test_import_descriptor_cleanup_requires_preimport_entry_inventory():
    with pytest.raises(ValueError, match="unverified"):
        common.close_import_descriptor(entry_verified=False)
