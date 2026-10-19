"""Hostile metadata cannot recreate or widen the owned DNS/name/TLS network."""
from copy import deepcopy
import ipaddress
import pytest
from recon_cockpit.secure_agent import name_tls_topology_spec as spec


def network_state(configuration="A"):
    result = {}
    for role in spec.ROLES:
        links = [{"interface": "lo", "index": 1, "peer_index": None, "kind": "loopback", "up": True}]
        if role == "router":
            links += [{"interface": row[1], "index": 10 + index, "peer_index": 2, "kind": "veth", "up": True}
                      for index, row in enumerate(spec.LINKS)]
        else:
            peer = 10 + next(index for index, row in enumerate(spec.LINKS) if row[0] == role)
            links.append({"interface": "eth0", "index": 2, "peer_index": peer, "kind": "veth", "up": True})
        addresses = spec.expected_addresses(role, configuration=configuration)
        routes = [{"table": 254, "destination": destination, "prefix": 32, "gateway": gateway,
                   "interface": interface, "protocol": 4, "scope": 0, "type": 1}
                  for destination, gateway, interface in spec.routes(role, configuration=configuration)]
        for address in addresses:
            if address["prefix"] != 30:
                continue
            network = ipaddress.IPv4Network(address["address"] + "/30", strict=False)
            routes.append({"table": 254, "destination": str(network.network_address), "prefix": 30,
                           "gateway": None, "interface": address["interface"], "protocol": 2, "scope": 253, "type": 1})
        result[role] = {"links": links, "addresses": addresses, "routes": routes, "ipv4_forwarding": role == "router", "ipv6_disabled": True}
    return result


def metadata(configuration="A"):
    networks = {role: f"net:[{30 + index}]" for index, role in enumerate(spec.ROLES)}
    value = {"ready": True, "profile": spec.PROFILE, "topology_sha256": spec.digest(configuration=configuration),
        "user": "user:[20]", "networks": networks,
        "owner_namespaces": {"user": "user:[20]", "net": networks["router"], "mnt": "mnt:[40]", "pid": "pid:[50]"},
        "listeners": {}, "baselines": [], "filtered": [], "bounds": deepcopy(spec.BOUNDS),
        "setup_helpers": 6, "capabilities_dropped": True, "setup_disabled": True,
        "exports": list(spec.EXPORTS), "network_state": network_state(configuration),
        "descriptor_custody": {"before_export": 25, "steady": 19},
        "namespace_identity": {"uid": 65534, "gid": 65534, "uid_map": [[65534, 65534, 1]],
                               "gid_map": [[65534, 65534, 1]], "groups": [65534]}}
    for index, (name, endpoint) in enumerate(spec.endpoints(configuration).items()):
        cookie = 300 if name.endswith("excluded") else 100 if name.startswith("dns") else 200
        value["listeners"][name] = {"inode": 1000 + index, "local": list(endpoint), "netns_cookie": cookie}
    for client in spec.OPERATIONS:
        for endpoint in spec.endpoints(configuration):
            value["baselines"].append({"client": client, "endpoint": endpoint, "connected": True})
            value["filtered"].append({"client": client, "endpoint": endpoint, "connected": client == endpoint})
    return value


@pytest.mark.parametrize("configuration", ("A", "B"))
def test_six_networks_export_only_thirteen_exact_descriptors(configuration):
    value = spec.validate_metadata(metadata(configuration), configuration=configuration)
    assert len(spec.ROLES) == 6 and len(spec.LINKS) == 5 and len(spec.EXPORTS) == 13
    assert len(value["listeners"]) == 9
    assert len(value["baselines"]) == len(value["filtered"]) == 27
    assert sum(not row["connected"] for row in value["filtered"]) == 24
    assert spec.endpoints(configuration)["dns_excluded"][0] == ("10.77.0.99" if configuration == "A" else "172.23.0.99")
    assert value["listeners"]["http"]["netns_cookie"] == value["listeners"]["tls"]["netns_cookie"]
    assert spec.routes("router", configuration=configuration) == [
        [spec.endpoints(configuration)["dns"][0], "10.79.0.14", "fd"],
        [spec.endpoints(configuration)["http"][0], "10.79.0.18", "fw"]]


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("operation", spec.OPERATIONS)
def test_client_filter_allows_only_exact_tcp_role_without_default_route(configuration, operation):
    rules = spec.firewall_rules(operation + "_client", configuration=configuration)
    selected = spec.endpoints(configuration)
    assert f"ip daddr {selected[operation][0]} tcp dport {selected[operation][1]} " in rules
    assert rules.count(" accept") == 2 and "udp" not in rules and "ip6" not in rules
    assert all(row[0] != "0.0.0.0" for row in spec.routes(operation + "_client", configuration=configuration))
    assert all(f"ip daddr {selected[other][0]} tcp dport {selected[other][1]} " not in rules
               for other in selected if other != operation)


@pytest.mark.parametrize("configuration", ("A", "B"))
@pytest.mark.parametrize("field", ("user", "networks", "listener_cookie", "listener_endpoint", "listener_inode",
    "exports", "bounds", "custody", "mapping", "groups", "ipv6", "default_route", "extra_link", "wrong_peer",
    "wrong_address", "forwarding", "filtered", "baseline", "other_configuration"))
def test_changed_topology_cannot_pass_immutable_validation(configuration, field):
    value = metadata(configuration)
    if field == "user": value["user"] = "net:[20]"
    elif field == "networks": value["networks"]["dns_client"] = value["networks"]["router"]
    elif field == "listener_cookie": value["listeners"]["tls"]["netns_cookie"] += 1
    elif field == "listener_endpoint": value["listeners"]["dns"]["local"][1] += 1
    elif field == "listener_inode": value["listeners"]["dns"]["inode"] = value["listeners"]["http"]["inode"]
    elif field == "exports": value["exports"].append("server_key")
    elif field == "bounds": value["bounds"]["file_descriptors"] += 1
    elif field == "custody": value["descriptor_custody"]["steady"] += 1
    elif field == "mapping": value["namespace_identity"]["uid_map"][0][2] = 65536
    elif field == "groups": value["namespace_identity"]["groups"] = [0]
    elif field == "ipv6": value["network_state"]["http_client"]["ipv6_disabled"] = False
    elif field == "default_route": value["network_state"]["http_client"]["routes"][0]["prefix"] = 0
    elif field == "extra_link": value["network_state"]["router"]["links"].append(deepcopy(value["network_state"]["router"]["links"][0]))
    elif field == "wrong_peer": value["network_state"]["router"]["links"][1]["peer_index"] = 50
    elif field == "wrong_address": value["network_state"]["dns_frontend"]["addresses"][0]["address"] = "192.0.2.1"
    elif field == "forwarding": value["network_state"]["http_client"]["ipv4_forwarding"] = True
    elif field == "filtered": value["filtered"][1]["connected"] = True
    elif field == "baseline": value["baselines"][0]["connected"] = False
    else: value = metadata("B" if configuration == "A" else "A")
    with pytest.raises(ValueError):
        spec.validate_metadata(value, configuration=configuration)


@pytest.mark.parametrize("configuration", (None, True, 1, {}, [], "C", "A "))
def test_configuration_is_closed(configuration):
    with pytest.raises(ValueError, match="configuration"):
        spec.endpoints(configuration)


def test_metadata_and_closure_are_detached_data_not_authority():
    original = metadata()
    value = spec.validate_metadata(original)
    value["listeners"]["dns"]["inode"] += 10
    assert original == metadata()
    receipt = {"status": "closed", "owner_exited": True, "descriptors_closed": True,
               "namespaces": original["networks"], "topology_sha256": spec.digest()}
    assert spec.validate_closure(receipt, metadata=original) == receipt
    with pytest.raises(ValueError):
        spec.validate_closure(receipt, metadata=None)
    with pytest.raises(ValueError):
        spec.validate_closure(receipt, metadata=original, configuration="B")
