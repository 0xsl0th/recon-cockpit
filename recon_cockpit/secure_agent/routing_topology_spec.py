"""Pure fixed routing topology commitment; grants no execution authority."""

from copy import deepcopy
import hashlib
import ipaddress
import json
import math
import re

PROFILE = "owned-disconnected-routing-topology-v1"
ROLES = ("http_client", "ssh_client", "router", "http_frontend", "ssh_frontend")
EXPORTS = ("user", *(role + "_net" for role in ROLES), "http_listener", "ssh_listener",
           "http_ledger_channel", "ssh_ledger_channel",
           *(f"ssh_pair_{number}_{side}" for number in range(4) for side in ("frontend", "daemon")))
ENDPOINTS = {"http": ("10.77.0.10", 8080), "ssh": ("10.77.0.20", 2222),
             "excluded": ("10.77.0.99", 8080), "http_wrong": ("10.77.0.10", 8081),
             "ssh_wrong": ("10.77.0.20", 2223)}
CLIENTS = {"http": "10.78.0.2", "ssh": "10.78.0.6"}
LINKS = (
    ("http_client", "ch", "10.78.0.1", "10.78.0.2"),
    ("ssh_client", "cs", "10.78.0.5", "10.78.0.6"),
    ("http_frontend", "fh", "10.78.0.9", "10.78.0.10"),
    ("ssh_frontend", "fs", "10.78.0.13", "10.78.0.14"),
)
BOUNDS = {"address_space_bytes": 268435456, "file_descriptors": 128,
          "retained_bytes": 1048576, "setup_helpers_total": 6,
          "setup_helpers_concurrent": 1, "setup_helper_seconds": 2,
          "setup_helper_output_bytes": 8192, "steady_processes": 1}
MAX_PACKET = 524288
NS_GET_USERNS = 0xB701
NS_GET_NSTYPE = 0xB703
def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    if len(raw) > MAX_PACKET:
        raise ValueError("routing_topology_packet_limit")
    return raw
def decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_PACKET:
        raise ValueError("routing_topology_packet_limit")
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("routing_topology_duplicate_json_key")
            result[key] = item
        return result
    def constant(_):
        raise ValueError("routing_topology_nonfinite_json")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("routing_topology_invalid_json") from error
    if type(value) is not dict:
        raise ValueError("routing_topology_packet_shape")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64 or type(item) is float and not math.isfinite(item):
            raise ValueError("routing_topology_json_limit")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value
def spec():
    return {"profile": PROFILE, "roles": list(ROLES), "links": [list(row) for row in LINKS],
            "endpoints": {key: list(value) for key, value in ENDPOINTS.items()},
            "clients": dict(CLIENTS), "bounds": dict(BOUNDS), "external_egress": False,
            "private_ssh_pairs": 4, "private_ssh_listener_retained": False,
            "transport": {"logical_bytes": MAX_PACKET, "frame_bytes": 32768, "seconds": 2},
            "routes": {role: routes(role) for role in ROLES},
            "firewalls": {role: firewall_rules(role) for role in ROLES}}
def digest():
    return hashlib.sha256(encode(spec())).hexdigest()
def routes(role):
    if role not in ROLES:
        raise ValueError("routing_topology_role")
    if role == "router":
        return [[ENDPOINTS[service][0], remote, interface] for service, (_, interface, _, remote)
                in zip(("http", "ssh"), LINKS[2:], strict=True)]
    _, _, gateway, _ = next(row for row in LINKS if row[0] == role)
    destinations = ([ENDPOINTS[key][0] for key in ("http", "ssh", "excluded")]
                    if role.endswith("client") else list(CLIENTS.values()))
    return [[destination, gateway, "eth0"] for destination in destinations]
def firewall_rules(role, private_pairs=(), *, private_routes=(), setup=False):
    if role not in ROLES:
        raise ValueError("routing_topology_role")
    rules = {"input": [], "output": [], "forward": []}
    for service, client_interface, frontend_interface in (("http", "ch", "fh"), ("ssh", "cs", "fs")):
        target, port = ENDPOINTS[service]
        client = CLIENTS[service]
        request = f"ip saddr {client} ip daddr {target} tcp dport {port} ct direction original"
        reply = f"ip saddr {target} ip daddr {client} tcp sport {port} ct direction reply ct state established"
        if role == service + "_client":
            rules["output"].append(f'oifname "eth0" {request} accept')
            rules["input"].append(f'iifname "eth0" {reply} accept')
        elif role == service + "_frontend":
            rules["input"].append(f'iifname "eth0" {request} accept')
            rules["output"].append(f'oifname "eth0" {reply} accept')
        elif role == "router":
            rules["forward"].extend((f'iifname "{client_interface}" oifname "{frontend_interface}" {request} accept',
                                     f'iifname "{frontend_interface}" oifname "{client_interface}" {reply} accept'))
    if private_pairs and private_routes:
        raise ValueError("routing_topology_duplicate_private_routes")
    if private_pairs:
        if role != "ssh_frontend" or len(private_pairs) != 4:
            raise ValueError("routing_topology_private_pairs")
        for pair in private_pairs:
            validate_pair(pair)
        private_routes = [{side: pair[side]["local"] for side in ("frontend", "daemon")} for pair in private_pairs]
    if private_routes:
        if role != "ssh_frontend" or len(private_routes) != 4 or type(setup) is not bool:
            raise ValueError("routing_topology_private_routes")
        seen = set()
        for pair in private_routes:
            if type(pair) is not dict or set(pair) != {"frontend", "daemon"}:
                raise ValueError("routing_topology_private_route_shape")
            for endpoint in pair.values():
                if (type(endpoint) is not list or len(endpoint) != 2 or endpoint[0] != "127.0.0.1"
                        or type(endpoint[1]) is not int or not 1024 <= endpoint[1] < 65536):
                    raise ValueError("routing_topology_private_route_endpoint")
            key = (pair["frontend"][1], pair["daemon"][1])
            if key in seen or key[0] == key[1]:
                raise ValueError("routing_topology_private_route_duplicate")
            seen.add(key)
            for source, destination in ((pair["frontend"], pair["daemon"]), (pair["daemon"], pair["frontend"])):
                state = "{ new, established }" if setup else "established"
                match = f"ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {source[1]} tcp dport {destination[1]} ct state {state} accept"
                rules["input"].append('iifname "lo" ' + match)
                rules["output"].append('oifname "lo" ' + match)
    return "table inet recon_routing {\n" + "".join(
        f" chain {hook} {{ type filter hook {hook} priority 0; policy drop;\n"
        + "".join("  " + rule + "\n" for rule in values) + " }\n"
        for hook, values in rules.items()) + "}\n"
def validate_pair(value):
    if type(value) is not dict or set(value) != {"frontend", "daemon"}:
        raise ValueError("routing_topology_private_pair_shape")
    for side in value.values():
        if (type(side) is not dict or set(side) != {"inode", "local", "peer", "netns_cookie"}
                or any(type(side[key]) is not int or not 0 < side[key] < 2**64 for key in ("inode", "netns_cookie"))):
            raise ValueError("routing_topology_private_pair_identity")
        for endpoint in (side["local"], side["peer"]):
            if (type(endpoint) is not list or len(endpoint) != 2 or endpoint[0] != "127.0.0.1"
                    or type(endpoint[1]) is not int or not 1024 <= endpoint[1] < 65536):
                raise ValueError("routing_topology_private_pair_endpoint")
    left, right = value["frontend"], value["daemon"]
    if (left["inode"] == right["inode"] or left["netns_cookie"] != right["netns_cookie"]
            or left["local"] != right["peer"] or left["peer"] != right["local"] or left["local"] == left["peer"]):
        raise ValueError("routing_topology_private_pair_binding")
    return deepcopy(value)


def expected_addresses(role):
    if role not in ROLES:
        raise ValueError("routing_topology_role")
    rows = [{"interface": "lo", "address": "127.0.0.1", "prefix": 8}]
    if role == "router":
        rows += [{"interface": interface, "address": local, "prefix": 30}
                 for _, interface, local, _ in LINKS]
        rows.append({"interface": "lo", "address": ENDPOINTS["excluded"][0], "prefix": 32})
    else:
        remote = next(row[3] for row in LINKS if row[0] == role)
        rows.append({"interface": "eth0", "address": remote, "prefix": 30})
        if role.endswith("frontend"):
            rows.append({"interface": "eth0", "address": ENDPOINTS[role.split("_")[0]][0], "prefix": 32})
    return sorted(rows, key=encode)


def validate_network_state(value):
    """Replay observed kernel links, addresses and all IPv4 route tables."""
    if type(value) is not dict or set(value) != set(ROLES):
        raise ValueError("routing_topology_network_state_roles")
    links_by_role = {}
    for role, state in value.items():
        if (type(state) is not dict or set(state) != {"links", "addresses", "routes", "ipv4_forwarding"}
                or type(state["ipv4_forwarding"]) is not bool
                or state["ipv4_forwarding"] != (role == "router")
                or type(state["links"]) is not list):
            raise ValueError("routing_topology_network_state_shape")
        names = {"lo", *(row[1] for row in LINKS)} if role == "router" else {"lo", "eth0"}
        observed = {}
        for link in state["links"]:
            if (type(link) is not dict or set(link) != {"interface", "index", "peer_index", "kind", "up"}
                    or type(link["interface"]) is not str or link["interface"] not in names
                    or link["interface"] in observed or type(link["index"]) is not int
                    or not 0 < link["index"] < 2**31 or link["up"] is not True):
                raise ValueError("routing_topology_link_identity")
            loopback = link["interface"] == "lo"
            if (link["kind"] != ("loopback" if loopback else "veth")
                    or (link["peer_index"] is not None if loopback else
                        type(link["peer_index"]) is not int or not 0 < link["peer_index"] < 2**31)):
                raise ValueError("routing_topology_link_kind")
            observed[link["interface"]] = link
        if set(observed) != names or len({row["index"] for row in observed.values()}) != len(names):
            raise ValueError("routing_topology_link_inventory")
        links_by_role[role] = observed
        addresses = expected_addresses(role)
        if type(state["addresses"]) is not list or encode(sorted(state["addresses"], key=encode)) != encode(addresses):
            raise ValueError("routing_topology_address_inventory")
        required, optional = set(), set()
        for destination, gateway, interface in routes(role):
            required.add((254, destination, 32, gateway, interface, 4, 0, 1))
        for address in addresses:
            network = ipaddress.IPv4Network(address["address"] + "/" + str(address["prefix"]), strict=False)
            row = (254, str(network.network_address), address["prefix"], None,
                   address["interface"], 2, 253, 1)
            if address["prefix"] == 30:
                required.add(row)
            elif address["prefix"] == 32:
                optional.add(row)
        if type(state["routes"]) is not list or len(state["routes"]) > 64:
            raise ValueError("routing_topology_route_inventory")
        seen, observed_main = set(), set()
        for route in state["routes"]:
            fields = ("table", "destination", "prefix", "gateway", "interface", "protocol", "scope", "type")
            if (type(route) is not dict or set(route) != set(fields)
                    or any(type(route[key]) is not int for key in ("table", "prefix", "protocol", "scope", "type"))
                    or type(route["destination"]) is not str or type(route["interface"]) is not str
                    or route["gateway"] is not None and type(route["gateway"]) is not str):
                raise ValueError("routing_topology_route_shape")
            row = tuple(route[key] for key in fields)
            if row in seen:
                raise ValueError("routing_topology_route_duplicate")
            seen.add(row)
            if route["table"] == 254:
                if row not in required | optional:
                    raise ValueError("routing_topology_unexpected_route")
                observed_main.add(row)
            else:
                # The only other allowed table is the kernel-created local table.
                # Its exact address ranges must derive from an observed fixed address.
                if (route["table"] != 255 or route["gateway"] is not None or route["protocol"] != 2
                        or route["type"] not in (2, 3) or route["scope"] not in (253, 254)
                        or not 0 < route["prefix"] <= 32):
                    raise ValueError("routing_topology_nonlocal_route")
                try:
                    network = ipaddress.IPv4Network(route["destination"] + "/" + str(route["prefix"]), strict=True)
                except ValueError as error:
                    raise ValueError("routing_topology_local_route_address") from error
                if not any(route["interface"] == address["interface"] and network.subnet_of(
                        ipaddress.IPv4Network(address["address"] + "/" + str(address["prefix"]), strict=False))
                        for address in addresses):
                    raise ValueError("routing_topology_ambient_local_route")
        if not required <= observed_main:
            raise ValueError("routing_topology_required_route_missing")
    for role, interface, _, _ in LINKS:
        router, peer = links_by_role["router"][interface], links_by_role[role]["eth0"]
        if router["peer_index"] != peer["index"] or peer["peer_index"] != router["index"]:
            raise ValueError("routing_topology_veth_peer_changed")
    return deepcopy(value)


def validate_metadata(value):
    fields = {"ready", "profile", "topology_sha256", "user", "networks", "listeners", "baselines",
              "filtered", "bounds", "setup_helpers", "capabilities_dropped", "setup_disabled", "exports",
              "private_ssh_pairs", "private_pairs_drained", "owner_namespaces", "network_state",
              "private_listener_closed", "descriptor_custody"}
    if (type(value) is not dict or set(value) != fields or value["ready"] is not True
            or value["profile"] != PROFILE or value["topology_sha256"] != digest()
            or value["exports"] != list(EXPORTS) or encode(value["bounds"]) != encode(BOUNDS)
            or type(value["setup_helpers"]) is not int or value["setup_helpers"] != BOUNDS["setup_helpers_total"]
            or value["capabilities_dropped"] is not True or value["setup_disabled"] is not True
            or value["private_pairs_drained"] is not True or value["private_listener_closed"] is not True
            or encode(value["descriptor_custody"]) != encode({"before_export": 26, "steady": 14})):
        raise ValueError("routing_topology_metadata_changed")
    validate_network_state(value["network_state"])
    if type(value["user"]) is not str or not re.fullmatch(r"user:\[\d+\]", value["user"]):
        raise ValueError("routing_topology_user_identity")
    networks, owner = value["networks"], value["owner_namespaces"]
    if (type(networks) is not dict or set(networks) != set(ROLES)
            or any(type(item) is not str or not re.fullmatch(r"net:\[\d+\]", item) for item in networks.values())
            or len(set(networks.values())) != 5 or type(owner) is not dict or set(owner) != {"user", "net", "mnt", "pid"}
            or any(type(item) is not str or not re.fullmatch(name + r":\[\d+\]", item) for name, item in owner.items())
            or owner["user"] != value["user"] or owner["net"] != networks["router"]):
        raise ValueError("routing_topology_network_identity")
    listeners = value["listeners"]
    if type(listeners) is not dict or set(listeners) != set(ENDPOINTS):
        raise ValueError("routing_topology_listener_metadata")
    for name, item in listeners.items():
        if (type(item) is not dict or set(item) != {"inode", "local", "netns_cookie"}
                or any(type(item[key]) is not int or not 0 < item[key] < 2**64 for key in ("inode", "netns_cookie"))
                or encode(item["local"]) != encode(list(ENDPOINTS[name]))):
            raise ValueError("routing_topology_listener_metadata")
    if (len({item["inode"] for item in listeners.values()}) != 5
            or len({item["netns_cookie"] for item in listeners.values()}) != 3
            or any(listeners[service]["netns_cookie"] != listeners[service + "_wrong"]["netns_cookie"]
                   for service in ("http", "ssh"))):
        raise ValueError("routing_topology_listener_namespace_binding")
    pairs = value["private_ssh_pairs"]
    if type(pairs) is not list or len(pairs) != 4:
        raise ValueError("routing_topology_private_pairs_metadata")
    seen = {item["inode"] for item in listeners.values()}
    for pair in pairs:
        validate_pair(pair)
        for side in pair.values():
            if side["inode"] in seen or side["netns_cookie"] != listeners["ssh"]["netns_cookie"]:
                raise ValueError("routing_topology_private_pair_namespace_binding")
            seen.add(side["inode"])
    if (len({tuple(pair["frontend"]["local"]) for pair in pairs}) != 4
            or len({tuple(pair["daemon"]["local"]) for pair in pairs}) != 1):
        raise ValueError("routing_topology_private_pair_tuple_reuse")
    for phase in ("baselines", "filtered"):
        expected = [{"client": client, "endpoint": endpoint,
                     "connected": True if phase == "baselines" else endpoint == client}
                    for client in ("http", "ssh") for endpoint in ENDPOINTS]
        if encode(value[phase]) != encode(expected):
            raise ValueError("routing_topology_witness_metadata")
    return deepcopy(value)


def validate_closure(value, *, metadata=None):
    fields = {"status", "owner_exited", "descriptors_closed", "namespaces", "topology_sha256"}
    if (type(value) is not dict or set(value) != fields or value["status"] != "closed"
            or value["owner_exited"] is not True or value["descriptors_closed"] is not True
            or value["topology_sha256"] != digest()):
        raise ValueError("routing_topology_cleanup_changed")
    expected = None if metadata is None else validate_metadata(metadata)["networks"]
    if value["namespaces"] != expected:
        raise ValueError("routing_topology_cleanup_namespaces_changed")
    return deepcopy(value)
