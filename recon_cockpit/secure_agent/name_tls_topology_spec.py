"""Pure six-network topology commitment for owned DNS, HTTP and TLS."""

from copy import deepcopy
import hashlib
import ipaddress
import json
import math
import re

PROFILE = "owned-name-tls-six-network-topology-v1"
OPERATIONS = ("dns", "http", "tls")
ROLES = ("dns_client", "http_client", "tls_client", "router", "dns_frontend", "web_frontend")
EXPORTS = ("user", *(role + "_net" for role in ROLES),
           *(role + "_listener" for role in OPERATIONS), *(role + "_ledger_channel" for role in OPERATIONS))
CLIENTS = {"dns": "10.79.0.2", "http": "10.79.0.6", "tls": "10.79.0.10"}
LINKS = (("dns_client", "cd", "10.79.0.1", "10.79.0.2"),
         ("http_client", "ch", "10.79.0.5", "10.79.0.6"),
         ("tls_client", "ct", "10.79.0.9", "10.79.0.10"),
         ("dns_frontend", "fd", "10.79.0.13", "10.79.0.14"),
         ("web_frontend", "fw", "10.79.0.17", "10.79.0.18"))
BOUNDS = {"address_space_bytes": 268435456, "file_descriptors": 128,
          "retained_bytes": 1048576, "setup_helpers_total": 6,
          "setup_helpers_concurrent": 1, "setup_helper_seconds": 2,
          "setup_helper_output_bytes": 8192, "steady_processes": 1, "setup_seconds": 10}
DESCRIPTOR_CUSTODY = {"before_export": 25, "steady": 19}
MAX_PACKET = 524288
NS_GET_USERNS, NS_GET_NSTYPE = 0xB701, 0xB703


def endpoints(configuration="A"):
    if type(configuration) is not str or configuration not in ("A", "B"):
        raise ValueError("name_tls_topology_configuration")
    dns, web, excluded, ports = (("10.77.0.53", "10.77.0.10", "10.77.0.99", (5353, 8080, 8443))
        if configuration == "A" else ("172.23.0.53", "172.23.0.10", "172.23.0.99", (15353, 18080, 18443)))
    result = dict(zip(OPERATIONS, ((dns, ports[0]), (web, ports[1]), (web, ports[2])), strict=True))
    result.update({op + "_wrong": (result[op][0], result[op][1] + 1) for op in OPERATIONS})
    result.update({op + "_excluded": (excluded, result[op][1]) for op in OPERATIONS})
    return result


def frontend_role(operation):
    if type(operation) is not str or operation not in OPERATIONS:
        raise ValueError("name_tls_topology_operation")
    return "dns_frontend" if operation == "dns" else "web_frontend"


def listener_keys(role):
    if role not in ROLES:
        raise ValueError("name_tls_topology_role")
    if role == "router":
        return tuple(op + "_excluded" for op in OPERATIONS)
    if role == "dns_frontend":
        return ("dns", "dns_wrong")
    if role == "web_frontend":
        return ("http", "tls", "http_wrong", "tls_wrong")
    return ()


def encode(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    if len(raw) > MAX_PACKET:
        raise ValueError("name_tls_topology_packet_limit")
    return raw
def decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_PACKET:
        raise ValueError("name_tls_topology_packet_limit")
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("name_tls_topology_duplicate_json_key")
            result[key] = item
        return result
    def constant(_):
        raise ValueError("name_tls_topology_nonfinite_json")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs, parse_constant=constant)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("name_tls_topology_invalid_json") from error
    if type(value) is not dict:
        raise ValueError("name_tls_topology_packet_shape")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64 or type(item) is float and not math.isfinite(item):
            raise ValueError("name_tls_topology_json_limit")
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    return value
def spec(*, configuration="A"):
    return {"profile": PROFILE, "roles": list(ROLES), "links": [list(row) for row in LINKS],
        "endpoints": {key: list(value) for key, value in endpoints(configuration).items()},
        "clients": dict(CLIENTS), "bounds": dict(BOUNDS), "external_egress": False,
        "exports": list(EXPORTS), "descriptor_custody": dict(DESCRIPTOR_CUSTODY),
        "transport": {"logical_bytes": MAX_PACKET, "frame_bytes": 32768, "seconds": 2},
        "routes": {role: routes(role, configuration=configuration) for role in ROLES},
        "firewalls": {role: firewall_rules(role, configuration=configuration) for role in ROLES}}


def digest(*, configuration="A"):
    return hashlib.sha256(encode(spec(configuration=configuration))).hexdigest()


def routes(role, *, configuration="A"):
    selected = endpoints(configuration)
    if role not in ROLES:
        raise ValueError("name_tls_topology_role")
    if role == "router":
        return [[selected[service][0], remote, interface] for service, (_, interface, _, remote)
                in zip(("dns", "http"), LINKS[3:], strict=True)]
    _, _, gateway, _ = next(row for row in LINKS if row[0] == role)
    destinations = ([selected[key][0] for key in ("dns", "http", "dns_excluded")]
                    if role.endswith("client") else list(CLIENTS.values()))
    return [[destination, gateway, "eth0"] for destination in destinations]


def firewall_rules(role, *, configuration="A"):
    selected = endpoints(configuration)
    if role not in ROLES:
        raise ValueError("name_tls_topology_role")
    rules = {"input": [], "output": [], "forward": []}
    for service, ci, fi in (("dns", "cd", "fd"), ("http", "ch", "fw"), ("tls", "ct", "fw")):
        target, port = selected[service]
        client = CLIENTS[service]
        request = f"ip saddr {client} ip daddr {target} tcp dport {port} ct direction original"
        reply = f"ip saddr {target} ip daddr {client} tcp sport {port} ct direction reply ct state established"
        if role == service + "_client":
            rules["output"].append(f'oifname "eth0" {request} accept')
            rules["input"].append(f'iifname "eth0" {reply} accept')
        elif role == frontend_role(service):
            rules["input"].append(f'iifname "eth0" {request} accept')
            rules["output"].append(f'oifname "eth0" {reply} accept')
        elif role == "router":
            rules["forward"].extend((f'iifname "{ci}" oifname "{fi}" {request} accept',
                                     f'iifname "{fi}" oifname "{ci}" {reply} accept'))
    return "table inet recon_name_tls {\n" + "".join(
        f" chain {hook} {{ type filter hook {hook} priority 0; policy drop;\n"
        + "".join("  " + rule + "\n" for rule in values) + " }\n"
        for hook, values in rules.items()) + "}\n"


def expected_addresses(role, *, configuration="A"):
    selected = endpoints(configuration)
    if role not in ROLES:
        raise ValueError("name_tls_topology_role")
    rows = [{"interface": "lo", "address": "127.0.0.1", "prefix": 8}]
    if role == "router":
        rows += [{"interface": interface, "address": local, "prefix": 30} for _, interface, local, _ in LINKS]
        rows.append({"interface": "lo", "address": selected["dns_excluded"][0], "prefix": 32})
    else:
        remote = next(row[3] for row in LINKS if row[0] == role)
        rows.append({"interface": "eth0", "address": remote, "prefix": 30})
        if role.endswith("frontend"):
            service = "dns" if role == "dns_frontend" else "http"
            rows.append({"interface": "eth0", "address": selected[service][0], "prefix": 32})
    return sorted(rows, key=encode)


def validate_network_state(value, *, configuration="A"):
    """Replay observed kernel links, addresses and all IPv4 route tables."""
    endpoints(configuration)
    if type(value) is not dict or set(value) != set(ROLES):
        raise ValueError("name_tls_topology_network_state_roles")
    links_by_role = {}
    for role, state in value.items():
        if (type(state) is not dict or set(state) != {"links", "addresses", "routes", "ipv4_forwarding", "ipv6_disabled"}
                or state["ipv6_disabled"] is not True
                or type(state["ipv4_forwarding"]) is not bool
                or state["ipv4_forwarding"] != (role == "router")
                or type(state["links"]) is not list):
            raise ValueError("name_tls_topology_network_state_shape")
        names = {"lo", *(row[1] for row in LINKS)} if role == "router" else {"lo", "eth0"}
        observed = {}
        for link in state["links"]:
            if (type(link) is not dict or set(link) != {"interface", "index", "peer_index", "kind", "up"}
                    or type(link["interface"]) is not str or link["interface"] not in names
                    or link["interface"] in observed or type(link["index"]) is not int
                    or not 0 < link["index"] < 2**31 or link["up"] is not True):
                raise ValueError("name_tls_topology_link_identity")
            loopback = link["interface"] == "lo"
            if (link["kind"] != ("loopback" if loopback else "veth")
                    or (link["peer_index"] is not None if loopback else
                        type(link["peer_index"]) is not int or not 0 < link["peer_index"] < 2**31)):
                raise ValueError("name_tls_topology_link_kind")
            observed[link["interface"]] = link
        if set(observed) != names or len({row["index"] for row in observed.values()}) != len(names):
            raise ValueError("name_tls_topology_link_inventory")
        links_by_role[role] = observed
        addresses = expected_addresses(role, configuration=configuration)
        if type(state["addresses"]) is not list or encode(sorted(state["addresses"], key=encode)) != encode(addresses):
            raise ValueError("name_tls_topology_address_inventory")
        required, optional = set(), set()
        for destination, gateway, interface in routes(role, configuration=configuration):
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
            raise ValueError("name_tls_topology_route_inventory")
        seen, observed_main = set(), set()
        for route in state["routes"]:
            fields = ("table", "destination", "prefix", "gateway", "interface", "protocol", "scope", "type")
            if (type(route) is not dict or set(route) != set(fields)
                    or any(type(route[key]) is not int for key in ("table", "prefix", "protocol", "scope", "type"))
                    or type(route["destination"]) is not str or type(route["interface"]) is not str
                    or route["gateway"] is not None and type(route["gateway"]) is not str):
                raise ValueError("name_tls_topology_route_shape")
            row = tuple(route[key] for key in fields)
            if row in seen:
                raise ValueError("name_tls_topology_route_duplicate")
            seen.add(row)
            if route["table"] == 254:
                if row not in required | optional:
                    raise ValueError("name_tls_topology_unexpected_route")
                observed_main.add(row)
            else:
                # The only other allowed table is the kernel-created local table.
                # Its exact address ranges must derive from an observed fixed address.
                if (route["table"] != 255 or route["gateway"] is not None or route["protocol"] != 2
                        or route["type"] not in (2, 3) or route["scope"] not in (253, 254)
                        or not 0 < route["prefix"] <= 32):
                    raise ValueError("name_tls_topology_nonlocal_route")
                try:
                    network = ipaddress.IPv4Network(route["destination"] + "/" + str(route["prefix"]), strict=True)
                except ValueError as error:
                    raise ValueError("name_tls_topology_local_route_address") from error
                if not any(route["interface"] == address["interface"] and network.subnet_of(
                        ipaddress.IPv4Network(address["address"] + "/" + str(address["prefix"]), strict=False))
                        for address in addresses):
                    raise ValueError("name_tls_topology_ambient_local_route")
        if not required <= observed_main:
            raise ValueError("name_tls_topology_required_route_missing")
    for role, interface, _, _ in LINKS:
        router, peer = links_by_role["router"][interface], links_by_role[role]["eth0"]
        if router["peer_index"] != peer["index"] or peer["peer_index"] != router["index"]:
            raise ValueError("name_tls_topology_veth_peer_changed")
    return deepcopy(value)


def validate_metadata(value, *, configuration="A"):
    selected = endpoints(configuration)
    fields = {"ready", "profile", "topology_sha256", "user", "networks", "listeners", "baselines",
              "filtered", "bounds", "setup_helpers", "capabilities_dropped", "setup_disabled", "exports",
              "owner_namespaces", "network_state", "descriptor_custody", "namespace_identity"}
    if (type(value) is not dict or set(value) != fields or value["ready"] is not True
            or value["profile"] != PROFILE or value["topology_sha256"] != digest(configuration=configuration)
            or value["exports"] != list(EXPORTS) or encode(value["bounds"]) != encode(BOUNDS)
            or type(value["setup_helpers"]) is not int or value["setup_helpers"] != BOUNDS["setup_helpers_total"]
            or value["capabilities_dropped"] is not True or value["setup_disabled"] is not True
            or encode(value["descriptor_custody"]) != encode(DESCRIPTOR_CUSTODY)):
        raise ValueError("name_tls_topology_metadata_changed")
    validate_network_state(value["network_state"], configuration=configuration)
    validate_namespace_identity(value["namespace_identity"])
    if type(value["user"]) is not str or not re.fullmatch(r"user:\[\d+\]", value["user"]):
        raise ValueError("name_tls_topology_user_identity")
    networks, owner = value["networks"], value["owner_namespaces"]
    if (type(networks) is not dict or set(networks) != set(ROLES)
            or any(type(item) is not str or not re.fullmatch(r"net:\[\d+\]", item) for item in networks.values())
            or len(set(networks.values())) != 6 or type(owner) is not dict or set(owner) != {"user", "net", "mnt", "pid"}
            or any(type(item) is not str or not re.fullmatch(name + r":\[\d+\]", item) for name, item in owner.items())
            or owner["user"] != value["user"] or owner["net"] != networks["router"]):
        raise ValueError("name_tls_topology_network_identity")
    listeners = value["listeners"]
    if type(listeners) is not dict or set(listeners) != set(selected):
        raise ValueError("name_tls_topology_listener_metadata")
    for name, item in listeners.items():
        if (type(item) is not dict or set(item) != {"inode", "local", "netns_cookie"}
                or any(type(item[key]) is not int or not 0 < item[key] < 2**64 for key in ("inode", "netns_cookie"))
                or encode(item["local"]) != encode(list(selected[name]))):
            raise ValueError("name_tls_topology_listener_metadata")
    cookies = [{listeners[key]["netns_cookie"] for key in listener_keys(role)}
               for role in ("router", "dns_frontend", "web_frontend")]
    if len({item["inode"] for item in listeners.values()}) != 9 or any(len(group) != 1 for group in cookies) or len(set.union(*cookies)) != 3:
        raise ValueError("name_tls_topology_listener_namespace_binding")
    for phase in ("baselines", "filtered"):
        expected = [{"client": client, "endpoint": endpoint,
                     "connected": True if phase == "baselines" else endpoint == client}
                    for client in OPERATIONS for endpoint in selected]
        if encode(value[phase]) != encode(expected):
            raise ValueError("name_tls_topology_witness_metadata")
    return deepcopy(value)


def validate_namespace_identity(value):
    if (type(value) is not dict or set(value) != {"uid", "gid", "uid_map", "gid_map", "groups"}
            or type(value["uid"]) is not int or value["uid"] != 65534
            or type(value["gid"]) is not int or value["gid"] != 65534
            or type(value["groups"]) is not list or value["groups"] not in ([], [65534])):
        raise ValueError("name_tls_topology_payload_identity")
    for name in ("uid_map", "gid_map"):
        rows = value[name]
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not list or len(rows[0]) != 3
                or any(type(number) is not int for number in rows[0])
                or rows[0][0] != 65534 or rows[0][2] != 1 or not 0 <= rows[0][1] < 2**32):
            raise ValueError("name_tls_topology_payload_mapping")
    return deepcopy(value)


def validate_closure(value, *, metadata=None, configuration="A"):
    fields = {"status", "owner_exited", "descriptors_closed", "namespaces", "topology_sha256"}
    if (type(value) is not dict or set(value) != fields or value["status"] != "closed"
            or value["owner_exited"] is not True or value["descriptors_closed"] is not True
            or value["topology_sha256"] != digest(configuration=configuration)):
        raise ValueError("name_tls_topology_cleanup_changed")
    expected = None if metadata is None else validate_metadata(metadata, configuration=configuration)["networks"]
    if value["namespaces"] != expected:
        raise ValueError("name_tls_topology_cleanup_namespaces_changed")
    return deepcopy(value)
