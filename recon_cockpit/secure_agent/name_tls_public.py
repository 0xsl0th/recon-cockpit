"""Key-free, immutable protocol constants for the separately owned name lab.

No fixture material, execution authority, imports with server keys or host I/O.
The preparation module remains independently pinned; tests compare the copies.
"""

import hashlib
import json
import math
from types import MappingProxyType

PROFILE = "owned_name_tls_v1"
CONFIGURATIONS = ("A", "B")
CASES = ("O1", "O2", "O3", "O4", "O5", "R1", "R2", *(f"N{i}" for i in range(1, 17)))
LOGICAL_NAME = "harbordesk.test"
DNS_NAME = LOGICAL_NAME + "."
DNS_TTL = 60
UNDECLARED_NAME = "other.harbordesk.test"
CA_PATH = "/tool/data/name-tls/ca.pem"
PUBLIC_CA_SHA256 = "617015dc0014927cacb2c334ed861b091ea4846b2461540aa4aac3fa2138b84d"
OPENSSL_CONFIG_PATH = "/tool/data/name-tls/openssl.cnf"


def approval_summary(tool_id, parameters):
    """An additional literal summary; full canonical action remains visible."""
    if tool_id not in ("owned_name_dns_v1", "owned_name_http_v1", "owned_name_tls_v1"):
        return None
    names = ["configuration", "case", "operation_slot", "session_id", "owner_id",
             "owner_identity_sha256", "selection_sha256", "runtime_identity_sha256"]
    if tool_id == "owned_name_dns_v1":
        names += ["question_name", "question_class", "question_type"]
    else:
        names += ["canonical_name", "binding_sha256", "observation_sha256", "observed_answer_sha256",
                  "observation_generation", "observed_ttl_seconds", "observed_at_us", "expires_at_us"]
        names += (["host"] if tool_id == "owned_name_http_v1" else
                  ["sni", "expected_certificate_name", "public_ca_sha256"])
    return {name: parameters[name] for name in names}


ENVIRONMENT = MappingProxyType({"LC_ALL": "C", "MALLOC_ARENA_MAX": "1",
                               "OPENSSL_CONF": OPENSSL_CONFIG_PATH, "TZ": "UTC0"})
ROWS = MappingProxyType({
    "A": ("10.77.0.53", 5353, "10.77.0.10", 8080, "/harbordesk/portal.html", 8443, "10.77.0.99"),
    "B": ("172.23.0.53", 15353, "172.23.0.10", 18080, "/portal/index.html", 18443, "172.23.0.99"),
})


def validate_selection(configuration, case):
    if type(configuration) is not str or configuration not in CONFIGURATIONS:
        raise ValueError("invalid_name_tls_configuration")
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_name_tls_case")
    return configuration, case


def endpoints(configuration):
    validate_selection(configuration, "O1")
    resolver, dns_port, service, http_port, path, tls_port, excluded = ROWS[configuration]
    return {"resolver": {"target": resolver, "port": dns_port, "transport": "tcp"},
            "http": {"target": service, "port": http_port, "path": path},
            "tls": {"target": service, "port": tls_port}, "excluded_address": excluded,
            "allowed_service_addresses": [service]}


def request_bytes(configuration, case):
    validate_selection(configuration, case)
    http = endpoints(configuration)["http"]
    return (f"GET {http['path']} HTTP/1.1\r\nHost: {LOGICAL_NAME}:{http['port']}\r\n"
            "Connection: close\r\n\r\n").encode("ascii")


def dns_argv(configuration, case):
    validate_selection(configuration, case)
    resolver = endpoints(configuration)["resolver"]
    return ("/tool/dig", "-r", "-4", "@" + resolver["target"], "-p", str(resolver["port"]),
            DNS_NAME, "IN", "A", "+tcp", "+norecurse", "+noedns", "+nocookie",
            "+nosearch", "+noadflag", "+nocdflag", "+tries=1", "+retry=0", "+time=2",
            "+noall", "+question", "+answer", "+authority", "+additional", "+comments", "+stats")


def tls_argv(configuration, case):
    validate_selection(configuration, case)
    target = endpoints(configuration)["tls"]
    return ("/tool/openssl", "s_client", "-4", "-connect", f"{target['target']}:{target['port']}",
            "-servername", LOGICAL_NAME, "-verify_hostname", LOGICAL_NAME, "-verify_return_error",
            "-CAfile", CA_PATH, "-no-CApath", "-no-CAstore", "-no_ticket", "-no_renegotiation",
            "-nocommands", "-groups", "P-256", "-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384", "-brief")


def encode(value, *, max_bytes=32768):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    if len(raw) > max_bytes:
        raise ValueError("name_tls_json_limit")
    return raw


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("name_tls_duplicate_json_key")
        result[key] = value
    return result


def decode(raw, *, max_bytes=32768):
    if type(raw) is not bytes or len(raw) > max_bytes:
        raise ValueError("name_tls_json_limit")
    def invalid_constant(_):
        raise ValueError("name_tls_invalid_json_constant")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=invalid_constant)
        stack = [(value, 0)]
        while stack:
            node, depth = stack.pop()
            if depth > 64:
                raise ValueError("name_tls_json_depth")
            if type(node) is float and not math.isfinite(node):
                raise ValueError("name_tls_invalid_json_constant")
            if type(node) is dict:
                stack.extend((item, depth + 1) for item in node.values())
            elif type(node) is list:
                stack.extend((item, depth + 1) for item in node)
        if type(value) is not dict:
            raise ValueError("name_tls_json_object")
        return value
    except (UnicodeDecodeError, RecursionError) as error:
        raise ValueError("name_tls_invalid_json") from error


def digest(value):
    return hashlib.sha256(encode(value, max_bytes=524288)).hexdigest()


# Digests of the accepted preparation, copied without importing owner key material.
PREPARATION_DIGESTS = MappingProxyType({
    'A/O1': '47ff6caab2207d23133c90b1ae635a63e23c1f2023f932baed334d1c8527c6b7',
    'A/O2': '0172a6c36689ce5aed00d9e6b2f0bc418505fa6e42ef4796ac6dff2f67e099df',
    'A/O3': '93149dc5e089c86b4ce33dfb2fe8eebd4d3b10b178c4e49cc0a974b97a038e98',
    'A/O4': 'dd566bd4df01362eff694261d36864fa27d4dbb9dadce6bebcb2b0be0f4d3809',
    'A/O5': '0b38af6a0c5c59c2889898b446a55dc2084b88eb8467d4ef189082ab0f94d6dd',
    'A/R1': 'b5eca9353ece4aac323134824b29f30c3b86bd00d395289ac78febab5f81dc0c',
    'A/R2': 'b5f1bdef9456ba9f0967fca93cacb6df18cce4ec7bfacdddc67812b451440536',
    'A/N1': 'ea2b3a6453d73a77fd08d5c0031a708a0fe6aa955852d2897a3cfcd91a23c77d',
    'A/N2': 'b05499767a33d91b189168b4c5ca19a8972512b9488a368437be5cae7d788c64',
    'A/N3': '11422f4f8442c5e7db1f6d9943a8b4d7dfd7947c335c2667fbf4b94132642cd0',
    'A/N4': '1dca1fcd618b78f564e19f7717de671bdd3a5657d17428f5c893870d839073e7',
    'A/N5': '7219bab266c09cccb087bc31c4faa7a86fb06699a61105d7a3e855110a2aef5a',
    'A/N6': 'da1897dc7d65acd44412ce2c5129af41e825ad5a74947b3b44c5c4fb3ea58277',
    'A/N7': '1d7759ecb30464a9912d2cf15fbb36956e1c2b55e05d0f8ccfeb3855afe4a344',
    'A/N8': '5fbd18d67e491c21d49d2651fe667496b19a2d6ce28aa4b68cdcbe7d84236f78',
    'A/N9': '081d7663397e2752270ac1e62075d39ac1fc585e0e1c67ef17074d75765cae10',
    'A/N10': '52252c2404e552216926bb6709ba71bc76fa9c499a5abc9f713af55d2cedd0e5',
    'A/N11': '8dc9e639aa8099d7e941a7c7a506dda05fa2836142f7ad93f53ee89588813e32',
    'A/N12': '6fcbcf3a7035d97a48e238f957d044bf4bf36d85ef2c311b1799c52de85189ac',
    'A/N13': 'ad139061c711604e9f0f27cd7ad01ba07de3a6fa279c741cd29e870a113a37d6',
    'A/N14': '9733eb1c09eedb2b7cda096fa201e2fafb83d12e08bffc8796a1cfe1382a077c',
    'A/N15': '065ac2f2b0732d4ddb7df930199cae5aa8cb5efa97dc15ab02daee360586f1a8',
    'A/N16': '515734486ba64b31121533806ac03bdf6cfeb8ef4ac6fa2267b51d13555f80f2',
    'B/O1': '7d189babe9a0b260b194d8784ce9ef0aa4941890e181996431d6a1cc384b700c',
    'B/O2': '29f7da4a723265395052de58814fce763e3bc098167349b2cd32601f53ea62d6',
    'B/O3': '93cc35aa54b13c6b59d524eceb24af93e7334ede3af7b16fe2ef631951d3738c',
    'B/O4': '7d40635267d46b57652f29a0a90d7845daaf25685daca3d06c25f565cc8a46fe',
    'B/O5': 'e7d154cab06c6c265dd34a5cccd56af11c4e57dfb6d083d65e105bb405719bdc',
    'B/R1': 'b31e3a97f3b07c19c1d0f96681b9470267aad191eaa8e6e9132669d4f128fe88',
    'B/R2': '5e2539f6d8bb7d59dfe30abde2dc706f40fce1ab5ef92556604e26c8d29ab334',
    'B/N1': '4430a7fec321c8c5e7ef0afddf5537e2a29980f1542f75dc8e7ea8822ae1935f',
    'B/N2': '5578e5356a3c42c1b5ee3067dd1cca2e9b641a477cad696b7efe279c491a5722',
    'B/N3': 'fb26bccd9dfe8ae30a24424f9f6baeff85ffb2d8ef6d01b66c5fee72fe7ad690',
    'B/N4': '61a0a500e97324c76e9cb3e2fbd1f89844a6ce91b73addb84871b26951f28c6f',
    'B/N5': 'adabb358aa764fbadaeaacd87b4fd5a90966f46e42bfb6f2b46de375e2d843c3',
    'B/N6': '4781a8b814f22e200c2b5b061919379992cf0f3636b1712bcb9f968daefcfb53',
    'B/N7': 'b7d92653f6119d2de0faaa3ce54d73307a4766560df1aabe5ba1d4c923114dd2',
    'B/N8': 'f031981bb08057b91d67c432337317bbb0ca54db76e3207ad6e64ad824e2b002',
    'B/N9': '0e9ec8a46308a5feca2a947474517b89815ef4a5f0239443bb44f83fcc1356cc',
    'B/N10': '4afe40dc854406cf917c48cbbc2b0216d755f2806c627b393f5bbf8f8cf22482',
    'B/N11': 'c47692c02811ed6474ab8a7905cdb074bcf7e4472be98ced4df5245753ea825c',
    'B/N12': '62e212102451273ceac9c00953253cc8a189f845df741a4ea0d03ceb6ca200af',
    'B/N13': '6b3588313f9f140eb2b22ef940e348fefb25a11bd8ca07608f10c8ac228d7c2f',
    'B/N14': '3dd1402af39fbd41fc0a3b165e4b40584c3f8058d8e05ce8c9865f5e19c31690',
    'B/N15': 'df0c8072ac3b3fc2c12825e8563172ae2ebab1679f8c0ee6530b386e48965d13',
    'B/N16': '2a8833b0460d20a327a3e1f571768940f61381e10c322f2d9def4b010b4298f7',
})
NATIVE_CONTRACT_SHA256 = "2b386c5ed4328cad4a56fa5d73e70e48b7260648d708671ef7a1b314c66f190d"
NATIVE_GATES_SHA256 = "a09572b5d23984326e82dfda921810eaf98c6ced100f4c65d8a3fdf0c58de0df"
