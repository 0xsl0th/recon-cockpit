"""Pure S3.3a Apache preparation, with no execution or approval capability.

The finite cases reuse the accepted stock-HTTP requests and useful/negative
criteria. These generated inputs are proposals: they establish neither a
working Apache configuration nor confinement or native compatibility.
"""

import hashlib
import re
from types import MappingProxyType

from . import stock_http_spec as http


PROFILE = "stock-apache-preparation-v1"
PLANNED_CONTRACT = "stock_http_compatibility_v1"
APACHE_VERSION = "2.4.65"
CONFIGURATIONS = http.CONFIGURATIONS
ORDINARY_CASES = http.ORDINARY_CASES
ROBUSTNESS_CASES = http.ROBUSTNESS_CASES
NEGATIVE_CASES = http.NEGATIVE_CASES
CASES = http.CASES
TRIALS = http.TRIALS
NMAP_CASES = http.NMAP_CASES
MAX_GENERATED_FILE_BYTES = http.MAX_GENERATED_FILE_BYTES
APACHE_CONFIG_PATH = "/tool/data/apache2.conf"
PUBLIC_ROOT = "/tool/public"
ROOT_FILE = PUBLIC_ROOT + "/root.html"
SELECTED_FILE = PUBLIC_ROOT + "/selected.html"
ERROR_URI = "/__owned_error.html"
PRIVATE_ENDPOINT = ("127.0.0.1", 19080)
NAMESPACE_UID = NAMESPACE_GID = 65534
APACHE_MODULES = (
    ("mpm_prefork_module", "/usr/lib/apache2/modules/mod_mpm_prefork.so", "/tool/modules/mod_mpm_prefork.so"),
    ("authz_core_module", "/usr/lib/apache2/modules/mod_authz_core.so", "/tool/modules/mod_authz_core.so"),
    ("headers_module", "/usr/lib/apache2/modules/mod_headers.so", "/tool/modules/mod_headers.so"),
    ("alias_module", "/usr/lib/apache2/modules/mod_alias.so", "/tool/modules/mod_alias.so"),
)
APACHE_ARGV = ("/tool/apache2", "-X", "-d", "/scratch", "-f", APACHE_CONFIG_PATH)
APACHE_ENVIRONMENT = MappingProxyType({"LC_ALL": "C", "MALLOC_ARENA_MAX": "1", "TZ": "UTC0"})
GENERATED_PASSWD = b"reconlab:x:65534:65534:Owned lab:/nonexistent:/nonexistent\n"
GENERATED_GROUP = b"reconlab:x:65534:\n"
GENERATED_NSSWITCH = b"passwd: files\ngroup: files\n"


def validate_selection(configuration, case):
    return http.validate_selection(configuration, case)


def action(configuration, case):
    return http.action(configuration, case)


def request_bytes(configuration, case):
    return http.request_bytes(configuration, case)


def budgets(case):
    return http.budgets(case)


def expectation(case):
    return http.expectation(case)


def response_body(case):
    # Redirect bodies belong to the implementation; the observable criterion
    # remains the exact Location/status and prohibition on following it.
    return http.response_body(case)


def apache_config(configuration, case):
    """Compile only fixed directives/public paths; never invoke Apache.

    The intended later owner must start as the nonzero namespace identity and
    mediate the private loopback listener. This file does not create that owner,
    enforce its resource limits or permit client access to a host listener.
    """
    validate_selection(configuration, case)
    selected = http.action(configuration, "O1")
    path = selected["parameters"]["path"]
    modules = "".join(f'LoadModule {name} "{destination}"\n' for name, _, destination in APACHE_MODULES)
    routes = f'AliasMatch "^/$" "{ROOT_FILE}"\n'
    if case == "O3":
        # The declared path has no compiled file. Apache's internal local error
        # document supplies the public body while preserving the 404 status.
        routes += (f'ErrorDocument 404 "{ERROR_URI}"\n'
                   f'AliasMatch "^{re.escape(ERROR_URI)}$" "{SELECTED_FILE}"\n')
    elif case == "O4":
        other = http.action("B" if configuration == "A" else "A", "O1")
        routes += (f'RedirectMatch 302 "^{re.escape(path)}$" '
                   f'"http://{other["target"]}:{other["parameters"]["port"]}/"\n')
    else:
        routes += f'AliasMatch "^{re.escape(path)}$" "{SELECTED_FILE}"\n'
    headers = ("Header always set Content-Security-Policy \"default-src 'none'\"\n"
               "Header always set X-Frame-Options \"DENY\"\n"
               "Header always set X-Content-Type-Options \"nosniff\"\n"
               if case in ("O1", "R2", *NEGATIVE_CASES) else "")
    value = (modules
        + 'ServerRoot "/scratch"\nDefaultRuntimeDir "/scratch"\n'
          'PidFile "/scratch/apache2.pid"\nErrorLog "/scratch/error.log"\nLogLevel crit\n'
          'User reconlab\nGroup reconlab\n'
        + f'Listen {PRIVATE_ENDPOINT[0]}:{PRIVATE_ENDPOINT[1]} http\n'
          'ServerName 127.0.0.1\nUseCanonicalName On\nHostnameLookups Off\n'
        + f'ServerTokens {"Prod" if case == "O6" else "Full"}\n'
          'ServerSignature Off\nTraceEnable Off\n'
          'Timeout 5\nKeepAlive Off\nListenBacklog 8\nAcceptFilter http none\n'
          'StartServers 1\nMinSpareServers 1\nMaxSpareServers 1\n'
          'ServerLimit 1\nMaxRequestWorkers 1\nMaxConnectionsPerChild 0\n'
          'EnableSendfile Off\nEnableMMAP Off\n'
        + f'DocumentRoot "{PUBLIC_ROOT}"\n'
          '<Directory "/">\n    AllowOverride None\n    Options None\n    Require all denied\n</Directory>\n'
        + f'<Directory "{PUBLIC_ROOT}">\n    Require all granted\n'
          '    ForceType text/html\n    AddDefaultCharset UTF-8\n</Directory>\n'
        + routes + headers).encode("ascii")
    if len(value) > MAX_GENERATED_FILE_BYTES:
        raise ValueError("stock_apache_generated_config_limit")
    return value


def compiled_files(configuration, case):
    validate_selection(configuration, case)
    # The redirect's built-in body is not copied or predicted here.
    body = response_body(case)
    return (
        ("compiled:stock-apache-config", APACHE_CONFIG_PATH, apache_config(configuration, case)),
        ("compiled:stock-apache-root", ROOT_FILE, http.ORDINARY_BODY),
        ("compiled:stock-apache-selected", SELECTED_FILE, http.ORDINARY_BODY if body is None else body),
        ("compiled:stock-apache-passwd", "/etc/passwd", GENERATED_PASSWD),
        ("compiled:stock-apache-group", "/etc/group", GENERATED_GROUP),
        ("compiled:stock-apache-nsswitch", "/etc/nsswitch.conf", GENERATED_NSSWITCH),
    )


encode = http.encode


def selection(configuration, case):
    """Detached proposed inputs; no manifest can enable native execution."""
    validate_selection(configuration, case)
    raw = request_bytes(configuration, case)
    return {"schema_version": "1", "profile": PROFILE, "configuration": configuration,
        "case": case, "diagnostic_only": True, "live_calls_enabled": False,
        "daemon_execution_performed": False, "runtime_closure_verified": False,
        "native_compatibility_verified": False, "production_contract_enabled": False,
        "planned_contract": PLANNED_CONTRACT, "implementation": "apache", "reviewed_source_version": APACHE_VERSION,
        "action_kind": http.action_kind(case), "action": action(configuration, case),
        "request": {"ascii": raw.decode("ascii"), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "budgets": budgets(case), "owner_budgets": http.owner_budgets(),
        "apache_argv": list(APACHE_ARGV), "apache_environment": dict(APACHE_ENVIRONMENT),
        "namespace_identity": {"uid": NAMESPACE_UID, "gid": NAMESPACE_GID},
        "private_daemon_endpoint": {"transport": "tcp", "target": PRIVATE_ENDPOINT[0], "port": PRIVATE_ENDPOINT[1]},
        "modules": [{"module": name, "source": source, "destination": destination}
                    for name, source, destination in APACHE_MODULES],
        "denied_destinations": [{"target": target, "port": port} for target, port in http.witness_endpoints(configuration)],
        "expected": expectation(case),
        "compiled_files": [{"source": source, "destination": destination, "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()}
                           for source, destination, data in compiled_files(configuration, case)]}


def selection_digest(configuration, case):
    return hashlib.sha256(encode(selection(configuration, case))).hexdigest()
