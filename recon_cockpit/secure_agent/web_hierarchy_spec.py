"""Finite development-only T04 corpus; no product registration or authority."""

CASES = ("nested", "empty", "wildcard", "mixed-controls", "redirect", "hostile", "stalled")
BASE = "/harbordesk/"
PREFIXES = (BASE, BASE + "docs/", BASE + "api/")
RESOURCE_NAMES = ("index.html", "status")
CONTROL_NAMES = ("missing-control-a", "missing-control-b")
WORDS = tuple(prefix.removeprefix(BASE) + name
              for prefix in PREFIXES for name in (*RESOURCE_NAMES, *CONTROL_NAMES))
PATHS = tuple(BASE + word for word in WORDS)
WORDLIST = ("\n".join(WORDS) + "\n").encode("ascii")
SESSION_SECONDS = 60
CLIENT_SECONDS = 10
MAX_OUTPUT_BYTES = 8192
MAX_OWNER_MESSAGE = 24576
MAX_REQUEST_BYTES = 1024
MAX_WIRE_BYTES = 1024
MAX_CONNECTIONS = 16
PARSER_VERSION = "web-hierarchy-diagnostic-json-v1"


def validate_case(case):
    if type(case) is not str or case not in CASES:
        raise ValueError("invalid_web_hierarchy_case")
    return case
