"""Networkless, exec-disabled parser for one bounded Nmap XML document."""

import json
import resource
import sys
from xml.parsers import expat  # Load native parser before installing the sandbox filter.

sys.path.insert(0, "/app")
import nmap_parser
import planner_worker


def main():
    try:
        if len(sys.argv) != 5:
            raise ValueError("invalid_nmap_parser_context")
        host = dict(zip(("user", "net", "mnt", "pid"), sys.argv[1:]))
        planner_worker._bootstrap(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 2)):
            resource.setrlimit(kind, (value, value))
        raw = sys.stdin.buffer.read(nmap_parser.MAX_XML_BYTES + 1)
        value = nmap_parser.parse_nmap_xml(raw)
        result = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(result) > 1024:
            raise ValueError("nmap_parser_output_limit")
        sys.stdout.buffer.write(result + b"\n")
        return 0
    except Exception:
        sys.stderr.write("nmap_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
