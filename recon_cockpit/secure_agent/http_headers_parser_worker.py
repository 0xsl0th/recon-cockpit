"""One networkless HTTP parse, entered only through the fixed runtime."""

import json
import resource
import sys

sys.path.insert(0, "/app")
import http_headers_parser
import planner_worker


def main() -> int:
    try:
        if len(sys.argv) != 5:
            raise ValueError("invalid_parser_arguments")
        host = dict(zip(("user", "net", "mnt", "pid"), sys.argv[1:]))
        checks = planner_worker._bootstrap(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 2)):
            resource.setrlimit(kind, (value, value))
        raw = sys.stdin.buffer.read(http_headers_parser.MAX_RESPONSE_BYTES + 1)
        try:
            parsed = http_headers_parser.parse_http_headers(raw)
            status = "parsed"
        except ValueError:
            parsed, status = None, "invalid"
        response = json.dumps({"profile": http_headers_parser.PARSER_VERSION,
                               "boundary_checks": checks, "status": status,
                               "result": parsed}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(response) > 1024:
            raise ValueError("invalid_parser_output_size")
        sys.stdout.buffer.write(response + b"\n")
        return 0
    except Exception:
        sys.stderr.write("http_headers_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
