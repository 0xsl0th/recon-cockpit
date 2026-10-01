"""Fixed networkless curl/ffuf parser entrypoint."""

import json
import resource
import sys

sys.path.insert(0, "/app")
import planner_worker
import web_tools_parser


def main():
    try:
        if len(sys.argv) != 6:
            raise ValueError("invalid_parser_arguments")
        tool_id = sys.argv[1]
        version = web_tools_parser.parser_version(tool_id)
        host = dict(zip(("user", "net", "mnt", "pid"), sys.argv[2:]))
        checks = planner_worker._bootstrap(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 2)):
            resource.setrlimit(kind, (value, value))
        raw = sys.stdin.buffer.read(web_tools_parser.MAX_OUTPUT_BYTES + 1)
        try:
            result = web_tools_parser.parse_tool_output(tool_id, raw)
            status = "parsed"
        except ValueError:
            result, status = None, "invalid"
        reply = json.dumps({"profile": version, "tool_id": tool_id, "boundary_checks": checks,
                            "status": status, "result": result}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(reply) > 4096:
            raise ValueError("invalid_parser_reply_size")
        sys.stdout.buffer.write(reply + b"\n")
        return 0
    except Exception:
        sys.stderr.write("web_tools_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
