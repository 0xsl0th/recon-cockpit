"""Fixed networkless dig/OpenSSL parser entrypoint."""

import json
import resource
import sys

sys.path.insert(0, "/app")
import planner_worker
import network_tools_parser


def main():
    try:
        if len(sys.argv) != 6:
            raise ValueError("invalid_parser_arguments")
        tool_id = sys.argv[1]
        version = network_tools_parser.parser_version(tool_id)
        host = dict(zip(("user", "net", "mnt", "pid"), sys.argv[2:]))
        checks = planner_worker._bootstrap(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 2)):
            resource.setrlimit(kind, (value, value))
        payload = sys.stdin.buffer.read(network_tools_parser.MAX_OUTPUT_BYTES + 5)
        if len(payload) < 4 or len(payload) > network_tools_parser.MAX_OUTPUT_BYTES + 4:
            raise ValueError("invalid_parser_payload")
        output_size = int.from_bytes(payload[:4], "big")
        if output_size > len(payload) - 4:
            raise ValueError("invalid_parser_payload")
        raw, stderr = payload[4:4 + output_size], payload[4 + output_size:]
        try:
            result = network_tools_parser.parse_tool_output(tool_id, raw, stderr)
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
        sys.stderr.write("network_tools_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
