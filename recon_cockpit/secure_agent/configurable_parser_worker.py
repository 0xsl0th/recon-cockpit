"""Networkless parser bootstrap for one scope-bound original tool output."""

import base64
import json
import resource
import sys

sys.path.insert(0, "/app")
from recon_cockpit.secure_agent import planner_worker, configurable_parser
from recon_cockpit.secure_agent.models import load_json


def main():
    try:
        if len(sys.argv) != 6:
            raise ValueError("invalid_configurable_parser_arguments")
        tool_id = sys.argv[1]
        version = configurable_parser.parser_version(tool_id)
        host = dict(zip(("user", "net", "mnt", "pid"), sys.argv[2:]))
        checks = planner_worker._bootstrap(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 2)):
            resource.setrlimit(kind, (value, value))
        payload = sys.stdin.buffer.read(16385)
        if len(payload) > 16384:
            raise ValueError("invalid_configurable_parser_payload")
        value = load_json(payload)
        if set(value) != {"scope", "endpoint_id", "raw", "stderr"}:
            raise ValueError("invalid_configurable_parser_payload")
        for key in ("raw", "stderr"):
            if type(value[key]) is not str:
                raise ValueError("invalid_configurable_parser_base64")
        raw = base64.b64decode(value["raw"], validate=True)
        stderr = base64.b64decode(value["stderr"], validate=True)
        if (base64.b64encode(raw).decode("ascii") != value["raw"]
                or base64.b64encode(stderr).decode("ascii") != value["stderr"]):
            raise ValueError("invalid_configurable_parser_base64")
        try:
            result = configurable_parser.parse_output(tool_id, raw, stderr,
                scope=value["scope"], endpoint_id=value["endpoint_id"])
            status = "parsed"
        except ValueError:
            result, status = None, "invalid"
        reply = json.dumps({"profile": version, "tool_id": tool_id, "boundary_checks": checks,
                            "status": status, "result": result}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(reply) > 4096:
            raise ValueError("invalid_configurable_parser_reply_size")
        sys.stdout.buffer.write(reply + b"\n")
        return 0
    except Exception:
        sys.stderr.write("configurable_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
