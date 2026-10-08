"""Fixed networkless parser entrypoint for owned TLS diagnostic observations."""

import json
import os
import resource
import stat
import sys

if not __package__:
    sys.path.insert(0, "/app")


def _private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor <= 2:
            continue
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != 9:
                raise
        else:
            raise ValueError("inherited_tls_observation_descriptor")


def _close_bootstrap_descriptors():
    # ctypes/libffi may retain an internal descriptor during the witnessed
    # bootstrap. No extra descriptors were present at entry, and no untrusted
    # input has been read. Close these before importing or running the parser.
    for name in os.listdir("/proc/self/fd"):
        descriptor = int(name)
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != 9:
                    raise


def main():
    try:
        if len(sys.argv) != 5 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("invalid_tls_observation_arguments")
        _private_descriptors()
        from recon_cockpit.secure_agent import planner_worker
        host = dict(zip(planner_worker.NAMESPACE_NAMES, sys.argv[1:], strict=True))
        checks = planner_worker._bootstrap(host)
        for kind, value in ((resource.RLIMIT_AS, 128 * 1024 * 1024), (resource.RLIMIT_CPU, 2)):
            resource.setrlimit(kind, (value, value))
            if resource.getrlimit(kind) != (value, value):
                raise ValueError("tls_observation_resource_limit_missing")
        _close_bootstrap_descriptors()
        _private_descriptors()
        from recon_cockpit.secure_agent import tls_posture_observation_contract as contract
        raw = sys.stdin.buffer.read(contract.MAX_INPUT_BYTES + 1)
        if not 0 < len(raw) <= contract.MAX_INPUT_BYTES:
            raise ValueError("invalid_tls_observation_input_size")
        try:
            result = contract.validate_observation(contract.parse_observation(raw))
            status = "parsed"
        except ValueError:
            result, status = None, "invalid"
        if result is not None:
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
            if len(encoded) > contract.MAX_RESULT_BYTES:
                raise ValueError("invalid_tls_observation_result_size")
        reply = json.dumps({"contract_version": contract.CONTRACT_VERSION, "boundary_checks": checks,
            "status": status, "result": result}, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(reply) + 1 > contract.MAX_RESULT_BYTES + 1024:
            raise ValueError("invalid_tls_observation_reply_size")
        sys.stdout.buffer.write(reply + b"\n")
        return 0
    except Exception:
        sys.stderr.write("tls_posture_observation_parser_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
