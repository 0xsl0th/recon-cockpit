"""Fixed no-network request builder and response parser for a trusted broker."""

import importlib.util
import sys


def main():
    try:
        # No request/response codec or observation parsing precedes bootstrap.
        spec = importlib.util.spec_from_file_location("secure_openai_bootstrap", "/app/planner_worker.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("missing bootstrap")
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        _, host = bootstrap._arguments(["three_step", *sys.argv[1:]])
        checks = bootstrap._bootstrap(host)
        # Only this fixed read-only package tree is mounted by the parent.
        sys.path.insert(0, "/app")
        from recon_cockpit.secure_agent import broker_ipc, openai_protocol

        raw = broker_ipc.read_frame(sys.stdin.buffer, broker_ipc.INIT)
        init = openai_protocol._decode_object(raw, broker_ipc.MAX_INIT_BYTES)
        profile = init.get("profile", openai_protocol.LEGACY_PROPOSAL_PROFILE)
        fields = {"schema_version", "config", "observation"}
        if profile == openai_protocol.WEB_MODEL_PROFILE:
            fields.add("profile")
        elif "profile" in init:
            raise ValueError("invalid profile")
        if set(init) != fields or init["schema_version"] != "1":
            raise ValueError("invalid initialization")
        config = init["config"]
        if type(config) is not dict or set(config) != {"model", "max_output_tokens"}:
            raise ValueError("invalid configuration")
        arguments = (openai_protocol.OpenAIConfig(**config), openai_protocol._encode(init["observation"]))
        request = (openai_protocol.build_request(*arguments, profile=profile)
                   if profile == openai_protocol.WEB_MODEL_PROFILE else openai_protocol.build_request(*arguments))
        sys.stdout.buffer.write(broker_ipc.frame(broker_ipc.REQUEST, request))
        sys.stdout.buffer.flush()
        response = broker_ipc.read_frame(sys.stdin.buffer, broker_ipc.RESPONSE)
        if sys.stdin.buffer.read(1) != b"":
            raise ValueError("extra broker input")
        output_status = "proposal"
        try:
            proposal = (openai_protocol.decode_response(response, profile=profile)
                        if profile == openai_protocol.WEB_MODEL_PROFILE else openai_protocol.decode_response(response))
            proposal = openai_protocol._decode_object(proposal, 16384)
        except openai_protocol.OpenAIProtocolError:
            if profile != openai_protocol.WEB_MODEL_PROFILE:
                raise
            proposal, output_status = None, "invalid"
        result = {
            "schema_version": "1", "proposal": proposal,
            "boundary_checks": checks,
        }
        if profile == openai_protocol.WEB_MODEL_PROFILE:
            result.update(profile=profile, output_status=output_status)
        envelope = openai_protocol._encode(result)
        sys.stdout.buffer.write(broker_ipc.frame(broker_ipc.RESULT, envelope))
        sys.stdout.buffer.flush()
    except Exception:
        sys.stderr.write("secure_openai_worker_failed\n")
        return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
