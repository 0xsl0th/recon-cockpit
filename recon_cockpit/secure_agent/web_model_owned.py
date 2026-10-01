"""Small owned TLS fixture for the real transport; never a model-quality claim."""
from contextlib import contextmanager
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
from uuid import uuid4

from .execution import ExecutionControl
from .provider_lab import _certificates
from .provider_pilot_contract import MODEL, PilotConfig
from .web_assessment_contract import action, encode
from .web_fixture import OPERATOR_NOTE


@contextmanager
def owned_provider(case, scenario, price, call_cap):
    from .web_model_contract import validate_request
    from .web_model_transport import LinuxWebModelTransport

    if scenario not in ("success", "refusal", "injection", "malformed", "missing_usage"):
        raise ValueError("invalid_owned_model_scenario")
    stop = threading.Event()
    errors = []
    key = "synthetic-" + uuid4().hex + uuid4().hex
    with tempfile.TemporaryDirectory(prefix="recon-web-model-owned-") as tmp:
        root = Path(tmp)
        ca = _certificates(root, "success", ExecutionControl(time.monotonic() + 15))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "server.crt", root / "server.key")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(3)
        listener.settimeout(.1)
        port = listener.getsockname()[1]

        def serve():
            count = 0
            while not stop.is_set() and count < 3:
                try:
                    raw, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                try:
                    raw.settimeout(3)
                    with context.wrap_socket(raw, server_side=True) as connection:
                        wire = b""
                        while b"\r\n\r\n" not in wire:
                            data = connection.recv(4096)
                            if not data or len(wire) + len(data) > 24576:
                                raise ValueError("invalid_fixture_request")
                            wire += data
                        headers, body = wire.split(b"\r\n\r\n", 1)
                        lines = headers.split(b"\r\n")
                        fields = dict(line.split(b": ", 1) for line in lines[1:])
                        length = int(fields[b"Content-Length"])
                        if (lines[0] != b"POST /v1/responses HTTP/1.1" or not 1 <= length <= 16384
                                or fields[b"Host"] != b"provider.owned.invalid"
                                or fields[b"Authorization"] != b"Bearer " + key.encode()):
                            raise ValueError("invalid_fixture_request")
                        while len(body) < length:
                            part = connection.recv(min(4096, length - len(body)))
                            if not part:
                                raise ValueError("incomplete_fixture_request")
                            body += part
                        validate_request(body)
                        request = json.loads(body)
                        observation = json.loads(request["input"][1]["content"][0]["text"])
                        step = observation["step"]
                        count += 1
                        proposal = action(case, step)
                        # Exercise metadata normalization with actual model-shaped output.
                        proposal.update(action_id=str(uuid4()), rationale="Synthetic model fixture proposal")
                        if (scenario == "injection" and step == 3
                                and json.loads(observation["untrusted_observation"]["body"]).get("operator_note") == OPERATOR_NOTE):
                            proposal["target"] = "127.0.0.2"
                        content = [{"type": "output_text", "text": encode({"schema_version": "1",
                            "action": proposal, "done": step == 3}).decode()}]
                        if scenario == "refusal":
                            content = [{"type": "refusal", "refusal": "Synthetic refusal of eligible owned task"}]
                        elif scenario == "malformed":
                            content = [{"type": "output_text", "text": "{}"}]
                        response = {"object": "response", "id": "resp_owned_" + uuid4().hex,
                            "model": MODEL, "status": "completed", "service_tier": "default",
                            "error": None, "incomplete_details": None,
                            "output": [{"type": "message", "role": "assistant", "status": "completed", "content": content}],
                            "usage": {"input_tokens": 1200, "output_tokens": 256, "total_tokens": 1456,
                                      "input_tokens_details": {"cached_tokens": 0},
                                      "output_tokens_details": {"reasoning_tokens": 0}}}
                        if scenario == "missing_usage":
                            response.pop("usage")
                        body = encode(response)
                        connection.sendall(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                            "Connection: close\r\nContent-Length: " + str(len(body)) + "\r\n\r\n").encode() + body)
                except (ssl.SSLError, OSError):
                    pass
                except Exception:
                    errors.append("owned_model_fixture_failed")
                finally:
                    raw.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        config = PilotConfig("127.0.0.1", price, call_cap, mode="owned", enabled=True, port=port)
        try:
            yield config, lambda: LinuxWebModelTransport(config, ca_pem=ca, synthetic_credential=key)
        finally:
            stop.set()
            listener.close()
            thread.join(4)
            if thread.is_alive() or errors:
                raise RuntimeError("owned_model_fixture_failed")
