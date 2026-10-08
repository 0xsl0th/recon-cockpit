"""Production owner envelope around the reviewed private TLS peer mediator.

The request chooses a closed fixture case, never an address or executable. The
owned service retains both private socketpair descriptors and its synthetic TLS key.
"""

import importlib.util
import json
import math
from pathlib import Path
import time

if __package__:
    from . import tls_posture_mediated_owner as mediated
    from . import network_tools_tls_posture_spec as spec
    from .network_tools_tls_posture_receipt import encode_owner_receipt
else:
    def _load(name, filename):
        definition = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(definition)
        definition.loader.exec_module(module)
        return module
    mediated = _load("tls_posture_production_mediator", "tls_posture_mediated_owner.py")
    spec = _load("tls_posture_production_spec", "network_tools_tls_posture_spec.py")
    encode_owner_receipt = _load("tls_posture_production_receipt",
        "network_tools_tls_posture_receipt.py").encode_owner_receipt


class Service(mediated.Service):
    def snapshot(self, minimum_connections, minimum_requests, deadline):
        original = super().snapshot(minimum_connections, minimum_requests, deadline)
        raw = json.dumps(original, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
        return {"connection_count": original["connection_count"],
                "request_count": original["request_count"],
                "tls_posture_owner": encode_owner_receipt(raw)}


class Owner(mediated.MediatedOwner):
    def read_request(self, source):
        raw = source.readline(8193)
        if len(raw) > 8192 or not raw.endswith(b"\n"):
            raise ValueError("invalid_tls_posture_owner_request")
        value = json.loads(raw, object_pairs_hook=mediated.fixture.owner._unique)
        if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
                or type(value["deadline"]) not in {int, float}
                or not math.isfinite(value["deadline"])
                or not 0 < value["deadline"] - time.monotonic() <= spec.LIMITS["max_runtime_seconds"]):
            raise ValueError("invalid_tls_posture_owner_request")
        version, variant = spec.case_parts(value["case"])
        return {"case": variant, "version": version, "deadline": value["deadline"],
                "host_namespaces": value["host_namespaces"]}

    def create_service(self, request, listener):
        self.service = Service(request, listener)
        return self.service


def main():
    return Owner().run()


if __name__ == "__main__":
    raise SystemExit(main())
