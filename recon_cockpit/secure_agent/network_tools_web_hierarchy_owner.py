"""Closed production case mapping around the reviewed finite HTTP owner."""

import importlib.util
import json
import math
from pathlib import Path
import time

if __package__:
    from . import web_hierarchy_owner as native
    from . import network_tools_web_hierarchy_spec as spec
else:
    def _load(name, filename):
        definition = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(definition)
        definition.loader.exec_module(module)
        return module
    native = _load("production_hierarchy_native_owner", "web_hierarchy_owner.py")
    spec = _load("production_hierarchy_owner_spec", "network_tools_web_hierarchy_spec.py")


class Owner(native.Owner):
    def read_request(self, source):
        raw = source.readline(8193)
        if len(raw) > 8192 or not raw.endswith(b"\n"):
            raise ValueError("invalid_web_hierarchy_owner_request")
        value = json.loads(raw, object_pairs_hook=native.owner._unique)
        if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
                or type(value["deadline"]) not in {int, float}
                or not math.isfinite(value["deadline"])
                or not 0 < value["deadline"] - time.monotonic() <= spec.LIMITS["max_runtime_seconds"]):
            raise ValueError("invalid_web_hierarchy_owner_request")
        variant = spec.case_parts(value["case"])
        return {"case": variant, "deadline": value["deadline"],
                "host_namespaces": value["host_namespaces"]}


def main():
    return Owner().run()


if __name__ == "__main__":
    raise SystemExit(main())
