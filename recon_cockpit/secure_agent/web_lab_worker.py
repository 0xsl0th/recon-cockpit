"""Reviewed HarborDesk specialization of the fixed disconnected owner."""

from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path
import time

if __package__:
    from . import owned_lab_worker as owner, web_fixture as fixture
else:
    _directory = Path(__file__).resolve().parent
    _spec = importlib.util.spec_from_file_location("web_fixed_owner", _directory / "owned_lab_worker.py")
    owner = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(owner)
    _spec = importlib.util.spec_from_file_location("web_fixed_fixture", _directory / "web_fixture.py")
    fixture = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(fixture)


def read_request(source):
    raw = source.readline(8193)
    if len(raw) > 8192 or not raw.endswith(b"\n"):
        raise ValueError("invalid_web_lab_request")
    value = json.loads(raw, object_pairs_hook=owner._unique)
    if (type(value) is not dict or set(value) != {"case", "deadline", "host_namespaces"}
            or type(value["case"]) is not str or value["case"] not in fixture.CASES
            or type(value["deadline"]) not in {int, float}
            or not math.isfinite(value["deadline"])
            or not 0 < value["deadline"] - time.monotonic() <= 60):
        raise ValueError("invalid_web_lab_request")
    return value


class WebService(owner.Service):
    def response(self, path):
        return fixture.response(self.case, path)


class WebOwner(owner.Owner):
    def read_request(self, source):
        return read_request(source)

    def create_service(self, request, listener):
        return WebService(request["case"], listener)


def main():
    return WebOwner().run()


if __name__ == "__main__":
    raise SystemExit(main())
