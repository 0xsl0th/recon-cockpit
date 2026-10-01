"""One explicitly enabled web-model request through the isolated TLS broker.

The host validates billing fields and a bounded opaque response; only the
separate networkless model parser interprets the proposal text.
"""

from __future__ import annotations

import base64
import binascii
import re

from .cost_contract import CostError, TokenUsage
from .provider_contract import WORKER_STATUSES
from .provider_pilot import LinuxPilotTransport
from .provider_pilot_contract import PilotError
from .web_model_contract import MAX_RESPONSE_BYTES, OUTPUT_STATUSES


def _receipt(value):
    try:
        if (type(value) is not dict or set(value) != {"status", "http_status", "summary", "response_b64"}
                or type(value["status"]) is not str or value["status"] not in WORKER_STATUSES
                or value["http_status"] is not None and (type(value["http_status"]) is not int
                                                        or not 100 <= value["http_status"] <= 599)):
            raise ValueError
        summary, response = value["summary"], value["response_b64"]
        if value["status"] != "ok":
            if summary is not None or response is not None:
                raise ValueError
        else:
            if (value["http_status"] != 200 or type(summary) is not dict
                    or set(summary) != {"usage", "reference", "output_status"}
                    or type(summary["output_status"]) is not str or summary["output_status"] not in OUTPUT_STATUSES):
                raise ValueError
            if summary["usage"] is None:
                if summary["reference"] is not None:
                    raise ValueError
            else:
                if (type(summary["usage"]) is not dict
                        or set(summary["usage"]) != {"input_tokens", "output_tokens", "cached_input_tokens"}
                        or type(summary["reference"]) is not str
                        or re.fullmatch(r"response-[a-f0-9]{64}", summary["reference"]) is None):
                    raise ValueError
                TokenUsage(**summary["usage"])
            if summary["output_status"] == "proposal":
                if type(response) is not str or len(response) > 4 * ((MAX_RESPONSE_BYTES + 2) // 3):
                    raise ValueError
                decoded = base64.b64decode(response, validate=True)
                if not 1 <= len(decoded) <= MAX_RESPONSE_BYTES or base64.b64encode(decoded).decode("ascii") != response:
                    raise ValueError
                response = decoded
            elif response is not None:
                raise ValueError
        return {"status": value["status"], "http_status": value["http_status"],
                "summary": summary, "response": response}
    except (ValueError, TypeError, KeyError, CostError, binascii.Error):
        raise PilotError("pilot_invalid_receipt") from None


class LinuxWebModelTransport(LinuxPilotTransport):
    """Fresh, single-use transport; constructor never reads credentials or CA files."""

    @property
    def boundary_checks(self):
        return dict(self._boundary_checks or {})

    @property
    def cleanup_verified(self):
        return self._cleanup_verified

    def exchange(self, request: bytes, *, control, authorize):
        # Disabled is rejected before request parsing, runtime or credential I/O.
        if not self.config.enabled:
            raise PilotError("pilot_disabled")
        if type(request) is not bytes:
            raise PilotError("pilot_invalid_config")
        result = self._exchange(control=control, authorize=authorize, web_request=request)
        return _receipt(result)
