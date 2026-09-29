"""Immutable session ceilings shared by authority and confined launchers."""

from dataclasses import asdict, dataclass
import hashlib
import json


@dataclass(frozen=True, slots=True)
class SessionLimits:
    max_steps: int = 3
    max_runtime_seconds: int = 60
    max_output_bytes: int = 3072

    def __post_init__(self):
        for name, maximum in (("max_steps", 16), ("max_runtime_seconds", 600),
                              ("max_output_bytes", 16 * 65536)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError("invalid_session_" + name)

    @property
    def digest(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True,
                                         separators=(",", ":")).encode("ascii")).hexdigest()
