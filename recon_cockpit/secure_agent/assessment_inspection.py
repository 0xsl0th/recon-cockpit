"""Shared, read-only dispatch for existing saved assessment evidence."""

import os

from .evidence import _read_private
from .models import load_json


def inspect_saved_assessment(directory) -> dict:
    """Replay a saved assessment through its existing reviewed inspector.

    The bounded private manifest selects only a fixed repository inspector. An
    unreadable or malformed manifest follows the legacy inspector's established
    failure path. Inspection never resumes an assessment or restores authority.
    """
    from .evidence import inspect_assessment

    manifest_fd = None
    try:
        manifest_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        manifest = load_json(_read_private(manifest_fd, "manifest.json", 8192))
    except (OSError, ValueError, RecursionError):
        manifest = {}
    finally:
        if manifest_fd is not None:
            os.close(manifest_fd)
    if type(manifest) is dict and manifest.get("workflow") in (
            "owned-nmap-http-assessment-v1", "owned-web-assessment-v1", "owned-http-headers-assessment-v1",
            "owned-web-tool-assessment-v1", "owned-network-tool-assessment-v1",
            "owned-service-web-assessment-v1"):
        from .nmap_evidence import inspect_assessment
    elif type(manifest) is dict and manifest.get("workflow") == "configurable-owned-http-ssh-v1":
        from .configurable_evidence import inspect_assessment
    return inspect_assessment(directory)
