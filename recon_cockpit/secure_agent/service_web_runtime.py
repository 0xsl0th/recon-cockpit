"""Pin exactly the two accepted native runtimes used by the owned workflow."""

from copy import deepcopy

from . import network_tools_runtime, web_tools_runtime


NATIVE_TOOL_IDS = (network_tools_runtime.NMAP_SERVICE, web_tools_runtime.FFUF)


def validate_manifests(value):
    if type(value) is not dict or set(value) != set(NATIVE_TOOL_IDS):
        raise ValueError("invalid_service_web_runtime_map")
    network_tools_runtime.validate_manifest(value[NATIVE_TOOL_IDS[0]], tool_id=NATIVE_TOOL_IDS[0])
    web_tools_runtime.validate_manifest(value[NATIVE_TOOL_IDS[1]], tool_id=NATIVE_TOOL_IDS[1])
    return deepcopy(value)


def inspect_service_web_runtime(control):
    return validate_manifests({
        NATIVE_TOOL_IDS[0]: network_tools_runtime.inspect_tool_runtime(NATIVE_TOOL_IDS[0], control),
        NATIVE_TOOL_IDS[1]: web_tools_runtime.inspect_tool_runtime(NATIVE_TOOL_IDS[1], control)})


def runtime_source_mounts(value):
    value = validate_manifests(value)
    mounts = (network_tools_runtime.runtime_source_mounts(value[NATIVE_TOOL_IDS[0]])
              + web_tools_runtime.runtime_source_mounts(value[NATIVE_TOOL_IDS[1]]))
    # Overlapping shared libraries have one identical host source/destination.
    return sorted(set(mounts))


def project_closure(closure, tool_id):
    """A child receives only its selected manifest, never the other executable."""
    if tool_id not in NATIVE_TOOL_IDS:
        raise ValueError("invalid_service_web_runtime_tool")
    manifests = validate_manifests(closure["service_web_runtime"])
    key = "network_tools_runtime" if tool_id == NATIVE_TOOL_IDS[0] else "web_tools_runtime"
    return {"stdlib": closure["stdlib"], "files": list(closure["files"]), key: manifests[tool_id]}
