"""A separate T03 runtime identity using the byte-identical accepted C14 client."""

from . import network_tools_ssh_algorithms_runtime as collector

TOOL_ID = "ssh_transport_policy_v1"
PROFILE = "network-tools-ssh-policy-runtime-v1"
EXECUTABLE = collector.EXECUTABLE
DESTINATION = collector.DESTINATION
FIXED_ARGV = collector.FIXED_ARGV
ENVIRONMENT = collector.ENVIRONMENT
COMPILED = collector.COMPILED
fixed_entries = collector.fixed_entries


def validate_manifest(value, *, tool_id=None):
    if (type(value) is not dict or value.get("tool_id") != TOOL_ID
            or value.get("profile") != PROFILE or tool_id not in (None, TOOL_ID)):
        raise ValueError("invalid_ssh_policy_runtime_manifest")
    # Validate every original closure field against the unchanged collector;
    # only the new public identity differs. Do not mutate either manifest.
    collector.validate_manifest({**value, "tool_id": collector.TOOL_ID,
        "profile": collector.PROFILE}, tool_id=collector.TOOL_ID)
    return value


def inspect_runtime(control):
    manifest = collector.inspect_runtime(control)
    return validate_manifest({**manifest, "tool_id": TOOL_ID, "profile": PROFILE})
