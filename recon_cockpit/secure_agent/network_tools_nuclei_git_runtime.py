"""Fixed Git HEAD marker profile using the existing sealed Nuclei boundary.

Only this compiled HTTP check is available. No ref, object, repository, template
or output-derived path is opened, and the C16 directory-listing bytes stay fixed.
"""

from . import network_tools_nuclei_runtime as shared
from .network_tools_nuclei_runtime import (
    BOUNDARY_FIELDS, CHUNK_BYTES, CONFIG_SEEDS, DESTINATION, EXECUTABLE,
    EXECUTABLE_SHA256, EXECUTABLE_SIZE, MAX_FILE_BYTES, MAX_MANIFEST_BYTES,
    MAX_RUNTIME_BYTES, MAX_WRITE_BYTES, SCRATCH, SCRATCH_BYTES, SCRATCH_INODES,
)

TOOL_ID = "nuclei_git_head_v1"
PROFILE = "network-tools-nuclei-git-static-runtime-v1"
TEMPLATE_ID = "recon-owned-git-head-v1"
TEMPLATE_PATH = "/tool/data/git-head.yaml"
# govaluate escapes the next rune rather than interpreting a backslash-n as LF.
# Fixed hex literals therefore commit the complete main/release bodies and LF.
TEMPLATE = b'''id: recon-owned-git-head-v1
info:
  name: Owned Git HEAD marker
  author: recon-cockpit
  severity: info
http:
  - method: GET
    path: ["http://127.0.0.1:8080/.git/HEAD"]
    headers:
      User-Agent: recon-cockpit-owned-nuclei/1
      Connection: close
      Accept-Encoding: identity
    redirects: false
    matchers:
      - type: dsl
        name: git-head-signature
        dsl:
          - 'status_code == 200 && content_type == "text/plain; charset=us-ascii" && (hex_encode(body) == "7265663a20726566732f68656164732f6d61696e0a" || hex_encode(body) == "7265663a20726566732f68656164732f72656c656173650a")'
'''
COMPILED = (("compiled:nuclei-template", TEMPLATE_PATH, TEMPLATE), *shared.COMPILED[1:])
ENVIRONMENT = dict(shared.ENVIRONMENT)
FIXED_ARGV = tuple(TEMPLATE_PATH if arg == shared.TEMPLATE_PATH else
    "http://127.0.0.1:8080/.git/HEAD" if arg == "http://127.0.0.1:8080/public/" else arg
    for arg in shared.FIXED_ARGV)


def manifest():
    return shared._manifest(TOOL_ID)


def validate_manifest(value, *, tool_id=None):
    return shared._validate_manifest(value, TOOL_ID, tool_id=tool_id)


def inspect_runtime(control):
    return shared._inspect_runtime(control, TOOL_ID)


def snapshot(value, control):
    return shared._snapshot(value, control, TOOL_ID)


def verify_mounted(value, control):
    return shared._verify_mounted(value, control, TOOL_ID)


def command(lab, bootstrap, value, descriptors, nonce, commitment):
    return shared._command(lab, bootstrap, value, descriptors, nonce, commitment, TOOL_ID)
