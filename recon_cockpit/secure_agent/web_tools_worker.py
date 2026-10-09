"""One independently authorized curl/ffuf exec under a distinct confinement profile.

Unlike the existing Python-only workers this profile permits exec of its small
read/execute allowlist. It does not claim seccomp counts or prohibits re-exec.
"""

import os
import sys


def private_descriptors():
    for name in os.listdir("/proc/self/fd"):
        if int(name) > 2:
            try:
                os.fstat(int(name))
            except OSError:
                continue
            raise ValueError("web_tool_inherited_descriptor")


if __name__ == "__main__":
    try:
        private_descriptors()
    except Exception:
        sys.stderr.write("web_tool_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")

import errno
import hashlib
import json
import resource
import stat
import time

from recon_cockpit.secure_agent import tool_worker_common as common

if __package__:
    from . import web_tools_runtime as runtime, worker
    from .web_tools_execution import consume_launch
    from .owned_lab_executor import assert_lab_namespaces
else:
    from recon_cockpit.secure_agent import web_tools_runtime as runtime, worker
    from recon_cockpit.secure_agent.web_tools_execution import consume_launch
    from recon_cockpit.secure_agent.owned_lab_executor import assert_lab_namespaces


def verify_files(manifest):
    runtime.validate_manifest(manifest)
    for item in manifest["files"]:
        raw = runtime._read_regular(item["destination"])
        if len(raw) != item["size"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("web_tool_mounted_runtime_mismatch")
        if item["destination"] == manifest["executable"] and not raw.startswith(b"\x7fELF"):
            raise ValueError("web_tool_requires_elf")
        if "security.capability" in os.listxattr(item["destination"]):
            raise ValueError("web_tools_runtime_file_capabilities")
    if manifest["tool_id"] == runtime.FFUF and os.listdir(runtime.FFUF_SCRAPER_DIRECTORY):
        raise ValueError("web_tool_scraper_directory_not_empty")


def _landlock_permissions(manifest):
    permissions = {item["destination"]: 4 for item in manifest["files"]}
    permissions[manifest["executable"]] |= 1
    permissions[manifest["interpreter"]] |= 1
    permissions.update({"/dev/null": 6, "/dev/urandom": 4, "/dev/random": 4,
                        "/proc/self/status": 4, "/tool/data": 8})
    if manifest["tool_id"] == runtime.FFUF:
        # READ_DIR only: no config or scraper file can be read or created.
        permissions[runtime.FFUF_SCRAPER_DIRECTORY] = 8
    return permissions


def landlock(manifest):
    common.apply_landlock(_landlock_permissions(manifest))


def syscall_filter(tool_id):
    if tool_id not in (runtime.CURL, runtime.FFUF):
        raise ValueError("unsupported_web_tool")
    common.syscall_filter(allow_threads=tool_id == runtime.FFUF)


def _limits(tool_id):
    address_space = (2048 if tool_id == runtime.FFUF else 256) * 1024 * 1024
    threads = 16 if tool_id == runtime.FFUF else 1
    for kind, maximum in ((resource.RLIMIT_AS, address_space), (resource.RLIMIT_CPU, 5),
                           (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_NPROC, threads),
                           (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
        inherited = resource.getrlimit(kind)[1]
        bound = maximum if inherited == resource.RLIM_INFINITY else min(maximum, inherited)
        resource.setrlimit(kind, (bound, bound))


# Preserve the reviewed worker API while sharing the fixed kernel witnesses.
clone_denials = common.clone_denials
_namespace_task_count = common._namespace_task_count
_thread_bound_witness = common._thread_bound_witness
_witnesses = common._witnesses


def main():
    try:
        if len(sys.argv) != 3 or not stat.S_ISFIFO(os.fstat(0).st_mode):
            raise ValueError("web_tool_requires_authority_pipe")
        raw = sys.stdin.buffer.read(32769)
        request, deadline, namespaces, digest = consume_launch(raw, sys.argv[1], sys.argv[2])
        manifest = json.loads(raw)["runtime"]
        if runtime.manifest_digest(manifest) != digest:
            raise ValueError("web_tools_runtime_commitment_mismatch")
        assert_lab_namespaces(request["host_namespaces"], namespaces)
        verify_files(manifest)
        _limits(request["tool_id"])
        worker.drop_privileges()
        syscall_filter(request["tool_id"])
        _witnesses()
        if request["tool_id"] == runtime.FFUF:
            _thread_bound_witness()
        # The authority stdin and any loader-retained descriptors are gone.
        sys.stdin.close()
        for name in os.listdir("/proc/self/fd"):
            if int(name) > 2:
                try:
                    os.close(int(name))
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        landlock(manifest)
        if time.monotonic() >= deadline:
            raise TimeoutError("web_tool_authority_expired")
        # A closed stdin cannot become a new capability; Web tool reads no input.
        os.write(2, runtime.READY_PREFIX + sys.argv[2].encode("ascii") + b"\n")
        argv = runtime.FIXED_ARGV[request["tool_id"]]
        os.execve(argv[0], argv, runtime.execution_environment(request["tool_id"]))
        return 78
    except Exception:
        sys.stderr.write("web_tool_worker_refused\n")
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
