"""Fixed planning entrypoint for the existing disconnected TLS worker."""

import errno
import os
import sys


if __name__ == "__main__":
    # Check before importing TLS/ctypes: runtime imports can retain library FDs.
    try:
        for name in os.listdir("/proc/self/fd"):
            if int(name) <= 2:
                continue
            try:
                os.fstat(int(name))
            except OSError as exc:
                if exc.errno == errno.EBADF:
                    continue
                raise
            raise RuntimeError("planning_inherited_descriptor")
    except Exception:
        sys.stderr.write("planning_worker_refused\n")
        raise SystemExit(78) from None
    sys.path.insert(0, "/app")
    from provider_worker import _main
    raise SystemExit(_main(planning=True))
