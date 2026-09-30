"""Fixed planning fixture entrypoint; shares the owned singleton network."""

import sys


if __name__ == "__main__":
    sys.path.insert(0, "/app")
    from provider_lab_worker import _main
    raise SystemExit(_main(planning=True))
