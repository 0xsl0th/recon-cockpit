"""Desktop entry point; help and package import do not require a display."""

import argparse
from pathlib import Path
import sys


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local offline scope and saved-evidence desktop.")
    parser.add_argument("--assessment", type=Path, help="Inspect an existing private assessment directory.")
    parser.add_argument("--theme", choices=("light", "dark"), default="dark")
    args = parser.parse_args(argv)
    try:
        import tkinter as tk
    except ImportError:
        print("The desktop requires Python's Tk component (python3-tk on Debian/Kali).", file=sys.stderr)
        return 2
    try:
        root = tk.Tk()
    except tk.TclError:
        print("No graphical display is available. Open the desktop in a local graphical session.", file=sys.stderr)
        return 2
    from .controller import DesktopController
    from .window import CockpitWindow
    controller = DesktopController()
    try:
        window = CockpitWindow(root, controller, theme=args.theme)
        if args.assessment is not None:
            controller.inspect_directory(args.assessment)
            window.refresh()
        root.mainloop()
    finally:
        # Window close waits for replay. No execution or daemon worker is ever
        # started by this adapter; interpreter exit also joins a reader on error.
        controller.close()
    return 0
