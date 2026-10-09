"""Shared lifecycle hygiene for opted-in native Tk tests."""

import gc
import os
import sys
import threading

import pytest


@pytest.fixture(autouse=True)
def collect_retired_tk_objects(request):
    # A preceding fixture's cached window can outlive its own teardown. Collect
    # only after pytest has released that fixture, before this test starts any
    # workers that could otherwise finalize old Tk Variables off the main thread.
    graphical = any(os.environ.get(name) == "1" for name in
                    ("RECON_GUI_INTEGRATION", "RECON_GRAPHICAL_APPROVAL_INTEGRATION"))
    if graphical and "tkinter" in sys.modules and request.node.get_closest_marker("integration"):
        assert threading.current_thread() is threading.main_thread()
        gc.collect()
