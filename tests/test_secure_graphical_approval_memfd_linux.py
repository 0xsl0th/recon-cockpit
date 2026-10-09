"""Real Linux sealing evidence, separate from cross-platform portable tests."""

import errno
import fcntl
import os
import sys

import pytest

from recon_cockpit.secure_agent import graphical_approval_isolation as isolation


pytestmark = pytest.mark.integration


def test_bootstrap_copies_are_sealed_and_close_on_exec():
    if os.environ.get('RECON_GRAPHICAL_APPROVAL_INTEGRATION') != '1':
        pytest.skip('enable actual graphical approval integration')
    assert sys.platform == 'linux' and hasattr(os, 'memfd_create')
    fd = isolation._sealed_file('test-only-cookie', b'private-test-bytes')
    try:
        assert os.read(fd, 99) == b'private-test-bytes'
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        with pytest.raises(OSError) as write:
            os.write(fd, b'!')
        assert write.value.errno == errno.EPERM
        with pytest.raises(OSError):
            os.ftruncate(fd, 0)
        with pytest.raises(OSError):
            os.ftruncate(fd, 999)
    finally:
        os.close(fd)
