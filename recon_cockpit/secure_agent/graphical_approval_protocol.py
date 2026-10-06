"""Graphical review bootstrap; review/consume retain the existing v1 protocol.

The frontend discriminator is part of the immutable bootstrap digest. There is
no affirmative-input operation on this authority channel.
"""

import math
import re

from . import approval_protocol as protocol
from .models import parse_policy

FRONTEND = 'graphical_v1'
AUTHORITY_PATH = '/run/reviewer.xauthority'
FONTCONFIG_PATH = '/run/reviewer-fonts.conf'
CHECKS = (protocol.CHECKS - {'terminal_operations_restricted'}) | {
    'display_bound', 'graphical_input_owned'}


def canonical_display(value):
    """Only the filesystem socket for a local display's first screen is allowed."""
    if type(value) is not str:
        raise ValueError('invalid_graphical_display')
    matched = re.fullmatch(r':(0|[1-9][0-9]{0,4})(?:\.0)?', value)
    if matched is None or int(matched[1]) > 65535:
        raise ValueError('invalid_graphical_display')
    return ':' + matched[1] + '.0'


def initial(value, now):
    fields = {'version', 'frontend', 'broker_id', 'session_id', 'policy',
              'deadline', 'display', 'display_socket'}
    if (type(value) is not dict or set(value) not in (fields, fields | {'witness'})
            or value['version'] != '1' or value['frontend'] != FRONTEND
            or type(value['deadline']) not in (int, float)
            or not math.isfinite(value['deadline'])
            or not 0 < value['deadline'] - now <= protocol.MAX_LIFETIME
            or canonical_display(value['display']) != value['display']):
        raise ValueError('invalid_graphical_approval_init')
    for name in ('display_socket', *(('witness',) if 'witness' in value else ())):
        if (type(value[name]) is not list or len(value[name]) != 2
                or any(type(item) is not int or item < 0 for item in value[name])):
            raise ValueError('invalid_graphical_approval_endpoint')
    protocol.identity(value['broker_id'])
    protocol.identity(value['session_id'])
    return parse_policy(value['policy'])
