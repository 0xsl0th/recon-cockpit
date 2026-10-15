"""Finite routing bootstrap transport; witnesses remain separate authorities."""

import array
import hashlib
import json
import math
import os
import socket

from .models import _object_pairs

BOOTSTRAP_BYTES = 128 * 1024


def encode(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                     separators=(",", ":")).encode("ascii")
    if len(raw) > BOOTSTRAP_BYTES:
        raise ValueError("routing_bootstrap_limit")
    return raw


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    if type(raw) is not bytes or not raw or len(raw) > BOOTSTRAP_BYTES:
        raise ValueError("routing_bootstrap_limit")
    def constant(_):
        raise ValueError("routing_bootstrap_constant")
    def finite(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("routing_bootstrap_constant")
        return value
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_object_pairs,
                           parse_constant=constant, parse_float=finite)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("routing_bootstrap_json") from error
    if type(value) is not dict:
        raise ValueError("routing_bootstrap_object")
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError("routing_bootstrap_depth")
        children = item.values() if type(item) is dict else item if type(item) is list else ()
        pending.extend((child, depth + 1) for child in children)
    return value


def receive_bootstrap(channel):
    """Take exactly the audit and approval reader FDs; close all on failure."""
    descriptors = []
    try:
        raw, ancillary, flags, _ = channel.recvmsg(BOOTSTRAP_BYTES + 1, socket.CMSG_SPACE(256))
        invalid = bool(flags)
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                invalid = True
                continue
            values = array.array("i")
            if len(data) % values.itemsize:
                invalid = True
            values.frombytes(data[:len(data) - len(data) % values.itemsize])
            descriptors.extend(values)
        if invalid or len(descriptors) != 2:
            raise ValueError("routing_bootstrap_descriptors")
        for descriptor in descriptors:
            os.set_inheritable(descriptor, False)
        value = decode(raw)
        result, descriptors = descriptors, []
        return value, result
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
