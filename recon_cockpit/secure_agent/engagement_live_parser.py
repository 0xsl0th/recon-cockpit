"""Bounded isolated parsing with actual payload pinning and shared cleanup."""
import base64
import hashlib
import time

from . import engagement_live_runtime as rt
from . import configurable_parser as parser
from .configurable_scope import validate_scope


def _parse_observed(*,tool_id,raw,stderr,scope,truncated,control,runtime):
    if tool_id not in (parser.NMAP,parser.HEADERS) or type(raw)is not bytes or type(stderr)is not bytes or type(truncated)is not bool:rt._fail('invalid_input')
    slot='http_identify' if tool_id==parser.NMAP else 'http_headers'
    if len(raw)+len(stderr)>(8192 if slot=='http_identify' else 2048):rt._fail('limit_exceeded')
    scope=validate_scope(scope)
    request={'schema_version':'1','slot':slot,'scope':scope,'raw_base64':base64.b64encode(raw).decode('ascii'),
             'stderr_base64':base64.b64encode(stderr).decode('ascii'),'truncated':truncated}
    encoded=rt._json(request)
    if len(encoded)>16384:rt._fail('limit_exceeded')
    started=time.monotonic();bounded=rt._ClippedControl(control,min(control.deadline,started+2))
    owner=None;reply=None;cleanup=None
    try:
        owner=rt._start_role(runtime=runtime,role='parser',payload={'slot':slot,'scope':scope},rights={},control=bounded)
        owner.pin.check_alive();bounded.check()
        rt._send_bytes(owner.channel,encoded,bounded)
        reply=rt._receive_bytes(owner.channel,4096,bounded)
        decoded=rt._decode(reply,4096);rt._fields(decoded,('schema_version','slot','parsed'))
        if decoded['schema_version']!='1' or decoded['slot']!=slot:rt._fail('parser_unavailable')
        parsed=parser.validate_result(tool_id,decoded['parsed'],scope,'http')
        bounded.check()
    finally:
        if owner is not None:cleanup=owner.close()
    # Emergency reaping after refusal is permitted; late successful parsing is not.
    bounded.check();control.check()
    receipt={'schema_version':'1','slot':slot,'input_sha256':hashlib.sha256(encoded).hexdigest(),
        'output_sha256':hashlib.sha256(reply).hexdigest(),'input_bytes':len(encoded),'output_bytes':len(reply),
        'elapsed_ms':round((time.monotonic()-started)*1000),'readiness':rt._hash(owner.ready),'cleanup':cleanup}
    bounded.check()
    return parsed,receipt,owner.ready


def parse(*,tool_id,raw,stderr,scope,truncated,control,runtime):
    parsed,receipt,_=_parse_observed(tool_id=tool_id,raw=raw,stderr=stderr,scope=scope,
        truncated=truncated,control=control,runtime=runtime)
    return parsed,receipt
