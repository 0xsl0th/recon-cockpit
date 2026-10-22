"""One parser-only request after actual parent readiness observation."""
import os
import sys
ENTRY_VERIFIED=False
if __name__=='__main__':
    for _name in os.listdir('/proc/self/fd'):
        if int(_name)<=2:continue
        try:os.fstat(int(_name))
        except OSError:continue
        raise SystemExit(78)
    ENTRY_VERIFIED=True
    sys.path.insert(0,'/app')

import base64
import errno
import socket
import time
from recon_cockpit.secure_agent import engagement_live_runtime as runtime
from recon_cockpit.secure_agent import configurable_parser as parser
from recon_cockpit.secure_agent.configurable_scope import validate_scope


def parse_request(value,payload):
    runtime._fields(value,('schema_version','slot','scope','raw_base64','stderr_base64','truncated'))
    if value['schema_version']!='1' or value['slot']!=payload['slot'] or value['scope']!=payload['scope'] or type(value['truncated'])is not bool:runtime._fail('invalid_input')
    raw=runtime._meter_bytes(value['raw_base64'],8192);stderr=runtime._meter_bytes(value['stderr_base64'],8192)
    cap=8192 if value['slot']=='http_identify' else 2048
    if len(raw)+len(stderr)>cap:runtime._fail('limit_exceeded')
    tool=parser.NMAP if value['slot']=='http_identify' else parser.HEADERS
    parsed=parser.parse_tool_output(tool,raw,stderr,value['scope'],'http',truncated=value['truncated'])
    return {'schema_version':'1','slot':value['slot'],'parsed':parsed}


def main():
    if len(sys.argv)!=3 or not ENTRY_VERIFIED:return 78
    initial,manifest,rights,channel=runtime._receive_initial('parser',sys.argv[1],sys.argv[2],entry_verified=True)
    payload=initial['payload']
    if payload['slot'] not in ('http_identify','http_headers'):runtime._fail('invalid_input')
    validate_scope(payload['scope'])
    entry=runtime.check_role_entry(role='parser',bootstrap=initial,expected_fds=rights,observer=initial['observer'])
    ready=runtime.bootstrap_role(role='parser',entry=entry,runtime_manifest=manifest,expected_fds=rights,deadline_ns=initial['deadline_ns'])
    try:fd=os.open('/parser-create-witness',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except OSError as error:
        if error.errno not in (errno.EACCES,errno.EPERM,errno.EROFS):raise
    else:os.close(fd);runtime._fail('invalid_role')
    ready['boundary_checks'].update(network_creation_blocked=True,filesystem_creation_blocked=True,authority_absent=True,landlock_applied=True)
    runtime._emit_ready(ready)
    control=runtime._WorkerControl(initial['deadline_ns'])
    raw=runtime._receive_bytes(channel,16384,control)
    result=parse_request(runtime._decode(raw,16384),payload)
    reply=runtime._json(result)
    if len(reply)>4096:runtime._fail('limit_exceeded')
    runtime._send_bytes(channel,reply,control)
    channel.close();return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,RuntimeError):raise SystemExit(78)
