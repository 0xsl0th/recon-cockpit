#!/usr/bin/env python3
"""Inspect a saved owned engagement bundle; no live authority is created."""
from pathlib import Path
import json
import os
import select
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
HELP = 'usage: engagement_live_inspect.py BUNDLE_DIRECTORY\nInspect saved owned evidence only. No store or live execution options.'


class _Discard:
    def write(self,value):return len(value)
    def flush(self):pass


def _emit(text,deadline=None):
    blocking=None
    def check():
        if deadline is not None and time.monotonic()>=deadline:raise OSError
    try:
        raw=(text+'\n').encode('ascii');check()
        if len(raw)>8192:raise OSError
        try:
            stdout_fd=sys.stdout.fileno()
            actual=type(stdout_fd) is int and stdout_fd==1
        except (AttributeError,OSError,ValueError):actual=False
        if actual:
            blocking=os.get_blocking(1);os.set_blocking(1,False)
            check();sys.stdout.flush()
            offset=0;attempts=0
            while offset<len(raw):
                check()
                if deadline is None and attempts:raise OSError
                attempts+=1
                try:count=os.write(1,raw[offset:])
                except BlockingIOError:
                    remaining=0 if deadline is None else max(0,deadline-time.monotonic())
                    if not remaining or not select.select([],[1],[],remaining)[1]:raise OSError from None
                    continue
                if count<=0:raise OSError
                offset+=count
            check();sys.stdout.flush()
            os.set_blocking(1,blocking);blocking=None
        else:
            check();value=raw.decode('ascii')
            count=sys.stdout.write(value)
            if type(count) is not int or count!=len(value):raise OSError
            check();sys.stdout.flush()
        check();return True
    except (Exception,KeyboardInterrupt):
        if blocking is not None:
            try:os.set_blocking(1,blocking)
            except (Exception,KeyboardInterrupt):pass
        # Only real descriptor1 may be redirected. Never retry a partial JSON.
        try:
            stdout_fd=sys.stdout.fileno()
            if type(stdout_fd) is int and stdout_fd==1:
                fd=os.open(os.devnull,os.O_WRONLY)
                try:os.dup2(fd,1)
                finally:
                    if fd!=1:os.close(fd)
        except (Exception,KeyboardInterrupt):pass
        sys.stdout=_Discard()
        return False


def main(argv=None):
    deadline=time.monotonic()+15
    args=sys.argv[1:] if argv is None else argv
    if args==['--help']:
        return 0 if _emit(HELP,min(deadline,time.monotonic()+2)) else 2
    emitted=False
    safe_error=lambda _: 'engagement_live_unavailable'
    try:
        from recon_cockpit.secure_agent.engagement_live_evidence import inspect_live_bundle, public_error_code
        safe_error=public_error_code
        from recon_cockpit.secure_agent.engagement_live_contract import LiveError
        if (type(args) is not list or len(args)!=1 or type(args[0]) is not str
                or not args[0] or args[0].startswith('-') or '\x00' in args[0]
                or '\n' in args[0] or len(args[0].encode('utf-8'))>4096):
            code='engagement_live_invalid_input'
        else:
            result=inspect_live_bundle(args[0],deadline=deadline)
            text=json.dumps(result,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False)
            if not _emit(text,deadline):return 2
            emitted=True
            if time.monotonic()>=deadline:return 2
            return 0 if result['status']=='complete' else 1
    except (Exception,KeyboardInterrupt) as error:
        candidate=getattr(error,'code',None)
        # Never echo an arbitrary exception/argument/path as a public code.
        code=safe_error(candidate)
    if emitted:return 2
    encoded=json.dumps({'schema_version':'1','error':code},sort_keys=True,separators=(',',':'))
    _emit(encoded)
    return 2


if __name__=='__main__':
    raise SystemExit(main())
