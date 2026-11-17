"""Explicit owned HTTP engagement runner; its default invocation is inert."""

import json
import os
from pathlib import Path
import select
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PROFILE = 'engagement-http-prefix-live-v1'
DESCRIPTION = ('Owned HTTP engagement execution requires --execute, an existing engagement store, '
               'audit and evidence paths, and an explicit review mode.')
HELP = ('usage: engagement_live.py [--execute] [--store-directory PATH] '
        '[--audit-path PATH] [--output-directory PATH] '
        '[--review-mode terminal|graphical_v1] [--help]\n')
VALUE_OPTIONS = frozenset(('--store-directory', '--audit-path', '--output-directory', '--review-mode'))


def parse_options(arguments):
    """Reject duplicate and expanded forms before opening any operator path."""
    if type(arguments) not in (list, tuple) or any(type(x) is not str for x in arguments):
        raise ValueError('engagement_live_invalid_input')
    result = {'execute': False, 'help': False, 'store_directory': None,
              'audit_path': None, 'output_directory': None, 'review_mode': None}
    seen = set()
    index = 0
    while index < len(arguments):
        option = arguments[index]
        if option in seen or option not in VALUE_OPTIONS | {'--execute', '--help'}:
            raise ValueError('engagement_live_invalid_input')
        seen.add(option)
        key = option[2:].replace('-', '_')
        if option in {'--execute', '--help'}:
            result[key] = True
            index += 1
            continue
        if index + 1 >= len(arguments):
            raise ValueError('engagement_live_invalid_input')
        value = arguments[index + 1]
        if option == '--review-mode':
            if value not in {'terminal', 'graphical_v1'}:
                raise ValueError('engagement_live_invalid_input')
        else:
            try:
                raw = value.encode('utf-8', errors='strict')
            except UnicodeError:
                raise ValueError('engagement_live_invalid_input') from None
            if not 0 < len(raw) <= 4096 or any(c in value for c in ('\0', '\n', '\r')):
                raise ValueError('engagement_live_invalid_input')
        result[key] = value
        index += 2
    if result['execute'] and any(result[k] is None for k in (
            'store_directory', 'audit_path', 'output_directory', 'review_mode')):
        raise ValueError('engagement_live_invalid_input')
    return result


def _output(raw, deadline):
    if type(raw) is not bytes or len(raw) > 8192:
        raise ValueError('engagement_live_limit_exceeded')
    fd = sys.stdout.fileno()
    blocking = os.get_blocking(fd)
    os.set_blocking(fd, False)
    offset = 0
    try:
        while offset < len(raw):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise ValueError('engagement_live_timeout')
            if time.monotonic() >= deadline:
                raise ValueError('engagement_live_timeout')
            try:
                count = os.write(fd, raw[offset:])
            except BlockingIOError:
                continue
            if count <= 0:
                raise ValueError('engagement_live_unavailable')
            offset += count
        if time.monotonic() >= deadline:
            raise ValueError('engagement_live_timeout')
    except BaseException as error:
        error.output_started = offset > 0
        raise
    finally:
        os.set_blocking(fd, blocking)


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'


def _run(options, outer_deadline):
    from recon_cockpit.secure_agent.execution import ExecutionControl
    from recon_cockpit.secure_agent.engagement_live_session import EngagementSession
    from recon_cockpit.secure_agent.engagement_live_evidence import inspect_live_bundle, write_live_bundle

    control = ExecutionControl(min(outer_deadline - 30, time.monotonic() + 120))
    service = None
    error = None
    try:
        service = EngagementSession.start(options['store_directory'], options['audit_path'],
                                          review_mode=options['review_mode'], control=control)
        opened = service.open_session()
        session_id = opened['binding']['session_id']
        for slot in ('http_identify', 'http_headers'):
            prepared = service.prepare(session_id, slot)
            reference = service.review(prepared, control=control)
            if reference is None:
                service.cancel(session_id)
                break
            result = service.execute(prepared, reference, control=control)
            if result['outcome'] != 'useful':
                break
    except Exception as failure:
        error = failure
        if service is None:
            service = getattr(failure,'engagement_session',None)
    finally:
        if service is not None:
            try:
                service.close()
            except Exception as cleanup_error:
                if not service._verified_reaped():
                    raise
                # Retain an observed timing failure after verified reaping.
                # The inspector still sees the failed cleanup receipt.
                if error is None:
                    error = cleanup_error
    if service is None:
        raise error
    packaging_deadline = min(outer_deadline-15,time.monotonic()+15)
    manifest, members = service._evidence_payload(deadline=packaging_deadline,
                                                 recover=error is not None)
    write_live_bundle(options['output_directory'], manifest=manifest, members=members,
                      deadline=packaging_deadline)
    return inspect_live_bundle(options['output_directory'],
                               deadline=min(outer_deadline, time.monotonic() + 15))


def main(arguments=None):
    started = time.monotonic()
    deadline = started + 2
    try:
        options = parse_options(sys.argv[1:] if arguments is None else arguments)
        if options['help']:
            _output(HELP.encode('ascii'), deadline)
            return 0
        if not options['execute']:
            _output(_encoded({'schema_version': '1', 'profile': PROFILE,
                              'execute': False, 'description': DESCRIPTION}), deadline)
            return 0
        deadline = started + 150
        report = _run(options, deadline)
        _output(_encoded(report), deadline)
        return 0 if report['status'] == 'complete' else 1
    except Exception as exc:
        if getattr(exc,'output_started',False):
            return 2
        from recon_cockpit.secure_agent.engagement_live_contract import LiveError
        code = exc.code if isinstance(exc, LiveError) else 'engagement_live_invalid_input'
        if type(exc) is ValueError and exc.args and exc.args[0] in {
                'engagement_live_invalid_input', 'engagement_live_timeout',
                'engagement_live_limit_exceeded', 'engagement_live_unavailable'}:
            code = exc.args[0]
        if isinstance(exc, (OSError, TimeoutError)):
            code = 'engagement_live_unavailable'
        try:
            _output(_encoded({'schema_version': '1', 'profile': PROFILE, 'error': code}), deadline)
        except Exception:
            pass
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
