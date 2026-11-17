"""Exact engagement review text and the isolated worker's graphical view.

The host has no answer callback. Both views bind the complete Prepared value;
the original fixed rationale is omitted only from human-facing text.
"""

import json
import math
import select
import time

from . import engagement_live_contract as contract
from .graphical_approval_view import ReviewWindow as _AcceptedReviewWindow
from .graphical_approval_view import fresh_challenge


def _prepared(action, policy, envelope):
    return contract.validate_prepared({
        'schema_version': '1', 'action': action.to_dict(),
        'policy': policy.to_dict(), 'envelope': envelope,
    })


def check_review_time(envelope):
    """Sample the reviewer's own clocks; an RPC never supplies the current time."""
    return contract.check_clock(
        contract.sample_clock(), anchor=envelope['clock_anchor'],
        window_start_utc_ns=envelope['window_start_utc_ns'],
        window_end_utc_ns=envelope['window_end_utc_ns'],
        deadline_ns=min(envelope['action_deadline_ns'],
                        envelope['session_deadline_ns'], envelope['broker_deadline_ns']),
    )


def _utc(value):
    seconds, nanoseconds = divmod(value, 1_000_000_000)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(seconds)) + f'.{nanoseconds:09d}Z'


def review_text(action, policy, envelope):
    prepared = _prepared(action, policy, envelope)
    binding = prepared['envelope']
    displayed = dict(prepared['action'])
    displayed.pop('rationale', None)
    literal = lambda value: json.dumps(value, ensure_ascii=True)
    lines = [
        'Review this exact engagement action',
        'Engagement    ' + literal(binding['engagement_id']),
        'Revision      ' + str(binding['revision']),
        'Generation    ' + str(binding['generation']),
        'Ledger owner  ' + literal(binding['ledger_owner_id']),
        'Broker        ' + literal(binding['broker_id']),
        'Session       ' + literal(binding['session_id']),
        'Dispatch      ' + literal(binding['dispatch_id']),
        'Reviewer      ' + literal(binding['reviewer_id']),
        'Review mode   ' + literal(binding['review_mode']),
        'Tool profile  ' + literal(displayed['tool_id']),
        'Destination   ' + literal(displayed['target']) + ':' + str(displayed['parameters']['port']),
    ]
    if 'method' in displayed['parameters']:
        lines.append('Request       ' + literal(displayed['parameters']['method'])
                     + ' ' + literal(displayed['parameters']['path']))
    lines.extend([
        'Window starts ' + _utc(binding['window_start_utc_ns']),
        'Window ends   ' + _utc(binding['window_end_utc_ns']),
        'Policy        ' + literal(policy.policy_version),
        'Policy digest ' + policy.digest,
        'Action digest ' + action.digest,
        'Envelope hash ' + contract.envelope_digest(binding),
        'Fixed charge  ' + json.dumps(binding['cost'], sort_keys=True, ensure_ascii=True),
        'Output limit  ' + str(binding['output_limit']) + ' bytes',
        'Native limit  ' + str(binding['native_timeout_ns']) + ' nanoseconds',
        '', 'Exact action (fixed rationale omitted):',
        json.dumps(displayed, sort_keys=True, ensure_ascii=True, indent=2),
        '', 'Complete engagement envelope:',
        contract.canonical(binding).decode('ascii'),
    ])
    return '\n'.join(lines)


class ReviewWindow(_AcceptedReviewWindow):
    """Use the accepted widgets, stale-input draining and explicit button gesture."""

    def review(self, action, policy, envelope, peer_fd, *, deadline_ns=None):
        prepared = _prepared(action, policy, envelope)
        envelope = prepared['envelope']
        if self._closed or self._active or policy.evaluate(action).decision != 'approval_required':
            raise contract.LiveError('engagement_live_approval_unavailable')
        check_review_time(envelope)
        deadline = min(envelope['action_deadline_ns'], envelope['session_deadline_ns'],
                       envelope['broker_deadline_ns']) / 1_000_000_000
        if deadline_ns is not None:
            deadline = min(deadline,deadline_ns/1_000_000_000)
        poller = select.poll()
        poller.register(peer_fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
        self._deadline = deadline
        self._approve_button.configure(state='disabled')
        self._copy_button.configure(state='disabled')
        self._challenge_text.set('')
        self._entry.delete(0, 'end')
        self._challenge = None
        self._decision = None
        self._pump()
        self._entry.delete(0, 'end')
        check_review_time(envelope)
        if poller.poll(0):
            return False
        self._challenge = fresh_challenge(action)
        self._details.configure(state='normal')
        self._details.delete('1.0', 'end')
        self._details.insert('1.0', review_text(action, policy, envelope))
        self._details.configure(state='disabled')
        self._details.yview_moveto(0)
        self._challenge_text.set(self._challenge)
        self._feedback.configure(text='Enter does not approve. The phrase is valid only for this review.')
        self._active = True
        self._approve_button.configure(state='normal')
        self._copy_button.configure(state='normal')
        try:
            self._root.deiconify()
            self._root.lift()
            self._entry.focus_set()
            while self._decision is None:
                check_review_time(envelope)
                if time.monotonic() >= deadline:
                    contract.fail('timeout')
                if poller.poll(0):
                    return False
                self._time_label.configure(text=(
                    'Action time remaining: '
                    + str(max(0, math.ceil(deadline - time.monotonic()))) + ' seconds'))
                self._pump()
                if self._decision is None:
                    time.sleep(.01)
            check_review_time(envelope)
            if time.monotonic() >= deadline:
                contract.fail('timeout')
            return self._decision is True and not poller.poll(0)
        except self._tk.TclError:
            return False
        finally:
            self._active = False
            self._challenge = None
            self._decision = None
            try:
                self._entry.delete(0, 'end')
                self._challenge_text.set('')
                self._copy_button.configure(state='disabled')
                self._approve_button.configure(state='disabled')
                self._root.withdraw()
            except self._tk.TclError:
                self._closed = True
