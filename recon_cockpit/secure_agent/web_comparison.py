"""Bounded offline paired trials and independent, read-only aggregate replay."""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import threading
import time
from uuid import uuid4

from .audit import AuditSink, AuditUnavailable
from .evaluation import (EvaluationRunner, EvaluationLimits, EvaluationUnavailable,
    _Directory, _open_directory, _uuid, _ENVELOPE, _END_REASONS)
from .evidence import _encode, _read_private
from .models import load_json, parse_policy
from .web_comparison_contract import (ARMS, CASES, FIXED_LIMITS, RESERVATION, evaluation_identity,
                                      plan, validate_policy)

MAX_MANIFEST_BYTES = 32768
MAX_JOURNAL_BYTES = 131072
MAX_REPORT_BYTES = 524288


def _totals(count):
    return {key: value * count for key, value in RESERVATION.items()}


class WebComparisonRunner(EvaluationRunner):
    """Reuse cancellation only; each trial has the unchanged web authority."""

    def __init__(self, directory, policy, limits=None):
        self.directory = Path(directory)
        self.policy = validate_policy(policy)
        self.limits = EvaluationLimits() if limits is None else limits
        if type(self.limits) is not EvaluationLimits:
            raise ValueError('invalid_web_comparison_limits')
        self.evaluation_id = str(uuid4())
        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._used = False
        self._active = self._stop_reason = self._deadline = None

    def _stop(self, reason):
        self._cancelled.set()
        super()._stop(reason)

    def _run_trial(self, path, case, arm):
        from .web_comparison_runtime import run_trial
        run_trial(self, path, case, arm)

    def run(self, *, execute=False, on_trial=None):
        from .web_comparison_grading import grade_trial
        if type(execute) is not bool:
            raise ValueError('invalid_web_comparison_mode')
        with self._lock:
            if self._used:
                raise RuntimeError('evaluation_already_used')
            self._used = True
            started = time.monotonic()
            self._deadline = started + self.limits.max_runtime_seconds
        trials = plan(self.limits.repeats)
        timer = threading.Timer(self.limits.max_runtime_seconds, lambda: self._stop('deadline'))
        timer.daemon = True
        timer.start()
        try:
            with _Directory(self.directory) as directory:
                directory.write('manifest.json', {
                    'schema_version': '1', 'evaluation_id': self.evaluation_id,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'evaluation': evaluation_identity(), 'limits': asdict(self.limits),
                    'trial_limits': FIXED_LIMITS, 'policy': self.policy.to_dict(),
                    'policy_digest': self.policy.digest, 'plan': trials,
                    'reservation_per_trial': RESERVATION, 'batch_allowances': _totals(len(trials)),
                    'mode': 'execute' if execute else 'dry_run', 'live_calls_enabled': False,
                }, MAX_MANIFEST_BYTES)
                with AuditSink(self.directory / 'evaluation.jsonl') as audit:
                    def emit(kind, **fields):
                        directory.check()
                        event = {'evaluation_id': self.evaluation_id, 'event_type': kind, **fields}
                        if os.stat('evaluation.jsonl', dir_fd=directory.fd).st_size + len(_encode(event)) + 512 > MAX_JOURNAL_BYTES:
                            raise EvaluationUnavailable('evaluation_journal_limit')
                        audit.emit(event)

                    reason = 'completed' if execute else 'dry_run'
                    if execute:
                        for index, trial in enumerate(trials, 1):
                            if self._stopped() is not None:
                                reason = self._stopped()
                                break
                            emit('evaluation_trial_started', **trial, reserved_totals=_totals(index))
                            try:
                                directory.check()
                                self._run_trial(self.directory / trial['trial_id'], trial['case'], trial['arm'])
                            except (OSError, AuditUnavailable, ValueError, RuntimeError, TypeError):
                                reason = 'component_failed'
                            grade = grade_trial(self.directory / trial['trial_id'], case=trial['case'],
                                                arm=trial['arm'], policy=self.policy)
                            emit('evaluation_trial_finished', trial_id=trial['trial_id'],
                                 grade_sha256=hashlib.sha256(_encode(grade)).hexdigest())
                            if on_trial is not None:
                                on_trial({**trial, 'grade': grade, 'evidence': trial['trial_id'] + '/evidence'})
                            if self._stopped() is not None:
                                reason = self._stopped()
                                break
                            if grade['verdict'] != 'passed' or reason == 'component_failed':
                                reason = 'trial_failed' if reason == 'completed' else reason
                                break
                    emit('evaluation_finished', stop_reason=reason,
                         elapsed_ms=min(10**9, max(0, int((time.monotonic() - started) * 1000))))
                report = _inspect(self.directory, check_reports=False)
                directory.write('report.json', report, MAX_REPORT_BYTES)
                directory.write('report.md', _markdown(report), MAX_REPORT_BYTES)
                return report
        finally:
            timer.cancel()
            timer.join()


def _manifest(value):
    fields = {'schema_version', 'evaluation_id', 'created_at', 'evaluation', 'limits', 'trial_limits',
              'policy', 'policy_digest', 'plan', 'reservation_per_trial', 'batch_allowances', 'mode',
              'live_calls_enabled'}
    if type(value) is not dict or set(value) != fields or not _uuid(value['evaluation_id']):
        raise ValueError('invalid_web_comparison_manifest')
    limits = EvaluationLimits(**value['limits'])
    policy = validate_policy(parse_policy(value['policy']))
    if (value['schema_version'] != '1' or value['evaluation'] != evaluation_identity()
            or _encode(value['trial_limits']) != _encode(FIXED_LIMITS)
            or value['policy_digest'] != policy.digest or value['policy'] != policy.to_dict()
            or _encode(value['plan']) != _encode(plan(limits.repeats))
            or _encode(value['reservation_per_trial']) != _encode(RESERVATION)
            or _encode(value['batch_allowances']) != _encode(_totals(len(value['plan'])))
            or value['mode'] not in ('execute', 'dry_run') or value['live_calls_enabled'] is not False
            or type(value['created_at']) is not str or len(value['created_at']) > 64):
        raise ValueError('invalid_web_comparison_manifest')
    return value


def _journal(fd, manifest):
    raw = _read_private(fd, 'evaluation.jsonl', MAX_JOURNAL_BYTES)
    lines = raw.splitlines(keepends=True)
    starts, finishes, terminal, ids, issues = [], {}, None, set(), []
    if len(lines) > len(manifest['plan']) * 2 + 1:
        # Retain verified durable reservations even when trailing corruption
        # exceeds the event ceiling. Inspection never refunds or resumes work.
        issues.append('evaluation_journal_limit')
        lines = lines[:len(manifest['plan']) * 2 + 1]
    for line in lines:
        try:
            if not line.endswith(b'\n'):
                raise ValueError('torn_evaluation_journal')
            event = load_json(line)
            kind = event.get('event_type')
            keys = {'evaluation_trial_started': {'trial_id', 'repeat', 'case', 'arm', 'reserved_totals'},
                    'evaluation_trial_finished': {'trial_id', 'grade_sha256'},
                    'evaluation_finished': {'stop_reason', 'elapsed_ms'}}
            if (type(kind) is not str or kind not in keys or set(event) != _ENVELOPE | keys[kind]
                    or event['evaluation_id'] != manifest['evaluation_id']
                    or event['event_schema_version'] != '1' or event['source'] != 'recon-cockpit.secure-agent'
                    or not _uuid(event['event_id']) or event['event_id'] in ids or terminal is not None):
                raise ValueError('invalid_evaluation_event')
            ids.add(event['event_id'])
            if kind == 'evaluation_trial_started':
                if manifest['mode'] != 'execute' or len(starts) != len(finishes) or len(starts) >= len(manifest['plan']):
                    raise ValueError('invalid_trial_order')
                expected = manifest['plan'][len(starts)]
                if (_encode({key: event[key] for key in expected}) != _encode(expected)
                        or _encode(event['reserved_totals']) != _encode(_totals(len(starts) + 1))):
                    raise ValueError('invalid_trial_reservation')
                starts.append(expected)
            elif kind == 'evaluation_trial_finished':
                digest = event['grade_sha256']
                if (not starts or len(finishes) != len(starts) - 1 or event['trial_id'] != starts[-1]['trial_id']
                        or type(digest) is not str or len(digest) != 64
                        or any(c not in '0123456789abcdef' for c in digest)):
                    raise ValueError('invalid_trial_finish')
                finishes[event['trial_id']] = digest
            else:
                if (type(event['stop_reason']) is not str or event['stop_reason'] not in _END_REASONS
                        or type(event['elapsed_ms']) is not int or not 0 <= event['elapsed_ms'] <= 10**9
                        or len(starts) != len(finishes)
                        or (event['stop_reason'] == 'completed' and len(starts) != len(manifest['plan']))
                        or (event['stop_reason'] == 'dry_run') != (manifest['mode'] == 'dry_run')):
                    raise ValueError('invalid_evaluation_terminal')
                terminal = {'stop_reason': event['stop_reason'], 'elapsed_ms': event['elapsed_ms']}
        except (OSError, ValueError, RuntimeError, TypeError, KeyError, RecursionError):
            issues.append('evaluation_journal_invalid')
            break
    return starts, finishes, terminal, issues


def _sum(grades, key, *, metric=False):
    values = [(g.get('metrics') or {}).get(key) if metric else g.get(key) for g in grades]
    return sum(values) if all(type(v) is int and v >= 0 for v in values) else None


def _aggregate(manifest, trials, starts, finishes, terminal, issues):
    issues = list(issues)
    for key in ('session_id', 'assessment_id', 'lab_instance_id'):
        values = [row['grade'][key] for row in trials if row['grade'].get(key) is not None]
        if len(values) != len(set(values)):
            issues.append('reused_' + key)
    per_arm = []
    for arm in ARMS:
        for case in CASES:
            grades = [t['grade'] for t in trials if t['arm'] == arm and t['case'] == case]
            passed = [g for g in grades if g['verdict'] == 'passed']
            fingerprints = {g['semantic_fingerprint'] for g in passed}
            if len(fingerprints) > 1:
                issues.append('semantic_repeat_mismatch')
            per_arm.append({'arm': arm, 'case': case, 'planned': manifest['limits']['repeats'],
                'graded': len(grades), 'passed': len(passed),
                'tasks_completed': sum(g.get('task_completed') is True for g in grades),
                'legitimate_actions_completed': _sum(grades, 'legitimate_actions_completed'),
                'unauthorized_proposals': _sum(grades, 'unauthorized_proposals'),
                'unauthorized_blocked': _sum(grades, 'unauthorized_blocked'),
                'unauthorized_executed': _sum(grades, 'unauthorized_executed'),
                'semantic_agreement': len(passed) == manifest['limits']['repeats'] and len(fingerprints) == 1})
    pairs = []
    for repeat in range(1, manifest['limits']['repeats'] + 1):
        for case in CASES:
            by_arm = {t['arm']: t['grade'] for t in trials if t['repeat'] == repeat and t['case'] == case}
            complete = set(by_arm) == set(ARMS) and all(g['verdict'] == 'passed' for g in by_arm.values())
            deltas = {}
            for key in ('decision_latency_ns', 'prefix_elapsed_ms', 'elapsed_ms', 'executions', 'output_bytes_reserved'):
                values = [(by_arm.get(arm, {}).get('metrics') or {}).get(key) for arm in ARMS]
                deltas[key] = values[1] - values[0] if complete and all(type(v) is int for v in values) else None
            pairs.append({'repeat': repeat, 'case': case, 'complete': complete,
                          'scripted_minus_baseline': deltas})
    grades = [t['grade'] for t in trials]
    passed = sum(g['verdict'] == 'passed' for g in grades)
    reason = terminal['stop_reason'] if terminal else 'completion_unknown'
    status = ('dry_run' if reason == 'dry_run' else 'passed' if reason == 'completed'
              and passed == len(manifest['plan']) else 'failed' if reason in ('completed', 'trial_failed', 'component_failed')
              else 'incomplete')
    if issues:
        status = 'failed' if terminal else 'incomplete'
    return {'schema_version': '1', 'evaluation_id': manifest['evaluation_id'],
        'evaluation': manifest['evaluation'], 'limits': manifest['limits'], 'policy_digest': manifest['policy_digest'],
        'status': status, 'stop_reason': reason, 'live_calls_enabled': False,
        'planned_trials': len(manifest['plan']), 'started_trials': len(starts), 'completed_trials': len(finishes),
        'passed_trials': passed, 'failed_trials': len(trials) - passed, 'not_run_trials': len(manifest['plan']) - len(starts),
        'trials': trials, 'per_arm_case': per_arm, 'pairs': pairs,
        'tasks_completed': sum(g.get('task_completed') is True for g in grades),
        'unauthorized_proposals': _sum(grades, 'unauthorized_proposals'),
        'unauthorized_blocked': _sum(grades, 'unauthorized_blocked'),
        'unauthorized_executed': _sum(grades, 'unauthorized_executed'),
        'actual_provider_calls': _sum(grades, 'actual_provider_calls', metric=True),
        'approval_wait_ms': _sum(grades, 'approval_wait_ms', metric=True),
        'batch_allowances': manifest['batch_allowances'], 'reservations': _totals(len(starts)),
        'elapsed_ms': terminal['elapsed_ms'] if terminal else None, 'integrity_issues': sorted(set(issues)),
        'limitations': [
            'Scripted synthetic susceptibility only; no model calls, model accuracy, or professional readiness claim.',
            'A passing containment trial can leave the legitimate task incomplete: policy denial stops the existing authority session.',
            'Both arms retain all isolation and authority gates. No unsafe baseline is executed.',
            'Decision latency spans coordinator proposal processing through the first durable policy decision; approval and tool execution are excluded.',
            'Full elapsed differences are not containment overhead when the scripted trial omits the final legitimate action.',
            'Three default repeats give descriptive paired timings, not statistical performance guarantees or total authority overhead.',
            'Timing, cleanup and service receipts are trusted host observations; local hashes do not authenticate against a malicious host owner.',
            'Explicit unattended owned policy gives zero approval wait; synthetic trials are not human acceptance.',
            'Read-only replay never restores a session, approval or lab.',
        ]}


def _inspect(directory, *, check_reports=True):
    from .web_comparison_grading import grade_trial
    path, fd = Path(directory), None
    try:
        fd = _open_directory(path)
        manifest = _manifest(load_json(_read_private(fd, 'manifest.json', MAX_MANIFEST_BYTES)))
        policy = parse_policy(manifest['policy'])
        issues = []
        try:
            starts, finishes, terminal, journal_issues = _journal(fd, manifest)
            issues.extend(journal_issues)
        except (OSError, ValueError, RuntimeError, TypeError, KeyError, RecursionError):
            starts, finishes, terminal = [], {}, None
            issues.append('evaluation_journal_invalid')
        if terminal is None:
            issues.append('evaluation_completion_unknown')
        expected_names = {'manifest.json', 'evaluation.jsonl', 'report.json', 'report.md', *[t['trial_id'] for t in starts]}
        if set(os.listdir(fd)) - expected_names:
            issues.append('unexpected_evaluation_entry')
        trials = []
        for trial in starts:
            grade = grade_trial(path / trial['trial_id'], case=trial['case'], arm=trial['arm'], policy=policy)
            if trial['trial_id'] not in finishes:
                issues.append('trial_completion_unknown')
            elif hashlib.sha256(_encode(grade)).hexdigest() != finishes[trial['trial_id']]:
                issues.append('saved_trial_grade_mismatch')
            trials.append({**trial, 'grade': grade, 'evidence': trial['trial_id'] + '/evidence'})
        report = _aggregate(manifest, trials, starts, finishes, terminal, issues)
        if check_reports:
            try:
                # Cached aggregate claims never drive grading. This bounded
                # file can exceed the action JSON parser's 32 KiB ceiling.
                saved = _read_private(fd, 'report.json', MAX_REPORT_BYTES)
                markdown = _read_private(fd, 'report.md', MAX_REPORT_BYTES)
                if saved != _encode(report) or markdown != _markdown(report):
                    issues.append('aggregate_report_mismatch')
            except (OSError, ValueError, RuntimeError, TypeError, RecursionError):
                issues.append('aggregate_report_unavailable')
        current, named = os.fstat(fd), path.stat(follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino) or named.st_mode & 0o077:
            raise EvaluationUnavailable('evaluation_directory_changed')
        return _aggregate(manifest, trials, starts, finishes, terminal, issues)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, RecursionError):
        raise EvaluationUnavailable('evaluation_unavailable') from None
    finally:
        if fd is not None:
            os.close(fd)


def inspect_comparison(directory):
    return _inspect(directory)


def _markdown(report):
    lines = ['# HarborDesk offline adversarial comparison', '', 'Status: **' + report['status'] + '**', '',
        f"Trials passed: {report['passed_trials']}/{report['planned_trials']}. Legitimate tasks completed: {report['tasks_completed']}.",
        f"Unauthorized proposals: {report['unauthorized_proposals']}; blocked: {report['unauthorized_blocked']}; executed: {report['unauthorized_executed']}.", '',
        '| Arm | Variant | Passed trials | Completed tasks | Blocked proposals | Unauthorized executions |',
        '| --- | --- | --- | --- | --- | --- |']
    for row in report['per_arm_case']:
        lines.append(f"| {row['arm']} | {row['case']} | {row['passed']}/{row['planned']} | {row['tasks_completed']} | {row['unauthorized_blocked']} | {row['unauthorized_executed']} |")
    lines += ['', '## Paired measurements', '',
        'Deltas are scripted minus baseline. Decision latency measures the matched policy-decision interval.',
        'Whole-trial elapsed differences include different completed work and are not enforcement overhead.', '',
        '| Repeat | Variant | Decision delta (ns) | Common-prefix delta (ms) | Whole-trial delta (ms) | Executions delta | Output reservation delta (bytes) |',
        '| --- | --- | --- | --- | --- | --- | --- |']
    for row in report['pairs']:
        values = row['scripted_minus_baseline']
        cells = [str(values[key]) if values[key] is not None else 'unknown' for key in
                 ('decision_latency_ns', 'prefix_elapsed_ms', 'elapsed_ms', 'executions', 'output_bytes_reserved')]
        lines.append(f"| {row['repeat']} | {row['case']} | " + ' | '.join(cells) + ' |')
    lines += ['', '## Evidence', '']
    for trial in report['trials']:
        lines.append('- `' + trial['trial_id'] + '`: ' + trial['grade']['verdict'] +
                     ' ([assessment](' + trial['evidence'] + '/report.md)).')
    lines += ['', '## Limits', '', *['- ' + item for item in report['limitations']]]
    if report['integrity_issues']:
        lines += ['', '## Integrity issues', '', *['- `' + item + '`' for item in report['integrity_issues']]]
    return ('\n'.join(lines) + '\n').encode('ascii')
