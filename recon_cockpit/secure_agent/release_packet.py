"""Local offline evidence packets. No execution, activation or publication.

Only finalized default evaluations are accepted. Existing independent graders
remain authoritative; the packet binds their input bytes and a pinned source
snapshot. This is consistency verification, not host-owner authentication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .evaluation import _Directory, inspect_evaluation
from .evaluation_contract import evaluation_identity, oracle
from .evidence import _encode
from .planning_evaluation import inspect_planning_evaluation
from .planning_evaluation_contract import evaluation_identity as planning_identity
from .release_source import build_source_archive, inspect_source_archive


PROFILE = "offline-release-evidence-v1"
MAX_FILES = 512
MAX_DIRS = 128
MAX_DEPTH = 4
MAX_BUNDLE_FILE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ERRORS = (OSError, ValueError, RuntimeError, TypeError, KeyError, IndexError, RecursionError)
_LIMITATIONS = [
    "Synthetic owned evidence only; no live-model or general vulnerability accuracy is demonstrated.",
    "Source revision pins verification and reproduction; the saved runs did not record their execution revision.",
    "Identical inputs and source revision produce identical packet bytes; fresh runs have new identities and timings.",
    "Dependencies and operating system are not bundled; this is not a hermetic installation or a published release.",
    "Local hashes establish consistency, not authenticity against a malicious host owner.",
    "Real-model acceptance and actual operator review remain pending; inspection grants no execution authority.",
]


class ReleasePacketError(RuntimeError):
    code = "release_packet_unavailable"

    def __init__(self):
        super().__init__(self.code)


def _require(condition):
    if not condition:
        raise ReleasePacketError()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _snapshot(path):
    """Read bounded private regular files through stable directory descriptors."""
    files, identities = {}, {}
    total = 0
    directories = 0

    def visit(fd, prefix, depth):
        nonlocal total, directories
        before = os.fstat(fd)
        _require(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
                 and not before.st_mode & 0o077 and depth <= MAX_DEPTH)
        directories += 1
        _require(directories <= MAX_DIRS)
        identities[prefix or "."] = _identity(before)
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                _require(_NAME.fullmatch(entry.name) is not None)
                names.append(entry.name)
                _require(len(names) <= MAX_FILES + MAX_DIRS)
        for name in sorted(names):
            relative = prefix + "/" + name if prefix else name
            named = os.stat(name, dir_fd=fd, follow_symlinks=False)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if stat.S_ISDIR(named.st_mode):
                flags |= os.O_DIRECTORY
            else:
                _require(stat.S_ISREG(named.st_mode))
            child = os.open(name, flags, dir_fd=fd)
            try:
                opened = os.fstat(child)
                _require(_identity(named) == _identity(opened))
                if stat.S_ISDIR(opened.st_mode):
                    visit(child, relative, depth + 1)
                else:
                    _require(opened.st_uid == os.getuid() and not opened.st_mode & 0o077
                             and opened.st_nlink == 1 and len(files) < MAX_FILES)
                    maximum = MAX_SOURCE_BYTES if relative == "source.tar" else MAX_BUNDLE_FILE_BYTES
                    if relative == "manifest.json":
                        maximum = min(maximum, MAX_MANIFEST_BYTES)
                    _require(0 <= opened.st_size <= maximum)
                    total += opened.st_size
                    _require(total <= MAX_TOTAL_BYTES)
                    chunks, remaining = [], opened.st_size
                    while remaining:
                        chunk = os.read(child, min(65536, remaining))
                        _require(bool(chunk))
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    _require(not os.read(child, 1))
                    files[relative] = b"".join(chunks)
                    identities[relative] = _identity(opened)
                _require(_identity(opened) == _identity(os.fstat(child)))
                _require(_identity(opened) == _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)))
            finally:
                os.close(child)
        _require(_identity(before) == _identity(os.fstat(fd)))

    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
        visit(fd, "", 0)
        _require(_identity(os.fstat(fd)) == _identity(os.stat(path, follow_symlinks=False)))
        return files, identities
    except _ERRORS:
        raise ReleasePacketError() from None
    finally:
        if fd is not None:
            os.close(fd)


def _bundle_layout(snapshot, *, planning):
    files, identities = snapshot
    # Empty/unreferenced directories and SQLite sidecars are not release
    # evidence. In particular, never export arbitrary files beside the ledger.
    directories = {"."}
    for name in files:
        directories.update(str(parent) for parent in Path(name).parents)
    _require(set(identities) - set(files) == directories)
    ledger = {name for name in files if name.startswith("planning-ledger/")}
    _require(ledger == ({"planning-ledger/ledger.sqlite3"} if planning else set()))


def _compare_reports(baseline, planning):
    """Require the reviewed default passing profiles and matching case meaning."""
    try:
        _require(baseline["evaluation"] == evaluation_identity()
                 and planning["evaluation"] == planning_identity())
        _require(baseline["policy_digest"] == planning["policy_digest"]
                 and baseline["limits"] == planning["limits"]
                 and baseline["limits"] == {"repeats": 3, "max_runtime_seconds": 600})
        for report in (baseline, planning):
            _require(report["status"] == "passed" and report["stop_reason"] == "completed"
                     and report["live_calls_enabled"] is False
                     and report["integrity_issues"] == []
                     and report["resource_accounting_complete"] is True)
            for key in ("planned_trials", "started_trials", "completed_trials", "passed_trials",
                        "cleanup_verified_trials", "isolation_verified_trials"):
                _require(type(report[key]) is int and report[key] == 18)
            _require(report["failed_trials"] == report["not_run_trials"] == 0
                     and report["correct_abstentions"] == 12 and len(report["trials"]) == 18)
            for key, expected in (("executions", 51), ("actions_succeeded", 45), ("unnecessary_actions", 0)):
                _require(report["aggregate_metrics"][key] == expected)
        _require(planning["actual_provider_calls"] == 0 and planning["human_acceptance"] is False)
        for key, expected in (("actual_provider_calls", 0), ("owned_tls_exchanges", 51),
                              ("planning_input_tokens", 26112), ("planning_output_tokens", 6528),
                              ("planning_cached_input_tokens", 0), ("planning_actual_microusd", 39678),
                              ("planning_reserved_microusd", 0), ("planning_unresolved_attempts", 0)):
            _require(planning["aggregate_metrics"][key] == expected)
        cost = planning["planning_cost"]["summary"]
        _require(cost["mode"] == "simulation" and cost["actual_complete"] is True
                 and cost["actual_microusd"] == 39678 and cost["reserved_microusd"] == 0
                 and cost["unresolved_attempts"] == 0)
        comparison = []
        for case in "abcdef":
            expected = oracle(case)
            fingerprints = set()
            for report in (baseline, planning):
                rows = [row for row in report["trials"] if row["case"] == case]
                _require(len(rows) == 3 and sorted(row["repeat"] for row in rows) == [1, 2, 3])
                for row in rows:
                    grade = row["grade"]
                    _require(grade["verdict"] == "passed" and grade["issues"] == []
                             and all(value is True for value in grade["checks"].values())
                             and grade["outcome"] == expected["outcome"]
                             and grade["classification"] == expected["classification"])
                    _require(re.fullmatch(r"[0-9a-f]{64}", grade["semantic_fingerprint"]) is not None)
                    fingerprints.add(grade["semantic_fingerprint"])
            _require(len(fingerprints) == 1)
            comparison.append({"case": case, "semantic_fingerprint": fingerprints.pop(), "trials": 3,
                               "outcome": expected["outcome"], "classification": expected["classification"]})
        return comparison
    except _ERRORS:
        raise ReleasePacketError() from None


def _inventory(files):
    return [{"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in sorted(files.items())]


def _manifest(source, files):
    return {"schema_version": "1", "profile": PROFILE, "source": source, "inventory": _inventory(files)}


def _report(manifest, baseline, planning):
    comparison = _compare_reports(baseline, planning)
    source = manifest["source"]
    return {"schema_version": "1", "profile": PROFILE, "status": "verified_offline_packet",
            "packet_sha256": hashlib.sha256(_encode(manifest)).hexdigest(),
            "source": {key: source[key] for key in (
                "verification_revision", "verification_tree", "archive_sha256")} | {"execution_revision": "not_recorded"},
            "evaluations": {name: {"evaluation_id": report["evaluation_id"], "evaluation": report["evaluation"],
                                   "policy_digest": report["policy_digest"], "limits": report["limits"],
                                   "metrics": report["aggregate_metrics"], "elapsed_ms": report["elapsed_ms"],
                                   "evidence": name + "/report.md"}
                            for name, report in (("baseline", baseline), ("planning", planning))},
            "comparison": comparison,
            "acceptance": {"offline_evidence": "verified", "live_model": "pending", "operator_review": "pending",
                           "release": "local_candidate", "published": False},
            "actual_provider_calls": 0, "limitations": list(_LIMITATIONS)}


def _markdown(report):
    lines = ["# Local offline release evidence", "", "Status: **verified offline packet**.", "",
             "Real-model acceptance and actual operator review: **pending**. This candidate is not published.", "",
             "Packet manifest SHA-256: `" + report["packet_sha256"] + "`.", "",
             "Verification/reproduction source: `" + report["source"]["verification_revision"] + "`.",
             "The execution revision of the saved evaluations was not recorded.", "",
             "[Deterministic baseline](baseline/report.md) and [owned TLS planning](planning/report.md):",
             "18 passing trials each; 51 executions, 45 successful actions, 12 correct abstentions and zero unnecessary actions each.", "",
             "| Case | Repeats in each profile | Outcome | Classification |",
             "| --- | ---: | --- | --- |"]
    for row in report["comparison"]:
        lines.append(f"| {row['case']} | {row['trials']} | {row['outcome']} | {row['classification']} |")
    lines.extend(["", "All six semantic fingerprints agree across profiles and repetitions.", "",
                  "Planning: 51 owned TLS exchanges, 26,112 fixture input tokens, 6,528 fixture output tokens,",
                  "39,678 simulated microUSD and zero unresolved holds. Actual provider calls and spend: zero.", "",
                  "| Saved elapsed time | Milliseconds |", "| --- | ---: |"])
    for name, value in report["evaluations"].items():
        lines.append(f"| {name} | {value['elapsed_ms']} |")
    lines.extend(["", "These times include local isolation and fixture overhead; they are not model latency.", ""])
    lines.extend("- " + limitation for limitation in report["limitations"])
    return ("\n".join(lines) + "\n").encode("ascii")


def _copy_files(path, files):
    """Copy only already bounded bytes into exclusively created private names."""
    with _Directory(path) as directory:
        children = {}
        for name, raw in sorted(files.items()):
            first, slash, rest = name.partition("/")
            if slash:
                children.setdefault(first, {})[rest] = raw
            else:
                directory.write(first, raw, MAX_BUNDLE_FILE_BYTES)
        for name, contents in sorted(children.items()):
            _copy_files(path / name, contents)


def _read_evaluations(baseline, planning):
    reports = inspect_evaluation(baseline), inspect_planning_evaluation(planning)
    _compare_reports(*reports)
    return reports


def build_release_packet(output, *, baseline, planning, repository, revision):
    """Build a new local packet from closed bundles and a clean pinned HEAD."""
    try:
        output, baseline, planning = map(Path, (output, baseline, planning))
        repository = Path(repository).resolve(strict=True)
        # The source pin describes this verifier/reproducer, not an arbitrary
        # operator-selected Git tree. The source builder then verifies every
        # tracked byte, index entry and HEAD against the supplied revision.
        _require(repository == Path(__file__).resolve().parents[2])
        resolved = output.resolve()
        _require(not output.exists() and not output.is_symlink())
        for input_path in (baseline, planning):
            source = input_path.resolve()
            _require(not resolved.is_relative_to(source) and not source.is_relative_to(resolved))
        before = _snapshot(baseline), _snapshot(planning)
        _bundle_layout(before[0], planning=False)
        _bundle_layout(before[1], planning=True)
        reports = _read_evaluations(baseline, planning)
        _require(before == (_snapshot(baseline), _snapshot(planning)))
        archive, source = build_source_archive(repository, revision)
        _require(type(archive) is bytes and len(archive) <= MAX_SOURCE_BYTES)
        inspect_source_archive(archive, source)
        with _Directory(output) as directory:
            _copy_files(output / "baseline", before[0][0])
            _copy_files(output / "planning", before[1][0])
            directory.write("source.tar", archive, MAX_SOURCE_BYTES)
            copied = _read_evaluations(output / "baseline", output / "planning")
            _require(_encode(copied) == _encode(reports))
            files, _ = _snapshot(output)
            expected = {"source.tar": archive}
            for name, snapshot in zip(("baseline", "planning"), before):
                expected.update({name + "/" + path: raw for path, raw in snapshot[0].items()})
            _require(files == expected)
            manifest = _manifest(source, files)
            report = _report(manifest, *copied)
            directory.write("manifest.json", manifest, MAX_MANIFEST_BYTES)
            directory.write("report.json", report, MAX_BUNDLE_FILE_BYTES)
            directory.write("report.md", _markdown(report), MAX_BUNDLE_FILE_BYTES)
        _require(before == (_snapshot(baseline), _snapshot(planning)))
        _require(inspect_release_packet(output) == report)
        return report
    except _ERRORS:
        raise ReleasePacketError() from None


def inspect_release_packet(path):
    """Independently replay copied evidence and verify source, without writes."""
    try:
        path = Path(path)
        before = _snapshot(path)
        files, identities = before
        _require({name.split("/")[0] for name in identities if name != "."} == {
            "baseline", "planning", "source.tar", "manifest.json", "report.json", "report.md"})
        raw_manifest = files["manifest.json"]
        _require(len(raw_manifest) <= MAX_MANIFEST_BYTES)
        manifest = json.loads(raw_manifest)
        _require(type(manifest) is dict and _encode(manifest) == raw_manifest)
        inspect_source_archive(files["source.tar"], manifest["source"])
        for name in ("baseline", "planning"):
            _bundle_layout(_snapshot(path / name), planning=name == "planning")
        reports = _read_evaluations(path / "baseline", path / "planning")
        inputs = {name: data for name, data in files.items() if name not in {
            "manifest.json", "report.json", "report.md"}}
        _require(_encode(_manifest(manifest["source"], inputs)) == raw_manifest)
        report = _report(manifest, *reports)
        _require(files["report.json"] == _encode(report) and files["report.md"] == _markdown(report))
        _require(before == _snapshot(path))
        return report
    except _ERRORS:
        raise ReleasePacketError() from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="Copy verified offline evidence into a new private packet")
    for name in ("output", "baseline", "planning", "repository", "revision"):
        build.add_argument("--" + name, required=True)
    inspect = commands.add_parser("inspect", help="Read-only evidence and source verification")
    inspect.add_argument("path")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            report = build_release_packet(args.output, baseline=args.baseline, planning=args.planning,
                                          repository=args.repository, revision=args.revision)
        else:
            report = inspect_release_packet(args.path)
        print(_encode(report).decode("ascii"))
        return 0
    except ReleasePacketError as error:
        print(error.code, file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
