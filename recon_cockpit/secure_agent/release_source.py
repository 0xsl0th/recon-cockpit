"""Deterministic, bounded snapshots of the reviewed repository source tree.

The explicit revision must be the clean checkout's full SHA-1 HEAD. Git is used
only for local object/index reads: no status filters, checkout, build, install,
hooks or fetch. Offline inspection never extracts or executes archive members.
The commit identity binds the archived tree; it does not authenticate its author
or establish which historical revision produced a supplied evaluation bundle.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import tarfile
import time


MAX_FILES = 1000
MAX_FILE_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_COMMIT_BYTES = 65536
_ROOT_FILES = frozenset({".gitignore", "README.md", "pyproject.toml", "recon.py", "uv.lock"})
_ROOT_DIRS = frozenset({".github", "docs", "examples", "recon_cockpit", "scripts", "tests"})
_PRIVATE_NAMES = frozenset({".git", ".secure-agent", ".aws", ".azure", ".ssh", ".gnupg", ".config",
    ".codex", ".agents", ".venv", "__pycache__", ".netrc", "credentials", "credentials.json",
    "secrets", "secrets.json", "id_rsa", "id_ed25519", "id_ecdsa"})
_PRIVATE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx", ".ovpn")
_METADATA_FIELDS = {"schema_version", "verification_revision", "verification_tree", "commit_object_base64",
                    "archive_sha256", "archive_bytes", "files"}
_FILE_FIELDS = {"path", "mode", "git_blob", "size", "sha256"}


class ReleaseSourceError(ValueError):
    """A fixed local error without Git output, paths or source contents."""


def _require(condition):
    if not condition:
        raise ReleaseSourceError("release_source_invalid")


def _hex(value, count):
    return type(value) is str and re.fullmatch("[a-f0-9]{" + str(count) + "}", value) is not None


def _path(value):
    _require(type(value) is str and 1 <= len(value) <= 240
             and re.fullmatch(r"[A-Za-z0-9_.\-/]+", value) is not None)
    parts = value.split("/")
    _require(1 <= len(parts) <= 32 and all(part not in {"", ".", ".."} and len(part) <= 100 for part in parts))
    _require(value in _ROOT_FILES or len(parts) > 1 and parts[0] in _ROOT_DIRS)
    _require(all(part.casefold() not in _PRIVATE_NAMES and part.casefold() != ".env"
                 and not part.casefold().startswith(".env.") for part in parts)
             and not value.casefold().endswith(_PRIVATE_SUFFIXES))
    return parts


def _object_id(kind, raw):
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def _tree(files):
    root = {}
    for entry in files:
        parts = _path(entry["path"])
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            _require(type(node) is dict)
        _require(parts[-1] not in node)
        node[parts[-1]] = (entry["mode"], entry["git_blob"])

    def digest(node):
        entries = []
        for name, child in node.items():
            directory = type(child) is dict
            mode, identity = ("40000", digest(child)) if directory else child
            entries.append((name.encode("ascii") + (b"/" if directory else b""),
                mode.encode("ascii") + b" " + name.encode("ascii") + b"\0" + bytes.fromhex(identity)))
        return _object_id("tree", b"".join(raw for _name, raw in sorted(entries)))

    return digest(root)


def _archive(files, contents):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:", format=tarfile.USTAR_FORMAT) as archive:
        for entry, raw in zip(files, contents):
            info = tarfile.TarInfo(entry["path"])
            info.type = tarfile.REGTYPE
            info.size = len(raw)
            info.mode = 0o755 if entry["mode"] == "100755" else 0o644
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(raw))
    raw = output.getvalue()
    _require(len(raw) <= MAX_ARCHIVE_BYTES)
    return raw


def _git(repository, args, maximum):
    """Bound both output and lifetime without exposing diagnostics or filters."""
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
               "-c", "core.attributesFile=" + os.devnull, "-c", "protocol.allow=never", "-C", str(repository), *args]
    environment = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                   "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_ATTR_NOSYSTEM": "1"}
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=environment, close_fds=True)
    output = bytearray()
    deadline = time.monotonic() + 10
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                _require(remaining > 0)
                if not selector.select(min(remaining, 0.1)):
                    continue
                part = os.read(process.stdout.fileno(), min(65536, maximum - len(output) + 1))
                if not part:
                    break
                output.extend(part)
                _require(len(output) <= maximum)
        _require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0)
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdout.close()


def _checkout(repository, revision):
    _require(_git(repository, ["rev-parse", "--is-inside-work-tree"], 16) == b"true\n")
    _require(_git(repository, ["rev-parse", "--verify", "HEAD"], 64) == revision.encode("ascii") + b"\n")
    top = _git(repository, ["rev-parse", "--show-toplevel"], 4096)
    _require(top.endswith(b"\n") and Path(os.fsdecode(top[:-1])).resolve() == repository)
    raw = _git(repository, ["ls-tree", "-rz", "--full-tree", revision], MAX_FILES * 320)
    _require(raw.endswith(b"\0"))
    entries = []
    for item in raw[:-1].split(b"\0"):
        header, path = item.split(b"\t", 1)
        mode, kind, identity = header.decode("ascii").split(" ")
        path = path.decode("ascii")
        _path(path)
        _require(mode in {"100644", "100755"} and kind == "blob" and _hex(identity, 40))
        entries.append({"path": path, "mode": mode, "git_blob": identity})
    _require(1 <= len(entries) <= MAX_FILES)
    entries.sort(key=lambda item: item["path"])
    _require(len({entry["path"] for entry in entries}) == len(entries))
    index = _git(repository, ["ls-files", "--stage", "-z"], MAX_FILES * 320)
    expected = b"".join(f"{entry['mode']} {entry['git_blob']} 0\t{entry['path']}\0".encode("ascii") for entry in entries)
    _require(index == expected)
    _require(_git(repository, ["ls-files", "--others", "--exclude-standard", "-z"], MAX_FILES * 320) == b"")
    return entries


def _working_file(root_fd, entry):
    parts = _path(entry["path"])
    opened = []
    parent = root_fd
    try:
        for part in parts[:-1]:
            parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            opened.append(parent)
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        opened.append(fd)
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE_BYTES
                 and bool(before.st_mode & 0o111) == (entry["mode"] == "100755"))
        raw = bytearray()
        while True:
            part = os.read(fd, min(65536, MAX_FILE_BYTES - len(raw) + 1))
            if not part:
                break
            raw.extend(part)
            _require(len(raw) <= MAX_FILE_BYTES)
        after = os.fstat(fd)
        _require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                 and len(raw) == before.st_size and _object_id("blob", raw) == entry["git_blob"])
        return bytes(raw)
    finally:
        for fd in reversed(opened):
            os.close(fd)


def build_source_archive(repository, revision):
    """Return canonical archive bytes and independently replayable Git identity."""
    root_fd = None
    try:
        _require(_hex(revision, 40))
        path = Path(repository).resolve(strict=True)
        root_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
        entries = _checkout(path, revision)
        commit = _git(path, ["cat-file", "commit", revision], MAX_COMMIT_BYTES)
        _require(_object_id("commit", commit) == revision)
        first = commit.split(b"\n", 1)[0]
        _require(first.startswith(b"tree ") and _hex(first[5:].decode("ascii"), 40))
        tree = first[5:].decode("ascii")
        _require(_tree(entries) == tree)
        files, contents = [], []
        total = 0
        for entry in entries:
            raw = _working_file(root_fd, entry)
            # Matching its Git blob ID binds these bytes without invoking any
            # working-tree filters or opening a separate unbounded blob reader.
            total += len(raw)
            _require(total <= MAX_ARCHIVE_BYTES)
            files.append({**entry, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            contents.append(raw)
        archive = _archive(files, contents)
        _require(_checkout(path, revision) == entries)
        for entry, raw in zip(entries, contents):
            _require(_working_file(root_fd, entry) == raw)
        metadata = {"schema_version": "1", "verification_revision": revision, "verification_tree": tree,
                    "commit_object_base64": base64.b64encode(commit).decode("ascii"),
                    "archive_sha256": hashlib.sha256(archive).hexdigest(), "archive_bytes": len(archive), "files": files}
        inspect_source_archive(archive, metadata)
        return archive, metadata
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError,
            subprocess.SubprocessError, tarfile.TarError, RecursionError):
        raise ReleaseSourceError("release_source_unavailable") from None
    finally:
        if root_fd is not None:
            os.close(root_fd)


def inspect_source_archive(archive_bytes, metadata):
    """Check closed schemas, canonical tar bytes, blobs, tree and commit offline."""
    try:
        _require(type(archive_bytes) is bytes and 0 < len(archive_bytes) <= MAX_ARCHIVE_BYTES
                 and type(metadata) is dict and set(metadata) == _METADATA_FIELDS
                 and metadata["schema_version"] == "1" and _hex(metadata["verification_revision"], 40)
                 and _hex(metadata["verification_tree"], 40) and _hex(metadata["archive_sha256"], 64)
                 and type(metadata["archive_bytes"]) is int and metadata["archive_bytes"] == len(archive_bytes)
                 and hashlib.sha256(archive_bytes).hexdigest() == metadata["archive_sha256"])
        encoded = metadata["commit_object_base64"]
        _require(type(encoded) is str and 0 < len(encoded) <= 4 * ((MAX_COMMIT_BYTES + 2) // 3))
        commit = base64.b64decode(encoded, validate=True)
        _require(0 < len(commit) <= MAX_COMMIT_BYTES and base64.b64encode(commit).decode("ascii") == encoded
                 and _object_id("commit", commit) == metadata["verification_revision"]
                 and commit.split(b"\n", 1)[0] == b"tree " + metadata["verification_tree"].encode("ascii"))
        files = metadata["files"]
        _require(type(files) is list and 1 <= len(files) <= MAX_FILES)
        previous = ""
        total = 0
        for entry in files:
            _require(type(entry) is dict and set(entry) == _FILE_FIELDS)
            _path(entry["path"])
            _require(entry["path"] > previous and type(entry["mode"]) is str
                     and entry["mode"] in {"100644", "100755"} and _hex(entry["git_blob"], 40)
                     and type(entry["size"]) is int and 0 <= entry["size"] <= MAX_FILE_BYTES
                     and _hex(entry["sha256"], 64))
            total += entry["size"]
            _require(total <= MAX_ARCHIVE_BYTES)
            previous = entry["path"]
        _require(_tree(files) == metadata["verification_tree"])
        contents = []
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
            for index, member in enumerate(archive):
                _require(index < len(files))
                entry = files[index]
                _require(member.type == tarfile.REGTYPE and member.sparse is None
                         and member.name == entry["path"] and member.size == entry["size"])
                stream = archive.extractfile(member)
                _require(stream is not None)
                with stream:
                    raw = stream.read(MAX_FILE_BYTES + 1)
                _require(len(raw) == entry["size"] and hashlib.sha256(raw).hexdigest() == entry["sha256"]
                         and _object_id("blob", raw) == entry["git_blob"])
                contents.append(raw)
        _require(len(contents) == len(files) and _archive(files, contents) == archive_bytes)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError,
            tarfile.TarError, RecursionError):
        raise ReleaseSourceError("release_source_invalid") from None
