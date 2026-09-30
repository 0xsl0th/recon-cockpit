"""Real local Git fixtures and hostile archives; no network or extraction."""

import base64
from copy import deepcopy
import hashlib
import io
import os
from pathlib import Path
import shlex
import subprocess
import tarfile

import pytest

from recon_cockpit.secure_agent import release_source as source


def git(repository, *arguments):
    environment = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_AUTHOR_DATE": "2026-09-30T00:00:00+00:00", "GIT_COMMITTER_DATE": "2026-09-30T00:00:00+00:00"}
    command = ["git", "-C", str(repository), "-c", "user.name=Source Fixture", "-c",
               "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
               "-c", "core.hooksPath=" + os.devnull, *arguments]
    return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env=environment).stdout


def commit(repository):
    git(repository, "add", "--all")
    git(repository, "commit", "-m", "Owned source fixture")
    return git(repository, "rev-parse", "HEAD").decode().strip()


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    git(root, "init", "--object-format=sha1")
    (root / ".gitignore").write_text(".env\n.secure-agent/\n.venv/\n")
    (root / "README.md").write_text("Owned offline source fixture.\n")
    (root / "recon_cockpit").mkdir()
    (root / "recon_cockpit" / "demo.py").write_text("raise RuntimeError('SOURCE MUST NEVER EXECUTE')\n")
    (root / "scripts").mkdir()
    executable = root / "scripts" / "demo.py"
    executable.write_text("#!/usr/bin/env python3\nraise RuntimeError('SOURCE MUST NEVER EXECUTE')\n")
    executable.chmod(0o755)
    # Git sorts trees as though directory names end in '/', which differs
    # from ordinary component sorting around punctuation-prefixed siblings.
    (root / "tests").mkdir()
    (root / "tests" / "a").mkdir()
    (root / "tests" / "a" / "child.py").write_bytes(b"nested\0fixture\xff")
    (root / "tests" / "a.py").write_text("fixture\n")
    revision = commit(root)
    return root, revision


def snapshot(root):
    return {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
            for path in root.rglob("*") if path.is_file()}


def test_build_is_deterministic_readonly_and_binds_real_git_objects(repository, monkeypatch):
    root, revision = repository
    before = snapshot(root)
    first, metadata = source.build_source_archive(root, revision)
    assert snapshot(root) == before
    second, again = source.build_source_archive(root, revision)
    assert first == second and metadata == again and snapshot(root) == before
    assert metadata["verification_revision"] == revision
    assert metadata["verification_tree"] == git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    assert base64.b64decode(metadata["commit_object_base64"]) == git(root, "cat-file", "commit", revision)
    assert metadata["archive_bytes"] == len(first)
    assert metadata["archive_sha256"] == hashlib.sha256(first).hexdigest()
    assert [entry["path"] for entry in metadata["files"]] == sorted(entry["path"] for entry in metadata["files"])
    for entry in metadata["files"]:
        assert entry["git_blob"] == git(root, "rev-parse", "HEAD:" + entry["path"]).decode().strip()
        assert entry["sha256"] == hashlib.sha256((root / entry["path"]).read_bytes()).hexdigest()
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:") as archive:
        members = archive.getmembers()
        assert len(members) == len(metadata["files"])
        assert all(member.isfile() and member.uid == member.gid == member.mtime == 0
                   and member.uname == member.gname == "" for member in members)
        assert archive.getmember("scripts/demo.py").mode == 0o755
        assert archive.getmember("README.md").mode == 0o644
    monkeypatch.setattr(subprocess, "Popen", lambda *_a, **_k: pytest.fail("offline inspection invoked a process"))
    monkeypatch.setattr(tarfile.TarFile, "extract", lambda *_a, **_k: pytest.fail("archive extracted"))
    monkeypatch.setattr(tarfile.TarFile, "extractall", lambda *_a, **_k: pytest.fail("archive extracted"))
    assert source.inspect_source_archive(first, metadata) is None
    assert snapshot(root) == before


def test_ignored_private_files_never_enter_archive(repository):
    root, revision = repository
    (root / ".env").write_text("PRIVATE-CREDENTIAL-CANARY")
    (root / ".secure-agent").mkdir()
    (root / ".secure-agent" / "audit.jsonl").write_text("PRIVATE-EVIDENCE-CANARY")
    archive, metadata = source.build_source_archive(root, revision)
    assert b"PRIVATE-CREDENTIAL" not in archive and b"PRIVATE-EVIDENCE" not in archive
    assert not any(entry["path"].startswith((".env", ".secure-agent")) for entry in metadata["files"])


@pytest.mark.parametrize("revision", ["HEAD", "main", "a" * 7, "A" * 40, "0" * 39, "0" * 41, "--help", None, True])
def test_only_explicit_full_lowercase_revision_is_accepted_before_git(monkeypatch, revision):
    monkeypatch.setattr(source, "_git", lambda *_a, **_k: pytest.fail("Git accessed for invalid revision"))
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive("PRIVATE-REPOSITORY", revision)


def test_valid_old_revision_cannot_replace_current_head(repository):
    root, revision = repository
    (root / "README.md").write_text("new owned fixture")
    commit(root)
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive(root, revision)


@pytest.mark.parametrize("change", ["unstaged", "staged", "untracked", "deleted", "mode", "symlink", "directory_symlink"])
def test_dirty_index_worktree_and_links_never_produce_source_archive(repository, change):
    root, revision = repository
    target = root / "recon_cockpit" / "demo.py"
    if change in {"unstaged", "staged"}:
        target.write_text("PRIVATE CHANGE")
        if change == "staged":
            git(root, "add", "--all")
    elif change == "untracked":
        (root / "README-untracked.md").write_text("PRIVATE")
    elif change == "deleted":
        target.unlink()
    elif change == "mode":
        target.chmod(0o755)
    elif change == "symlink":
        target.unlink()
        target.symlink_to(root / "README.md")
    else:
        destination = root.parent / "outside"
        target.parent.rename(destination)
        (root / "recon_cockpit").symlink_to(destination, target_is_directory=True)
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive(root, revision)


@pytest.mark.parametrize("path", [".env", ".aws/config", ".ssh/id_ed25519", ".secure-agent/audit.jsonl",
    "examples/.env.local", "examples/provider.key", "tests/credentials/key.json", "docs/secrets.json", "build/output.py"])
def test_tracked_private_roots_and_unreviewed_paths_are_refused(repository, path):
    root, _revision = repository
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("PRIVATE MUST NOT EXPORT")
    git(root, "add", "--force", "--", path)
    git(root, "commit", "-m", "Rejected path fixture")
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive(root, revision)


@pytest.mark.parametrize("kind", ["symlink", "submodule"])
def test_git_symlink_and_submodule_modes_are_refused(repository, kind):
    root, revision = repository
    if kind == "symlink":
        target = root / "tests" / "link.py"
        target.symlink_to(root / "README.md")
        revision = commit(root)
    else:
        git(root, "update-index", "--add", "--cacheinfo", "160000," + revision + ",tests/vendor")
        git(root, "commit", "-m", "Rejected submodule fixture")
        revision = git(root, "rev-parse", "HEAD").decode().strip()
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive(root, revision)


def test_git_filters_and_inherited_process_configuration_never_run(repository, monkeypatch):
    root, revision = repository
    marker = root.parent / "executed"
    command = "printf PRIVATE > " + shlex.quote(str(marker))
    git(root, "config", "core.fsmonitor", command)
    git(root, "config", "filter.fixture.clean", command)
    (root / ".git" / "info" / "attributes").write_text("*.py filter=fixture\n")
    monkeypatch.setenv("GIT_DIR", str(root.parent / "does-not-exist"))
    monkeypatch.setenv("GIT_WORK_TREE", "/")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", command)
    monkeypatch.setenv("GIT_SSH_COMMAND", command)
    raw, metadata = source.build_source_archive(root, revision)
    source.inspect_source_archive(raw, metadata)
    assert not marker.exists()


@pytest.mark.parametrize("limit", ["files", "file_bytes", "archive_bytes"])
def test_source_bounds_are_enforced_before_release(repository, limit):
    root, _revision = repository
    directory = root / "tests" / "bounded"
    directory.mkdir()
    if limit == "files":
        for number in range(source.MAX_FILES):
            (directory / f"file-{number:04d}.py").write_bytes(b"x")
    elif limit == "file_bytes":
        (directory / "huge.py").write_bytes(b"x" * (source.MAX_FILE_BYTES + 1))
    else:
        for number in range(17):
            (directory / f"large-{number}.py").write_bytes(b"x" * source.MAX_FILE_BYTES)
    revision = commit(root)
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive(root, revision)


def test_final_checkout_recheck_detects_changes_during_snapshot(repository, monkeypatch):
    root, revision = repository
    original = source._archive

    def change(files, contents):
        raw = original(files, contents)
        (root / "README.md").write_text("concurrent change")
        return raw

    monkeypatch.setattr(source, "_archive", change)
    with pytest.raises(source.ReleaseSourceError, match="^release_source_unavailable$"):
        source.build_source_archive(root, revision)


def test_every_metadata_field_is_required_and_unknown_fields_are_rejected(repository):
    raw, original = source.build_source_archive(*repository)
    for child in (False, True):
        fields = original["files"][0] if child else original
        for field in (*fields, "unknown"):
            changed = deepcopy(original)
            target = changed["files"][0] if child else changed
            if field == "unknown":
                target[field] = "PRIVATE"
            else:
                del target[field]
            with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
                source.inspect_source_archive(raw, changed)


@pytest.mark.parametrize("field,value", [("schema_version", 1), ("verification_revision", "0" * 40),
    ("verification_tree", "0" * 40), ("commit_object_base64", "!!!!"),
    ("commit_object_base64", base64.b64encode(b"tree " + b"0" * 40 + b"\n").decode()),
    ("archive_sha256", "0" * 64), ("archive_bytes", True), ("files", []),
    ("files", [{}] * (source.MAX_FILES + 1))])
def test_invalid_metadata_cannot_supply_missing_source_identity(repository, field, value):
    raw, metadata = source.build_source_archive(*repository)
    metadata[field] = value
    with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
        source.inspect_source_archive(raw, metadata)


@pytest.mark.parametrize("field,value", [("path", "../escape.py"), ("path", "/absolute.py"),
    ("path", "tests//double.py"), ("path", "tests/./dot.py"), ("path", "tests/../escape.py"),
    ("path", "tests/back\\slash.py"), ("path", "tests/.env"), ("path", ".git/config"),
    ("path", "tests/" + "x" * 101), ("mode", "120000"), ("mode", "160000"),
    ("size", True), ("size", -1), ("size", source.MAX_FILE_BYTES + 1),
    ("git_blob", "0" * 40), ("sha256", "0" * 64)])
def test_file_descriptors_reject_paths_modes_sizes_and_content_substitution(repository, field, value):
    raw, metadata = source.build_source_archive(*repository)
    metadata["files"][0][field] = value
    with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
        source.inspect_source_archive(raw, metadata)


def changed_archive(raw, transform, *, tar_format=tarfile.USTAR_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as original:
        members = [(member, original.extractfile(member).read()) for member in original]
    members = transform(members)
    with tarfile.open(fileobj=output, mode="w:", format=tar_format) as target:
        for member, content in members:
            target.addfile(member, io.BytesIO(content) if member.isfile() else None)
    return output.getvalue()


@pytest.mark.parametrize("fault", ["uid", "gid", "mtime", "uname", "mode", "symlink", "hardlink", "directory",
    "duplicate", "reverse", "missing", "gnu", "pax", "trailing", "content"])
def test_noncanonical_or_unsafe_tar_is_rejected_even_with_updated_archive_hash(repository, fault):
    raw, metadata = source.build_source_archive(*repository)

    def transform(members):
        member = members[0][0]
        if fault in {"uid", "gid", "mtime", "mode"}:
            setattr(member, fault, 1)
        elif fault == "uname":
            member.uname = "PRIVATE"
        elif fault in {"symlink", "hardlink", "directory"}:
            member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "directory": tarfile.DIRTYPE}[fault]
            member.linkname = "../../PRIVATE"
            member.size = 0
        elif fault == "duplicate":
            members.append(deepcopy(members[0]))
        elif fault == "reverse":
            members.reverse()
        elif fault == "missing":
            members.pop()
        elif fault == "pax":
            member.pax_headers = {"comment": "PRIVATE"}
        elif fault == "content":
            members[0] = (member, b"x" * member.size)
        return members

    raw = changed_archive(raw, transform, tar_format={"gnu": tarfile.GNU_FORMAT,
                          "pax": tarfile.PAX_FORMAT}.get(fault, tarfile.USTAR_FORMAT))
    if fault == "trailing":
        raw += b"\0" * 512
    metadata["archive_bytes"] = len(raw)
    metadata["archive_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
        source.inspect_source_archive(raw, metadata)


def test_rehashing_changed_files_does_not_rebind_original_git_tree_and_commit(repository):
    raw, metadata = source.build_source_archive(*repository)

    def transform(members):
        member, _ = members[0]
        content = b"x" * member.size
        members[0] = (member, content)
        metadata["files"][0]["sha256"] = hashlib.sha256(content).hexdigest()
        metadata["files"][0]["git_blob"] = source._object_id("blob", content)
        return members

    raw = changed_archive(raw, transform)
    metadata["archive_bytes"] = len(raw)
    metadata["archive_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
        source.inspect_source_archive(raw, metadata)
    metadata["verification_tree"] = source._tree(metadata["files"])
    with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
        source.inspect_source_archive(raw, metadata)


@pytest.mark.parametrize("raw", [b"", b"invalid", "not-bytes", bytearray(b"invalid"), b"x" * (source.MAX_ARCHIVE_BYTES + 1)])
def test_invalid_or_oversized_archive_input_is_a_safe_local_error(raw):
    with pytest.raises(source.ReleaseSourceError, match="^release_source_invalid$"):
        source.inspect_source_archive(raw, {})
