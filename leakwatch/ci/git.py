"""Thin git helpers for CI: which files/lines changed, and what was added in a commit range."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path


class GitError(Exception):
    pass


def _git(repo: Path, *args: str, timeout: int = 300) -> str:
    if not shutil.which("git"):
        raise GitError("git not installed")
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                       errors="ignore", timeout=timeout)
    if p.returncode != 0:
        raise GitError(p.stderr.strip() or f"git {' '.join(args)} failed")
    return p.stdout


def is_repo(repo: Path) -> bool:
    try:
        return _git(repo, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitError:
        return False


def head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").strip()


def ensure_ref(repo: Path, ref: str, log) -> bool:
    """CI clones are often shallow / single-branch: fetch the PR target if it's missing."""
    try:
        _git(repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
        return True
    except GitError:
        pass
    branch = ref.split("/", 1)[1] if ref.startswith("origin/") else ref
    try:
        _git(repo, "fetch", "--quiet", "origin", f"{branch}:refs/remotes/origin/{branch}")
        _git(repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
        return True
    except GitError as e:
        log.warning("cannot resolve %s (%s)", ref, e)
        return False


def merge_base(repo: Path, base: str) -> str:
    return _git(repo, "merge-base", base, "HEAD").strip()


def changed_lines(repo: Path, base_commit: str) -> dict[str, set[int]]:
    """{path: {added line numbers}} for base..HEAD (added/modified/renamed files)."""
    out = _git(repo, "diff", "--unified=0", "--no-color", "--diff-filter=ACMR", f"{base_commit}..HEAD")
    result: dict[str, set[int]] = {}
    path = None
    for ln in out.splitlines():
        if ln.startswith("+++ b/"):
            path = ln[6:]
            result.setdefault(path, set())
        elif ln.startswith("@@") and path:
            m = re.search(r"\+(\d+)(?:,(\d+))?", ln)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                result[path].update(range(start, start + count))
    return result


def added_by_commit(repo: Path, rev_range: str | None, max_commits: int):
    """Yield (commit, path, added_text) for every file change in the range (or whole history)."""
    args = ["log", "-p", "--no-color", "--format=@@COMMIT %H", f"-n{max_commits}"]
    args += [rev_range or "HEAD"]
    out = _git(repo, *args, timeout=900)
    commit, path, added = "", "", []
    for ln in out.splitlines():
        if ln.startswith("@@COMMIT "):
            if commit and path and added:
                yield commit, path, "\n".join(added)
            commit, path, added = ln.split()[1], "", []
        elif ln.startswith("+++ b/"):
            if commit and path and added:
                yield commit, path, "\n".join(added)
            path, added = ln[6:], []
        elif ln.startswith("+") and not ln.startswith("+++"):
            added.append(ln[1:])
    if commit and path and added:
        yield commit, path, "\n".join(added)


def remote_name(repo: Path) -> str:
    try:
        url = _git(repo, "config", "--get", "remote.origin.url").strip()
        return re.sub(r"\.git$", "", url.rstrip("/").split("/")[-1].split(":")[-1]) or repo.resolve().name
    except GitError:
        return repo.resolve().name
