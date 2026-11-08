"""CI stage: scan a repository checkout (whole tree, or only what a PR changes).

Modes
  full  every tracked-looking file in the working tree (+ optional whole git history)
  diff  files/lines changed between the PR target and HEAD, plus every commit in the
        PR range (catches "added a key, removed it in the next commit")

Only findings that are NEW in a PR (on added lines / added in PR commits), at or above
`fail_on`, not baselined and not ignored inline are "blocking" → exit code 1.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..common.models import SEVERITY_RANK, Finding, value_hash
from ..common.patterns import ALL_RULES, PII_RULES, SECRET_RULES, mask, scan_text
from . import coderules, git, gitleaks

DEFAULT_EXCLUDES = ["*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.zip", "*.gz", "*.whl",
                    "*.pdf", "*.exe", "*.dll", "*.so", "*.jar", "*.lock", "package-lock.json", "*.min.js",
                    "*.map", ".leakwatch-baseline.json"]
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache",
             "leakwatch-results"}
RISKY_FILENAMES = {".env": "high", "id_rsa": "critical", "id_ed25519": "critical", "id_ecdsa": "critical",
                   ".git-credentials": "critical", ".npmrc": "medium", ".pypirc": "medium",
                   "credentials": "high", "secrets.json": "high", "terraform.tfstate": "critical"}
RISKY_SUFFIXES = {".pem": "high", ".key": "high", ".pfx": "high", ".p12": "high", ".jks": "medium",
                  ".bak": "medium", ".sql": "low", ".dump": "medium"}
IGNORE_MARKERS = ("leakwatch:ignore", "gitleaks:allow")


@dataclass
class CIOptions:
    repo: Path
    mode: str = "auto"                 # auto | full | diff
    base: str | None = None            # e.g. origin/main
    history: bool = False              # full mode: also scan entire git history
    fail_on: str = "high"
    detect: list = field(default_factory=lambda: ["secret", "pii", "risky_file", "code"])
    exclude: list = field(default_factory=list)
    use_gitleaks: str = "auto"         # auto | on | off
    gitleaks_config: str | None = None
    baseline: str = ".leakwatch-baseline.json"
    max_file_kb: int = 1024
    history_max_commits: int = 2000
    rules: list = field(default_factory=list)          # custom code rules
    disabled_rules: list = field(default_factory=list)
    target: str | None = None          # repo display name

    @classmethod
    def from_repo(cls, repo: Path, **overrides) -> "CIOptions":
        conf = {}
        p = repo / ".leakwatch.toml"
        if p.exists():
            with open(p, "rb") as fh:
                conf = tomllib.load(fh).get("ci", {})
        merged = {k: v for k, v in conf.items() if k in cls.__dataclass_fields__}
        merged.update({k: v for k, v in overrides.items() if v is not None})
        return cls(repo=repo, **merged)


@dataclass
class CIResult:
    meta: dict
    findings: list[Finding]
    blocking: list[Finding]


def _excluded(rel: str, patterns: list[str]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)


def _iter_tree(repo: Path, excludes: list[str]):
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            rel = Path(dirpath, fn).relative_to(repo).as_posix()
            if not _excluded(rel, excludes):
                yield rel


def _read_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    return raw.decode("utf-8", errors="ignore")


def _line_key(line_text: str) -> str:
    return hashlib.sha1(line_text.strip().encode()).hexdigest()[:12]


def _scan_content(rel: str, text: str, target: str, opts: CIOptions, added: set[int] | None) -> list[Finding]:
    """added=None → full mode (everything counts as new)."""
    lines = text.splitlines()
    ignored = {i + 1 for i, ln in enumerate(lines) if any(m in ln for m in IGNORE_MARKERS)}
    is_new = (lambda ln: True) if added is None else (lambda ln: ln in added)
    out: list[Finding] = []

    rules = (SECRET_RULES if "secret" in opts.detect else []) + (PII_RULES if "pii" in opts.detect else [])
    seen, pii = set(), {}
    for rule, value, off in scan_text(text, rules, max_hits=500):
        ln = text.count("\n", 0, off) + 1
        h = value_hash(value)
        if ln in ignored or h in seen:
            continue
        seen.add(h)
        if rule.category == "pii":
            pii.setdefault(rule.name, []).append(ln)
            continue
        out.append(Finding("ci", rule.name, "secret", rule.severity, target, rel,
                           f"{rule.name.split('.', 1)[1]} in {rel}", mask(value), h,
                           extra={"path": rel, "line": ln, "new": is_new(ln)}))
    for rname, lns in pii.items():
        rule = next(r for r in ALL_RULES if r.name == rname)
        n = len(lns)
        sev = rule.severity if (rule.severity == "critical" or n >= 3) else "info"
        out.append(Finding("ci", rname, "pii", sev, target, rel,
                           f"{n} {rname.split('.', 1)[1]} value(s) in {rel} — real personal data in the repo?",
                           f"count={n}", dedup_key=rname,
                           extra={"path": rel, "line": lns[0], "count": n, "new": any(is_new(x) for x in lns)}))

    if "code" in opts.detect:
        for rid, sev, cat, msg, ln in coderules.scan_file(rel, text, opts.rules, set(opts.disabled_rules)):
            if ln in ignored:
                continue
            key = _line_key(lines[ln - 1] if 0 < ln <= len(lines) else "")
            out.append(Finding("ci", rid, cat, sev, target, rel, msg, (lines[ln - 1].strip()[:100] if ln <= len(lines) else ""),
                               dedup_key=key, extra={"path": rel, "line": ln, "new": is_new(ln)}))
    return out


def _risky_file(rel: str, target: str, new: bool) -> Finding | None:
    name = rel.rsplit("/", 1)[-1]
    sev = RISKY_FILENAMES.get(name) or next((s for suf, s in RISKY_SUFFIXES.items() if name.endswith(suf)), None)
    if name.startswith(".env.") and name not in (".env.example", ".env.sample", ".env.template"):
        sev = "high"
    if not sev:
        return None
    return Finding("ci", "exposure.risky_file", "exposure", sev, target, rel, f"Sensitive file committed: {name}",
                   dedup_key="file", extra={"path": rel, "line": 0, "new": new})


def _history(repo: Path, target: str, rev_range: str | None, opts: CIOptions, tree_hashes: set[str], log) -> list[Finding]:
    """Secrets present in history (whole repo or PR range) but no longer in the tree."""
    out: dict[str, Finding] = {}
    try:
        for commit, path, added in git.added_by_commit(repo, rev_range, opts.history_max_commits):
            if _excluded(path, DEFAULT_EXCLUDES + opts.exclude):
                continue
            added_lines = added.splitlines()
            for rule, value, off in scan_text(added, SECRET_RULES, max_hits=50):
                h = value_hash(value)
                line_text = added_lines[added.count("\n", 0, off)] if added_lines else ""
                if h in tree_hashes or any(m in line_text for m in IGNORE_MARKERS):
                    continue
                f = Finding("ci", rule.name + ".history", "secret", rule.severity, target, path,
                            f"{rule.name.split('.', 1)[1]} committed in {commit[:8]}, not in current files "
                            f"(still recoverable from git history — rotate it)",
                            mask(value), h, extra={"path": path, "line": 0, "commit": commit[:8], "new": True})
                out[f.fingerprint] = f   # log is newest-first → ends with the commit that introduced it
    except git.GitError as e:
        log.warning("history scan skipped: %s", e)
    return list(out.values())


def run(opts: CIOptions, log) -> CIResult:
    repo = opts.repo.resolve()
    in_git = git.is_repo(repo)
    target = opts.target or (git.remote_name(repo) if in_git else repo.name)
    excludes = DEFAULT_EXCLUDES + opts.exclude

    mode, base_ref, base_commit = opts.mode, opts.base, None
    if mode == "auto":
        dest = os.environ.get("BITBUCKET_PR_DESTINATION_BRANCH")
        if dest and not base_ref:
            base_ref = f"origin/{dest}"
        mode = "diff" if base_ref else "full"
    if mode == "diff":
        if not in_git or not base_ref or not git.ensure_ref(repo, base_ref, log):
            log.warning("diff mode unavailable (base %s) — falling back to full scan", base_ref)
            mode = "full"
        else:
            base_commit = git.merge_base(repo, base_ref)

    findings: list[Finding] = []
    if mode == "full":
        files = {rel: None for rel in _iter_tree(repo, excludes)}
    else:
        files = {rel: lines for rel, lines in git.changed_lines(repo, base_commit).items()
                 if not _excluded(rel, excludes) and (repo / rel).is_file()}

    for rel, added in files.items():
        if "risky_file" in opts.detect:
            rf = _risky_file(rel, target, True)
            if rf:
                findings.append(rf)
        text = _read_text(repo / rel, opts.max_file_kb * 1024)
        if text is not None:
            findings += _scan_content(rel, text, target, opts, added)
    log.info("ci: scanned %d file(s) in %s mode", len(files), mode)

    if "secret" in opts.detect and in_git and (mode == "diff" or opts.history):
        tree = {f.evidence_hash for f in findings if f.evidence_hash}
        findings += _history(repo, target, f"{base_commit}..HEAD" if mode == "diff" else None, opts, tree, log)

    if opts.use_gitleaks != "off" and "secret" in opts.detect:
        if gitleaks.available():
            gl = gitleaks.run(repo, target, log, mode="git" if mode == "diff" else "dir",
                              rev_range=f"{base_commit}..HEAD" if mode == "diff" else None,
                              config=opts.gitleaks_config)
            known = {(f.extra.get("path"), f.extra.get("line")) for f in findings if f.category == "secret"}
            known |= {(f.extra.get("path"), f.extra.get("commit")) for f in findings if f.rule.endswith(".history")}
            for f in gl:
                key2 = (f.extra["path"], f.extra.get("commit"))
                if (f.extra["path"], f.extra["line"]) in known or (f.extra.get("commit") and key2 in known):
                    continue
                f.extra["new"] = True   # gitleaks only saw the PR range (diff) or the tree (full)
                findings.append(f)
        elif opts.use_gitleaks == "on":
            log.error("gitleaks requested but not found on PATH")

    # dedupe, baseline, blocking
    uniq = {f.fingerprint: f for f in findings}
    baseline = set()
    bp = repo / opts.baseline
    if bp.exists():
        try:
            baseline = set(json.loads(bp.read_text()).get("fingerprints", []))
        except (json.JSONDecodeError, AttributeError):
            log.warning("baseline file %s is not valid", bp)
    threshold = SEVERITY_RANK[opts.fail_on]
    blocking = []
    for f in uniq.values():
        f.extra["baselined"] = f.fingerprint in baseline
        f.extra["blocking"] = (SEVERITY_RANK[f.severity] >= threshold and not f.extra["baselined"]
                               and bool(f.extra.get("new")))
        if f.extra["blocking"]:
            blocking.append(f)

    meta = {
        "tool": "leakwatch-ci", "repo": target, "mode": mode, "base": base_ref,
        "commit": git.head(repo) if in_git else os.environ.get("BITBUCKET_COMMIT", ""),
        "branch": os.environ.get("BITBUCKET_BRANCH", ""), "pr": os.environ.get("BITBUCKET_PR_ID", ""),
        "fail_on": opts.fail_on, "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_scanned": len(files), "gitleaks": bool(gitleaks.available()) and opts.use_gitleaks != "off",
    }
    ordered = sorted(uniq.values(), key=lambda f: (not f.extra["blocking"], -SEVERITY_RANK[f.severity],
                                                   f.extra.get("path", ""), f.extra.get("line", 0)))
    return CIResult(meta, ordered, blocking)


def write_baseline(result: CIResult, repo: Path, path: str) -> Path:
    p = repo / path
    p.write_text(json.dumps({"comment": "Accepted existing findings. Remove an entry once it is fixed.",
                             "created": result.meta["scanned_at"],
                             "fingerprints": sorted(f.fingerprint for f in result.findings)}, indent=2) + "\n")
    return p
