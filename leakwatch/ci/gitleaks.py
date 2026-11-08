"""Optional: run gitleaks (if installed) and convert its report into LeakWatch findings.

gitleaks has far more secret rules than LeakWatch's built-ins. We always run it with
--redact so the raw secret never lands in the report file, and dedupe against the
built-in scan by file:line.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..common.models import Finding


def available(binary: str = "gitleaks") -> str | None:
    return shutil.which(binary)


def run(repo: Path, target: str, log, *, mode: str, rev_range: str | None = None,
        binary: str = "gitleaks", config: str | None = None) -> list[Finding]:
    exe = available(binary)
    if not exe:
        return []
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "gitleaks.json"
        if mode == "dir":
            cmd = [exe, "dir", str(repo)]
        else:
            cmd = [exe, "git", str(repo)]
            if rev_range:
                cmd += ["--log-opts", rev_range]
        cmd += ["--report-format", "json", "--report-path", str(report), "--redact", "--exit-code", "0",
                "--no-banner"]
        if config:
            cmd += ["--config", config]
        p = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=1800)
        if p.returncode != 0 or not report.exists():
            log.warning("gitleaks failed (rc=%s): %s", p.returncode, p.stderr.strip()[:300])
            return []
        try:
            items = json.loads(report.read_text() or "[]")
        except json.JSONDecodeError:
            return []
    out = []
    for it in items or []:
        rel = it.get("File", "")
        if rel.startswith(str(repo)):
            rel = str(Path(rel).relative_to(repo))
        commit = it.get("Commit") or ""
        rule = "secret.gitleaks." + it.get("RuleID", "unknown")
        f = Finding("ci", rule + (".history" if mode == "git" and commit else ""), "secret", "high", target,
                    rel,
                    f"{it.get('Description') or it.get('RuleID')} (gitleaks)",
                    evidence=(it.get("Match") or "")[:80],
                    dedup_key=it.get("Fingerprint") or rule,
                    extra={"path": rel, "line": int(it.get("StartLine", 0) or 0), "commit": commit[:8],
                           "engine": "gitleaks"})
        out.append(f)
    log.info("gitleaks: %d finding(s)", len(out))
    return out
