"""Bring CI results (findings.json) into the runtime store so both stages share one history.

Only FULL scans of a repo can auto-resolve that repo's earlier CI findings (a PR diff scan
sees only part of the repo). Files dropped into [ingest].watch_dir are picked up every cycle.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..common.models import Finding


def load(path: Path) -> tuple[dict, list[Finding]]:
    doc = json.loads(path.read_text("utf-8"))
    meta = doc.get("meta", {})
    fields = Finding.__dataclass_fields__
    findings = [Finding(**{k: v for k, v in d.items() if k in fields}) for d in doc.get("findings", [])]
    return meta, findings


def ingest_file(store, path: Path, log):
    meta, findings = load(path)
    repo = meta.get("repo", "unknown")
    full = meta.get("mode") == "full"
    for f in findings:
        f.target = repo
        f.extra.update({"ci_commit": meta.get("commit", "")[:8], "ci_branch": meta.get("branch", "")})
    res = store.ingest(findings, {"ci": full}, {("ci", repo)} if full else set())
    log.info("ingest %s: repo=%s mode=%s → new %d, reopened %d, resolved %d", path.name, repo, meta.get("mode"),
             len(res[0]), len(res[1]), len(res[3]))
    return res


def ingest_watch_dir(cfg, store, log):
    """Returns combined (new, reopened, escalated, resolved)."""
    icfg = cfg.get("ingest", {})
    if not icfg.get("watch_dir"):
        return [], [], [], []
    d = cfg.path(icfg["watch_dir"])
    done = d / "processed"
    d.mkdir(parents=True, exist_ok=True)
    done.mkdir(exist_ok=True)
    acc = ([], [], [], [])
    for p in sorted(d.glob("*.json")):
        try:
            r = ingest_file(store, p, log)
            for a, b in zip(acc, r):
                a.extend(b)
            shutil.move(str(p), done / p.name)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            log.error("ingest %s failed: %s", p.name, e)
    return acc
