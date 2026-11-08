"""leakwatch — two stages, one history.

CI (in Bitbucket Pipelines or any CI; no config file needed, optional .leakwatch.toml in the repo)
  leakwatch ci scan      [--path .] [--mode auto|full|diff] [--base origin/main] [--history]
                         [--fail-on high] [--out leakwatch-results] [--bitbucket auto|cloud|dc|off]
  leakwatch ci baseline  [--path .]          accept current findings (writes .leakwatch-baseline.json)

Runtime (scheduled on a server/PC, config file)
  leakwatch -c runtime.toml runtime run [--only http,nuclei,db,ingest]
  leakwatch -c runtime.toml runtime daemon
  leakwatch -c runtime.toml ingest <findings.json>...     bring CI results into the runtime store
  leakwatch -c runtime.toml list|show|feedback|report
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def _ci(a, log) -> int:
    from .ci import bitbucket, outputs
    from .ci.scan import CIOptions, run, write_baseline

    repo = Path(a.path).resolve()
    opts = CIOptions.from_repo(repo, mode=a.mode, base=a.base, history=a.history or None, fail_on=a.fail_on,
                               use_gitleaks=a.gitleaks, target=a.name)
    if a.ci_cmd == "baseline":
        opts.mode, opts.history = "full", True   # accept tree + history debt
        res = run(opts, log)
        p = write_baseline(res, repo, opts.baseline)
        print(f"baseline: {len(res.findings)} finding(s) accepted → {p.relative_to(repo)} (commit this file)")
        return 0
    res = run(opts, log)
    paths = outputs.write_all(res, Path(a.out))
    print(outputs.summary_text(res))
    print(f"\nresults: {', '.join(str(p) for p in paths.values())}")
    if a.bitbucket != "off":
        bitbucket.publish(res, log, None if a.bitbucket == "auto" else a.bitbucket)
    return 1 if res.blocking else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="leakwatch", description="Leak detection: CI stage + runtime stage")
    p.add_argument("-c", "--config", default="runtime.toml", help="runtime config (not used by `ci`)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    ci = sub.add_parser("ci", help="scan a repository checkout (CI stage)")
    cisub = ci.add_subparsers(dest="ci_cmd", required=True)
    for name in ("scan", "baseline"):
        c = cisub.add_parser(name)
        c.add_argument("--path", default=".")
        c.add_argument("--name", help="repo display name (default: git remote name)")
        c.add_argument("--gitleaks", choices=["auto", "on", "off"], default=None)
        if name == "scan":
            c.add_argument("--mode", choices=["auto", "full", "diff"], default=None)
            c.add_argument("--base", help="diff base ref, e.g. origin/main (auto: BITBUCKET_PR_DESTINATION_BRANCH)")
            c.add_argument("--history", action="store_true", help="full mode: also scan the whole git history")
            c.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], default=None)
            c.add_argument("--out", default="leakwatch-results")
            c.add_argument("--bitbucket", choices=["auto", "cloud", "dc", "off"], default="auto")
        else:
            c.set_defaults(mode=None, base=None, history=False, fail_on=None)

    rt = sub.add_parser("runtime", help="scheduled checks against running systems")
    rtsub = rt.add_subparsers(dest="rt_cmd", required=True)
    r = rtsub.add_parser("run"); r.add_argument("--only")
    rtsub.add_parser("daemon")

    ing = sub.add_parser("ingest", help="import CI findings.json into the runtime store")
    ing.add_argument("files", nargs="+")
    ls = sub.add_parser("list"); ls.add_argument("--status", default="open")
    sh = sub.add_parser("show"); sh.add_argument("id")
    fb = sub.add_parser("feedback")
    fb.add_argument("id"); fb.add_argument("verdict", choices=["fp", "fixed", "confirm"])
    fb.add_argument("--note", default="")
    fb.add_argument("--rule-wide", action="store_true")
    sub.add_parser("report")
    a = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    log = logging.getLogger("leakwatch")

    if a.cmd == "ci":
        try:
            return _ci(a, log)
        except Exception as e:  # noqa: BLE001 — scanner errors must not look like "leak found"
            log.exception("ci scan error: %s", e)
            return 2

    from .common import report
    from .common.config import Config
    from .common.store import Store, now
    from .runtime import ingest, loop

    cfg = Config.load(a.config)
    if a.cmd == "runtime":
        if a.rt_cmd == "run":
            s = loop.run_once(cfg, a.only.split(",") if a.only else None)
            print(json.dumps(s, ensure_ascii=False, indent=2))
            return 1 if s["errors"] else 0
        loop.daemon(cfg)
        return 0

    store = Store(cfg.data_dir)
    if a.cmd == "ingest":
        for f in a.files:
            ingest.ingest_file(store, Path(f), log)
        report.write(cfg, store)
    elif a.cmd == "list":
        rows = store.findings(None if a.status == "all" else a.status)
        for x in rows:
            loc = x["location"]
            line = json.loads(x["extra"] or "{}").get("line")
            loc = f"{loc}:{line}" if line else loc
            print(f"{x['fingerprint'][:8]}  {x['severity']:<8} {x['status']:<10} {x['detector']:<6} {x['target']:<14} "
                  f"{x['title'][:64]}  @ {loc[:60]}")
        print(f"\n{len(rows)} finding(s)")
    elif a.cmd == "show":
        x = store.get(a.id)
        print(json.dumps(x, ensure_ascii=False, indent=2) if x else "not found")
    elif a.cmd == "feedback":
        x = store.get(a.id)
        if not x:
            print("not found"); return 1
        if a.verdict == "fp":
            if a.rule_wide:
                store.add_suppression(rule=x["rule"], target=x["target"], reason=a.note or "false positive")
            store.add_suppression(fingerprint=x["fingerprint"], reason=a.note or "false positive")
        elif a.verdict == "fixed":
            store.set_status(x["fingerprint"], "resolved", a.note)
        else:
            store.set_status(x["fingerprint"], "open", a.note or "confirmed")
        if a.note:
            with open(cfg.data_dir / "triage_instructions.md", "a", encoding="utf-8") as fh:
                fh.write(f"- [{now()[:10]}] {a.verdict.upper()} {x['rule']} on {x['target']} "
                         f"({x['location'][:80]}): {a.note}\n")
        report.write(cfg, store)
        print(f"{x['fingerprint'][:8]} → {a.verdict}")
    elif a.cmd == "report":
        print(report.write(cfg, store))
    return 0


if __name__ == "__main__":
    sys.exit(main())
