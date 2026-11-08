"""Runtime stage: scheduled checks against running systems (on-prem or cloud, reached over HTTPS).

  1 exposure      sensitive paths, directory listing, headers          (http)
  2 known vulns   CVE / misconfiguration templates                       (nuclei)
  3 authz         unauthenticated data, IDOR, secrets/PII in responses   (http)
  4 storage       plaintext passwords, weak hashes, unencrypted PII       (db)
  (+ CI results ingested from [ingest].watch_dir)
"""
from __future__ import annotations

import logging
import signal
import time
import traceback

from ..common import alerts, report, triage
from ..common.store import Store, now
from . import db, http, ingest, nuclei

log = logging.getLogger("leakwatch")

# name -> (scan fn, auto_resolve)
REGISTRY = {
    "http": (http.scan, True),      # also emits "cloud" findings for optional [[cloud_storage]]
    "nuclei": (nuclei.scan, True),
    "db": (db.scan, True),
}


def run_once(cfg, only: list[str] | None = None) -> dict:
    store = Store(cfg.data_dir)
    started = now()
    findings, ran, errors, scanned = [], {}, {}, set()
    for name, (scan, auto_resolve) in REGISTRY.items():
        if only and name not in only:
            continue
        try:
            findings += scan(cfg, log, scanned)
            ran[name] = auto_resolve
            if name == "http":
                ran["cloud"] = True
        except Exception as e:  # noqa: BLE001 — one broken check must not stop the loop
            errors[name] = f"{e.__class__.__name__}: {e}"
            log.error("check %s failed:\n%s", name, traceback.format_exc())
    new, reopened, escalated, resolved = store.ingest(findings, ran, scanned)
    if not only or "ingest" in only:
        i_new, i_re, i_esc, i_res = ingest.ingest_watch_dir(cfg, store, log)
        new, reopened, escalated, resolved = new + i_new, reopened + i_re, escalated + i_esc, resolved + i_res
    events = [("NEW", f) for f in new] + [("REOPENED", f) for f in reopened] + [("ESCALATED", f) for f in escalated]
    triage.triage(cfg, log, [f for _, f in events], store)
    alerts.send(cfg, log, events, resolved)
    store.record_run(started, list(ran), len(findings), len(new), len(reopened), len(resolved), errors)
    path = report.write(cfg, store)
    summary = {"findings": len(findings), "new": len(new), "reopened": len(reopened),
               "escalated": len(escalated), "resolved": len(resolved), "errors": errors, "report": str(path)}
    log.info("cycle done: %s", summary)
    return summary


def daemon(cfg) -> None:
    stop = {"flag": False}

    def _stop(*_):
        stop["flag"] = True
        log.info("stopping after current cycle…")

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)
    interval = cfg.interval_minutes * 60
    log.info("runtime daemon started: every %d min", cfg.interval_minutes)
    while not stop["flag"]:
        t0 = time.time()
        try:
            run_once(cfg)
        except Exception:  # noqa: BLE001
            log.error("cycle crashed:\n%s", traceback.format_exc())
        while not stop["flag"] and time.time() - t0 < interval:
            time.sleep(1)
