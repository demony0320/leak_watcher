"""Publish CI results to Bitbucket Code Insights (report + line annotations on the PR diff).

Bitbucket Cloud (Pipelines)
  Inside a Pipelines step, requests go through the pipeline auth proxy at localhost:29418
  (plain http to api.bitbucket.org); no token needed. Uses BITBUCKET_REPO_OWNER/_SLUG/_COMMIT.

Bitbucket Data Center / Server (any CI: Bamboo, Jenkins, ...)
  BITBUCKET_SERVER_URL, BITBUCKET_PROJECT, BITBUCKET_REPO, BITBUCKET_TOKEN (read-permission
  HTTP access token) and the commit hash.

Evidence sent is the masked value only.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

REPORT_KEY = "leakwatch"
CLOUD_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
DC_SEV = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "LOW"}
TYPE = {"secret": "VULNERABILITY", "pii": "VULNERABILITY", "exposure": "VULNERABILITY",
        "authz": "VULNERABILITY", "storage": "VULNERABILITY"}


def detect_flavor() -> str | None:
    if os.environ.get("BITBUCKET_SERVER_URL"):
        return "dc"
    if os.environ.get("BITBUCKET_COMMIT") and os.environ.get("BITBUCKET_REPO_SLUG"):
        return "cloud"
    return None


def _send(method: str, url: str, body, headers: dict, proxy: str | None, log):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **headers})
    handlers = [urllib.request.ProxyHandler({"http": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        log.error("bitbucket %s %s → %s %s", method, url.split("?")[0], e.code, (e.read() or b"")[:300])
    except urllib.error.URLError as e:
        log.error("bitbucket %s failed: %s", method, e)
    return None


def _annotation_text(f) -> str:
    return f"[{f.severity}] {f.title}" + (f" — {f.evidence}" if f.evidence else "")


def publish(result, log, flavor: str | None = None, link: str | None = None) -> bool:
    flavor = flavor or detect_flavor()
    if not flavor:
        log.info("not running in Bitbucket — skipping Code Insights")
        return False
    findings = [f for f in result.findings if f.extra.get("new") and not f.extra.get("baselined")]
    findings.sort(key=lambda f: (not f.extra.get("blocking"),))
    n_block = len(result.blocking)
    passed = n_block == 0
    details = (f"{len(result.findings)} finding(s), {n_block} blocking at fail_on={result.meta['fail_on']}. "
               f"Mode: {result.meta['mode']}. Evidence is masked; see the pipeline artifact for details.")

    if flavor == "cloud":
        owner, slug, commit = (os.environ["BITBUCKET_REPO_OWNER"], os.environ["BITBUCKET_REPO_SLUG"],
                               os.environ["BITBUCKET_COMMIT"])
        base = f"http://api.bitbucket.org/2.0/repositories/{owner}/{slug}/commit/{commit}/reports/{REPORT_KEY}"
        proxy = os.environ.get("LEAKWATCH_BB_PROXY", "http://localhost:29418")
        report = {"title": "LeakWatch", "details": details[:2000], "report_type": "SECURITY", "reporter": "LeakWatch",
                  "result": "PASSED" if passed else "FAILED",
                  "data": [{"title": "Blocking", "type": "NUMBER", "value": n_block},
                           {"title": "Findings", "type": "NUMBER", "value": len(result.findings)},
                           {"title": "Mode", "type": "TEXT", "value": result.meta["mode"]}]}
        if link:
            report["link"] = link
        if not _send("PUT", base, report, {}, proxy, log):
            return False
        anns = []
        for i, f in enumerate(findings[:1000]):
            a = {"external_id": f"lw-{f.fingerprint}", "annotation_type": TYPE.get(f.category, "BUG"),
                 "summary": _annotation_text(f)[:450], "severity": CLOUD_SEV[f.severity],
                 "path": f.extra.get("path", f.location)}
            if f.extra.get("line"):
                a["line"] = int(f.extra["line"])
            anns.append(a)
        for i in range(0, len(anns), 100):
            _send("POST", base + "/annotations", anns[i:i + 100], {}, proxy, log)
        log.info("Code Insights (cloud): report %s, %d annotation(s)", "PASSED" if passed else "FAILED", len(anns))
        return True

    # Data Center / Server
    srv = os.environ["BITBUCKET_SERVER_URL"].rstrip("/")
    proj, repo = os.environ["BITBUCKET_PROJECT"], os.environ["BITBUCKET_REPO"]
    commit = os.environ.get("BITBUCKET_COMMIT") or result.meta.get("commit")
    token = os.environ.get("BITBUCKET_TOKEN", "")
    base = f"{srv}/rest/insights/1.0/projects/{proj}/repos/{repo}/commits/{commit}/reports/{REPORT_KEY}"
    hdr = {"Authorization": f"Bearer {token}"}
    report = {"title": "LeakWatch", "details": details[:2000], "reporter": "LeakWatch",
              "result": "PASS" if passed else "FAIL",
              "data": [{"title": "Blocking", "type": "NUMBER", "value": n_block},
                       {"title": "Findings", "type": "NUMBER", "value": len(result.findings)},
                       {"title": "Mode", "type": "TEXT", "value": result.meta["mode"]}]}
    if link:
        report["link"] = link
    if not _send("PUT", base, report, hdr, None, log):
        return False
    _send("DELETE", base + "/annotations", None, hdr, None, log)  # replace previous run's annotations
    anns = [{"externalId": f"lw-{f.fingerprint}", "path": f.extra.get("path", f.location),
             "line": int(f.extra.get("line") or 0), "message": _annotation_text(f)[:2000],
             "severity": DC_SEV[f.severity], "type": TYPE.get(f.category, "BUG")} for f in findings[:1000]]
    for i in range(0, len(anns), 500):
        _send("POST", base + "/annotations", {"annotations": anns[i:i + 500]}, hdr, None, log)
    log.info("Code Insights (data center): report %s, %d annotation(s)", "PASS" if passed else "FAIL", len(anns))
    return True
