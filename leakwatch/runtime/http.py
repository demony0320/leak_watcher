"""Active, scoped probes against your own web apps / APIs and cloud storage URLs.

Every request goes through Config.check_scope — hosts must be listed in
[scope].allowed_hosts. Requests are GET only, rate-limited, and never send
payloads that change state.
"""
from __future__ import annotations

import json
import re
import ssl
import time
import urllib.error
import urllib.request

from ..common.config import ScopeError, secret_from
from ..common.models import Finding, value_hash
from ..common.patterns import ALL_RULES, mask, scan_text

SENSITIVE_PATHS = {
    "/.env": ("critical", r"(?im)^[A-Z_]{3,}\s*="),
    "/.git/config": ("critical", r"\[core\]"),
    "/.git/HEAD": ("high", r"^ref: refs/"),
    "/.svn/entries": ("high", r"."),
    "/.DS_Store": ("low", r"Bud1"),
    "/config.json": ("medium", r"[\"'](password|secret|key|token)"),
    "/appsettings.json": ("high", r"ConnectionStrings|\"Password\""),
    "/web.config": ("high", r"<configuration"),
    "/actuator/env": ("critical", r"propertySources|activeProfiles"),
    "/actuator/heapdump": ("critical", r"JAVA PROFILE"),
    "/server-status": ("medium", r"Apache Server Status"),
    "/phpinfo.php": ("medium", r"PHP Version"),
    "/debug": ("medium", r"(?i)traceback|stack ?trace|debug"),
    "/swagger-ui.html": ("low", r"(?i)swagger"),
    "/swagger/index.html": ("low", r"(?i)swagger"),
    "/v3/api-docs": ("low", r"\"openapi\""),
    "/openapi.json": ("low", r"\"openapi\""),
    "/api-docs": ("low", r"(?i)swagger|openapi"),
    "/backup.sql": ("critical", r"(?i)insert into|create table"),
    "/dump.sql": ("critical", r"(?i)insert into|create table"),
    "/backup.zip": ("high", r"^PK"),
    "/test": ("low", r"."),
    "/admin": ("low", r"(?i)admin"),
}
DIR_LISTING = re.compile(r"(?i)<title>\s*Index of /|Directory listing for /")


class Http:
    def __init__(self, cfg, spec: dict):
        self.cfg = cfg
        self.headers = {"User-Agent": "LeakWatch/0.1 (internal leak scanner)"}
        token = secret_from(spec, "token")
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        for k, v in spec.get("headers", {}).items():
            self.headers[k] = v
        self.ctx = ssl.create_default_context()
        if spec.get("verify_tls") is False:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.calls = 0

    def get(self, url: str, auth: bool = True) -> tuple[int, dict, str]:
        self.cfg.check_scope(url)
        if self.calls:
            time.sleep(self.cfg.http_delay)
        self.calls += 1
        headers = dict(self.headers)
        if not auth:
            headers.pop("Authorization", None)
            headers.pop("Cookie", None)
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.http_timeout, context=self.ctx) as r:
                return r.status, dict(r.headers), r.read(2_000_000).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers or {}), (e.read(200_000) or b"").decode("utf-8", "ignore")
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            return 0, {}, str(e)


def _body_findings(body: str, target: str, url: str, extra_note: str = "") -> list[Finding]:
    out, pii, seen = [], {}, set()
    for rule, value, _ in scan_text(body, ALL_RULES):
        if value_hash(value) in seen:
            continue
        seen.add(value_hash(value))
        if rule.category == "pii":
            pii.setdefault(rule.name, set()).add(value_hash(value))
            continue
        out.append(Finding("http", rule.name, "secret", rule.severity, target, url,
                           f"{rule.name.split('.', 1)[1]} returned in HTTP response{extra_note}",
                           mask(value), value_hash(value)))
    for rname, hashes in pii.items():
        rule = next(r for r in ALL_RULES if r.name == rname)
        out.append(Finding("http", rname, "pii", rule.severity if len(hashes) >= 2 or rule.severity == "critical" else "low",
                           target, url, f"{len(hashes)} {rname.split('.', 1)[1]} value(s) in response{extra_note}",
                           f"count={len(hashes)}", dedup_key=rname, extra={"count": len(hashes)}))
    return out


def _looks_like_data(status: int, body: str) -> bool:
    if status != 200 or len(body.strip()) < 2:
        return False
    if re.search(r"(?i)(<form[^>]+login|unauthori[sz]ed|forbidden|sign in|로그인)", body[:4000]):
        return False
    return True


def scan(cfg, log, scanned: set | None = None) -> list[Finding]:
    scanned = scanned if scanned is not None else set()
    out: list[Finding] = []
    for spec in cfg.section("http"):
        name, base = spec["name"], spec["base_url"].rstrip("/")
        try:
            cfg.check_scope(base)
        except ScopeError as e:
            log.error("http[%s]: %s", name, e)
            continue
        h = Http(cfg, spec)
        status, headers, body = h.get(base + "/", auth=False)
        if status == 0:
            log.warning("http[%s]: unreachable (%s)", name, body)
            continue
        scanned.add(("http", name))
        out.extend(_headers_check(name, base, headers))

        # SPA / catch-all servers answer 200 to everything; learn what "not found" looks like
        _, _, notfound = h.get(base + "/leakwatch-nonexistent-7f3a9c", auth=False)

        def is_catch_all(b: str) -> bool:
            return bool(notfound) and abs(len(b) - len(notfound)) <= max(32, len(notfound) * 0.03)

        # 1) exposed sensitive paths (unauthenticated)
        paths = dict(SENSITIVE_PATHS)
        for p in spec.get("extra_paths", []):
            paths[p] = ("medium", r".")
        for path, (sev, sig) in paths.items():
            st, _, b = h.get(base + path, auth=False)
            if st == 200 and is_catch_all(b):
                continue
            if st == 200 and re.search(sig, b[:20000]):
                out.append(Finding("http", "exposure.sensitive_path", "exposure", sev, name, base + path,
                                   f"Publicly reachable: {path}", b[:80].replace("\n", " ") if sev in ("low", "medium") else "",
                                   dedup_key=path))
                out.extend(_body_findings(b, name, base + path, f" ({path})"))
            elif st == 200 and DIR_LISTING.search(b):
                out.append(Finding("http", "exposure.dir_listing", "exposure", "high", name, base + path,
                                   "Directory listing enabled", dedup_key=path))

        # 2) endpoints that must require auth — call them without credentials
        for path in spec.get("auth_required", []):
            st, _, b = h.get(base + path, auth=False)
            if _looks_like_data(st, b):
                out.append(Finding("http", "authz.missing_auth", "authz", "critical", name, base + path,
                                   f"Returns data without authentication (HTTP {st})", dedup_key=path,
                                   extra={"bytes": len(b)}))
                out.extend(_body_findings(b, name, base + path, " without auth"))

        # 3) object-level authorization (IDOR / sequential id enumeration)
        for idor in spec.get("idor", []):
            out.extend(_idor_check(h, name, base, idor, log))

        # 4) known pages: scan what they return for secrets/PII
        for path in spec.get("crawl_paths", []):
            st, _, b = h.get(base + path, auth=True)
            if st == 200:
                out.extend(_body_findings(b, name, base + path))
        log.info("http[%s]: %d requests", name, h.calls)

    for spec in cfg.section("cloud_storage"):
        out.extend(_cloud_check(cfg, spec, log, scanned))
    return out


def _headers_check(name: str, base: str, headers: dict) -> list[Finding]:
    out = []
    h = {k.lower(): v for k, v in headers.items()}
    for k in ("server", "x-powered-by", "x-aspnet-version"):
        if k in h and re.search(r"\d", h[k]):
            out.append(Finding("http", "exposure.version_banner", "exposure", "info", name, base,
                               f"Version disclosed in {k} header", h[k][:60], dedup_key=k))
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        out.append(Finding("http", "exposure.cors_wildcard_credentials", "exposure", "high", name, base,
                           "CORS allows any origin with credentials", dedup_key="cors"))
    return out


def _idor_check(h: Http, name: str, base: str, spec: dict, log) -> list[Finding]:
    """Request the user's own object, then neighbouring ids with the SAME credentials.

    If neighbours come back 200 with different personal data, any logged-in user
    (or a stolen low-privilege token) can enumerate other people's records.
    """
    tmpl = spec["path"]
    own = str(spec["own_id"])
    st0, _, own_body = h.get(base + tmpl.replace("{id}", own), auth=True)
    if st0 != 200:
        log.warning("idor[%s]: own object %s returned %s — check token/own_id", tmpl, own, st0)
        return []
    probes = int(spec.get("neighbors", 3))
    leaked = []
    if own.isdigit():
        candidates = [str(int(own) + d) for d in range(-probes, probes + 1) if d != 0 and int(own) + d > 0]
    else:
        candidates = [str(x) for x in spec.get("other_ids", [])]
    for cid in candidates:
        st, _, b = h.get(base + tmpl.replace("{id}", cid), auth=True)
        if _looks_like_data(st, b) and b != own_body:
            pii = {r.name for r, _, _ in scan_text(b, ALL_RULES) if r.category == "pii"}
            leaked.append((cid, sorted(pii)))
    out = []
    if leaked:
        out.append(Finding("http", "authz.idor", "authz", "critical", name, base + tmpl,
                           f"Other users' objects readable by changing the id ({len(leaked)}/{len(candidates)} neighbours)",
                           f"ids={','.join(c for c, _ in leaked[:5])}", dedup_key=tmpl,
                           extra={"pii_types": sorted({p for _, ps in leaked for p in ps}),
                                  "hint": "Enforce server-side owner check; rate-limit lookups; avoid sequential ids"}))
    # same object without any credentials?
    st, _, b = h.get(base + tmpl.replace("{id}", own), auth=False)
    if _looks_like_data(st, b):
        out.append(Finding("http", "authz.missing_auth", "authz", "critical", name, base + tmpl,
                           "Object endpoint returns data without authentication", dedup_key=tmpl))
    return out


def _cloud_check(cfg, spec: dict, log, scanned: set) -> list[Finding]:
    """Anonymous access to S3 / Azure Blob / GCS / MinIO URLs (no SDK needed)."""
    name, url = spec["name"], spec["url"]
    try:
        cfg.check_scope(url)
    except ScopeError as e:
        log.error("cloud_storage[%s]: %s", name, e)
        return []
    h = Http(cfg, {"verify_tls": spec.get("verify_tls", True)})
    out = []
    list_url = url
    if spec.get("provider") == "azure" and "comp=list" not in url:
        list_url = url + ("&" if "?" in url else "?") + "restype=container&comp=list"
    st, _, body = h.get(list_url, auth=False)
    if st == 0:
        log.warning("cloud_storage[%s]: unreachable (%s)", name, body)
        return []
    scanned.add(("cloud", name))
    if st == 200 and re.search(r"<ListBucketResult|<EnumerationResults|\"kind\":\s*\"storage#objects\"", body):
        n = len(re.findall(r"<Key>|<Name>|\"name\":", body))
        out.append(Finding("cloud", "exposure.public_bucket_listing", "exposure", "critical", name, list_url,
                           f"Storage container lists {n} objects anonymously", f"objects≈{n}", dedup_key="list"))
    for obj in spec.get("probe_objects", []):
        ourl = url.split("?")[0].rstrip("/") + "/" + obj.lstrip("/")
        st, _, body = h.get(ourl, auth=False)
        if st == 200:
            out.append(Finding("cloud", "exposure.public_object", "exposure", "high", name, ourl,
                               "Object readable anonymously", dedup_key=obj))
            out.extend(_body_findings(body, name, ourl))
    return out
