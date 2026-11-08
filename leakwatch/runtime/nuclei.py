"""Known-vulnerability / misconfiguration scan via nuclei (ProjectDiscovery), if installed.

Targets = every [[http]] base_url (already scope-checked) + [nuclei].extra_targets.
Templates come from a local folder you refresh by carrying the nuclei-templates repo in
— re-running after each refresh is what catches "old service, newly published CVE".
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from ..common.config import ScopeError
from ..common.models import Finding
from ..common.patterns import mask

SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "unknown": "info"}


def scan(cfg, log, scanned: set | None = None) -> list[Finding]:
    scanned = scanned if scanned is not None else set()
    ncfg = cfg.get("nuclei", {})
    if not ncfg or ncfg.get("enabled") is False:
        return []
    exe = shutil.which(ncfg.get("binary", "nuclei"))
    if not exe:
        log.warning("nuclei: binary not found (%s) — skipping CVE/misconfig scan", ncfg.get("binary", "nuclei"))
        return []

    targets: dict[str, str] = {}  # url -> target name
    for spec in cfg.section("http"):
        targets[spec["base_url"].rstrip("/")] = spec["name"]
    for t in ncfg.get("extra_targets", []):
        targets[t["url"].rstrip("/")] = t["name"]
    allowed = {}
    for url, name in targets.items():
        try:
            cfg.check_scope(url)
            allowed[url] = name
        except ScopeError as e:
            log.error("nuclei: %s", e)
    if not allowed:
        return []

    with tempfile.TemporaryDirectory() as td:
        tfile = Path(td) / "targets.txt"
        tfile.write_text("\n".join(allowed) + "\n")
        cmd = [exe, "-list", str(tfile), "-jsonl", "-silent", "-disable-update-check", "-no-color",
               "-severity", ",".join(ncfg.get("severity", ["critical", "high", "medium", "low"])),
               "-rate-limit", str(ncfg.get("rate_limit", 50))]
        for t in ncfg.get("templates", []):
            cmd += ["-t", str(cfg.path(t))]
        for tag in ncfg.get("exclude_tags", ["dos", "fuzz", "intrusive"]):
            cmd += ["-etags", tag]
        cmd += [str(a) for a in ncfg.get("extra_args", [])]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, errors="ignore",
                               timeout=int(ncfg.get("timeout_minutes", 60)) * 60)
        except subprocess.TimeoutExpired:
            log.error("nuclei: timed out")
            return []
    if p.returncode not in (0, 1):
        log.error("nuclei: rc=%s %s", p.returncode, p.stderr.strip()[:300])
        return []
    for name in allowed.values():
        scanned.add(("nuclei", name))

    out = []
    for line in p.stdout.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {})
        matched = r.get("matched-at") or r.get("host", "")
        host = (urlparse(matched).hostname or matched).lower()
        name = next((n for u, n in allowed.items() if (urlparse(u).hostname or "").lower() == host), host)
        tid = r.get("template-id", "unknown")
        extracted = [mask(str(x)) for x in (r.get("extracted-results") or [])][:3]
        refs = info.get("reference") or []
        out.append(Finding(
            "nuclei", f"nuclei.{tid}", "exposure", SEV.get(str(info.get("severity", "info")).lower(), "info"), name,
            matched, info.get("name", tid) + (f" [{r['matcher-name']}]" if r.get("matcher-name") else ""),
            ", ".join(extracted), dedup_key=f"{tid}:{r.get('matcher-name', '')}",
            extra={"template": tid, "cve": (info.get("classification") or {}).get("cve-id"),
                   "hint": (refs[0] if isinstance(refs, list) and refs else "")}))
    log.info("nuclei: %d target(s), %d finding(s)", len(allowed), len(out))
    return out
