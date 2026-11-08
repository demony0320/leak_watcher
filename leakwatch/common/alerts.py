"""Alert sinks. All internal: console, JSONL file, generic webhook (Teams/Slack/Mattermost-compatible), SMTP."""
from __future__ import annotations

import json
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

from .config import secret_from
from .models import SEVERITY_RANK, Finding

ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def _line(kind: str, f: Finding) -> str:
    return f"{ICON.get(f.severity, '')} [{f.severity.upper()}] {kind}: {f.title} — {f.target} {f.location} ({f.fingerprint[:8]})"


def send(cfg, log, events: list[tuple[str, Finding]], resolved: list[dict]):
    acfg = cfg.get("alerts", {})
    minsev = SEVERITY_RANK[acfg.get("min_severity", "medium")]
    events = [(k, f) for k, f in events if SEVERITY_RANK[f.severity] >= minsev]
    resolved = [r for r in resolved if SEVERITY_RANK.get(r["severity"], 0) >= minsev]
    if not events and not (resolved and acfg.get("notify_resolved", True)):
        return
    lines = [_line(k, f) for k, f in events]
    lines += [f"✅ RESOLVED: {r['title']} — {r['target']} {r['location']} ({r['fingerprint'][:8]})"
              for r in resolved] if acfg.get("notify_resolved", True) else []
    text = "LeakWatch\n" + "\n".join(lines)

    if acfg.get("console", True):
        print(text, flush=True)
    if acfg.get("jsonl"):
        p = cfg.path(acfg["jsonl"])
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            for k, f in events:
                fh.write(json.dumps({"event": k, **f.to_dict()}, ensure_ascii=False) + "\n")
            for r in resolved:
                fh.write(json.dumps({"event": "resolved", "fingerprint": r["fingerprint"], "title": r["title"]},
                                    ensure_ascii=False) + "\n")
    url = secret_from(acfg, "webhook_url")
    if url:
        try:
            body = json.dumps({"text": text}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10, context=ssl.create_default_context()).read()
        except Exception as e:  # noqa: BLE001
            log.error("webhook alert failed: %s", e)
    smtp = acfg.get("smtp")
    if smtp:
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[LeakWatch] {len(events)} new/reopened, {len(resolved)} resolved"
            msg["From"], msg["To"] = smtp["from"], ", ".join(smtp["to"])
            msg.set_content(text)
            with smtplib.SMTP(smtp["host"], int(smtp.get("port", 25)), timeout=15) as s:
                if smtp.get("starttls"):
                    s.starttls()
                pw = secret_from(smtp, "password")
                if smtp.get("user") and pw:
                    s.login(smtp["user"], pw)
                s.send_message(msg)
        except Exception as e:  # noqa: BLE001
            log.error("smtp alert failed: %s", e)
