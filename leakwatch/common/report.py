"""Self-contained HTML status page (no external assets — opens fine in a closed network)."""
from __future__ import annotations

import html
import json
from collections import Counter

from .models import SEVERITY_RANK
from datetime import datetime

from .store import now


def _local(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return iso or ""

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--mute:#6b6b66;--line:#e4e4df;
--crit:#c42b1c;--high:#d4680f;--med:#b38600;--low:#3b6fb6;--info:#8a8a85;--ok:#2e7d4f}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--fg:#ecece8;--mute:#9a9a94;--line:#33332f;
--crit:#ff6b5b;--high:#ff9d4d;--med:#e6c14a;--low:#7aa7ec;--info:#8a8a85;--ok:#5cc489}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,"Segoe UI","Malgun Gothic",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mute);margin-bottom:20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.tile b{display:block;font-size:24px;font-variant-numeric:tabular-nums}.tile span{color:var(--mute);font-size:12px}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
button,input{font:inherit;color:var(--fg);background:var(--card);border:1px solid var(--line);border-radius:8px;padding:5px 10px;cursor:pointer}
button.on{border-color:var(--fg)}input{cursor:text;min-width:220px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mute);font-weight:600}tr:last-child td{border-bottom:0}
.sev{font-weight:700;font-size:12px;text-transform:uppercase}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}.info{color:var(--info)}
code{font:12px ui-monospace,Consolas,monospace;word-break:break-all}.mute{color:var(--mute);font-size:12px}
.tri{margin-top:4px;font-size:12px;padding:6px 8px;border-left:3px solid var(--line)}
.st-resolved{color:var(--ok)}.st-suppressed{color:var(--mute)}
"""

JS = """
const rows=[...document.querySelectorAll('tbody tr')];let sev='all',st='open',q='';
function apply(){rows.forEach(r=>{const ok=(sev==='all'||r.dataset.sev===sev)&&(st==='all'||r.dataset.st===st)
&&(!q||r.textContent.toLowerCase().includes(q));r.style.display=ok?'':'none'})}
document.querySelectorAll('[data-f]').forEach(b=>b.onclick=()=>{const [k,v]=b.dataset.f.split(':');
if(k==='sev')sev=v;else st=v;document.querySelectorAll(`[data-f^="${k}:"]`).forEach(x=>x.classList.toggle('on',x===b));apply()});
document.querySelector('#q').oninput=e=>{q=e.target.value.toLowerCase();apply()};apply();
"""


def write(cfg, store):
    rows = store.findings()
    runs = store.runs(10)
    open_rows = [r for r in rows if r["status"] == "open"]
    by_sev = Counter(r["severity"] for r in open_rows)
    e = html.escape
    tiles = "".join(
        f'<div class="tile"><b class="{s}">{by_sev.get(s, 0)}</b><span>open {s}</span></div>'
        for s in ("critical", "high", "medium", "low"))
    tiles += (f'<div class="tile"><b>{sum(r["status"] == "resolved" for r in rows)}</b><span>resolved</span></div>'
              f'<div class="tile"><b>{sum(r["status"] == "suppressed" for r in rows)}</b><span>suppressed</span></div>')
    body = []
    for r in rows:
        tri = ""
        if r["triage"]:
            t = json.loads(r["triage"])
            steps = " · ".join(e(s) for s in t.get("next_steps", []))
            fp = " · 오탐 가능성" if t.get("likely_false_positive") else ""
            tri = f'<div class="tri"><b>{e(t.get("priority", ""))}</b>{fp} — {e(t.get("summary", ""))}<br>{steps}</div>'
        extra = json.loads(r["extra"] or "{}")
        hint = f'<div class="mute">{e(str(extra["hint"]))}</div>' if "hint" in extra else ""
        body.append(
            f'<tr data-sev="{e(r["severity"])}" data-st="{e(r["status"])}">'
            f'<td class="sev {e(r["severity"])}">{e(r["severity"])}</td>'
            f'<td>{e(r["title"])}{hint}{tri}<div class="mute">{e(r["rule"])}</div></td>'
            f'<td><span class="mute">{e(r["detector"])}</span> {e(r["target"])}<br><code>{e(r["location"])}'
            f'{":" + str(extra["line"]) if extra.get("line") else ""}</code></td>'
            f'<td><code>{e(r["evidence"] or "")}</code></td>'
            f'<td class="st-{e(r["status"])}">{e(r["status"])}<div class="mute">seen {r["seen_count"]}×<br>'
            f'{e(_local(r["first_seen"]))}</div></td><td><code>{e(r["fingerprint"][:8])}</code></td></tr>')
    last = runs[0] if runs else {}
    errs = json.loads(last.get("errors") or "{}") if last else {}
    err_html = "".join(f'<div class="high">⚠ {e(k)}: {e(v)}</div>' for k, v in errs.items())
    filt = "".join(f'<button data-f="sev:{s}" class="{"on" if s == "all" else ""}">{s}</button>'
                   for s in ["all", "critical", "high", "medium", "low", "info"])
    filt += "".join(f'<button data-f="st:{s}" class="{"on" if s == "open" else ""}">{s}</button>'
                    for s in ["open", "resolved", "suppressed", "all"])
    page = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>LeakWatch</title><style>{CSS}</style></head>
<body><main><h1>LeakWatch</h1>
<div class="sub">갱신 {e(_local(now()))} · 최근 실행: 발견 {last.get("total", 0)}, 신규 {last.get("new", 0)},
재발 {last.get("reopened", 0)}, 해결 {last.get("resolved", 0)}</div>{err_html}
<div class="tiles">{tiles}</div>
<div class="bar">{filt}<input id="q" placeholder="검색 (대상, 위치, 규칙…)"></div>
<div class="wrap"><table><thead><tr><th>심각도</th><th>내용</th><th>대상 / 위치</th><th>증거(마스킹)</th><th>상태</th><th>ID</th></tr></thead>
<tbody>{''.join(body) or '<tr><td colspan="6" class="mute">아직 발견 사항 없음</td></tr>'}</tbody></table></div>
</main><script>{JS}</script></body></html>"""
    path = cfg.data_dir / "report.html"
    path.write_text(page, "utf-8")
    return path
