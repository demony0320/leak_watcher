"""CI result files.

  <out>/findings.json                 machine-readable; also what `leakwatch ingest` reads
  <out>/test-results/leakwatch.xml    JUnit — Bitbucket Pipelines shows it as test results automatically
  <out>/leakwatch.sarif               SARIF 2.1.0 for IDEs / other platforms
  <out>/summary.md                    human summary (printed to the log too)
"""
from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from .. import __version__
from ..common.models import SEVERITY_RANK

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _loc(f) -> str:
    line = f.extra.get("line") or 0
    return f"{f.extra.get('path', f.location)}{':' + str(line) if line else ''}"


def write_all(result, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": _json(result, out_dir / "findings.json"),
        "junit": _junit(result, out_dir / "test-results" / "leakwatch.xml"),
        "sarif": _sarif(result, out_dir / "leakwatch.sarif"),
        "summary": _summary(result, out_dir / "summary.md"),
    }
    return paths


def _json(result, p: Path) -> Path:
    p.write_text(json.dumps({"meta": result.meta, "findings": [f.to_dict() for f in result.findings]},
                            ensure_ascii=False, indent=2), "utf-8")
    return p


def _junit(result, p: Path) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    cases = []
    for f in result.findings:
        name = quoteattr(f"[{f.severity}] {f.rule} @ {_loc(f)}")
        body = escape(f"{f.title}\n{f.evidence}\nfingerprint={f.fingerprint}")
        if f.extra.get("blocking"):
            cases.append(f'<testcase classname="leakwatch.{f.category}" name={name}>'
                         f'<failure message={quoteattr(f.title)}>{body}</failure></testcase>')
        else:
            why = "baselined" if f.extra.get("baselined") else ("existing code" if not f.extra.get("new") else "below fail_on")
            cases.append(f'<testcase classname="leakwatch.{f.category}" name={name}>'
                         f'<skipped message={quoteattr(why)}/></testcase>')
    if not result.findings:
        cases.append('<testcase classname="leakwatch" name="no leaks found"/>')
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>\n<testsuites><testsuite name="leakwatch" '
           f'tests="{max(len(result.findings), 1)}" failures="{len(result.blocking)}" '
           f'skipped="{len(result.findings) - len(result.blocking)}">' + "".join(cases) + "</testsuite></testsuites>\n")
    p.write_text(xml, "utf-8")
    return p


def _sarif(result, p: Path) -> Path:
    rules, results = {}, []
    for f in result.findings:
        rules.setdefault(f.rule, {"id": f.rule, "shortDescription": {"text": f.rule},
                                  "properties": {"category": f.category}})
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.extra.get("path", f.location)}}}
        if f.extra.get("line"):
            loc["physicalLocation"]["region"] = {"startLine": int(f.extra["line"])}
        results.append({"ruleId": f.rule, "level": SARIF_LEVEL[f.severity],
                        "message": {"text": f"{f.title} {f.evidence}".strip()},
                        "locations": [loc], "partialFingerprints": {"leakwatch/v1": f.fingerprint},
                        "properties": {"severity": f.severity, "blocking": f.extra.get("blocking", False)}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "LeakWatch", "version": __version__, "rules": list(rules.values())}},
                     "results": results}]}
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=2), "utf-8")
    return p


def summary_text(result) -> str:
    m = result.meta
    head = (f"LeakWatch CI — {m['repo']} ({m['mode']}"
            f"{', base ' + m['base'] if m.get('base') else ''}) · {m['files_scanned']} files · "
            f"{len(result.findings)} finding(s), {len(result.blocking)} blocking (fail_on={m['fail_on']})")
    lines = [head, ""]
    if result.blocking:
        lines.append("BLOCKING")
        lines += [f"  ✗ [{f.severity}] {_loc(f)} — {f.title} {f.evidence} ({f.fingerprint[:8]})" for f in result.blocking]
        lines.append("")
    rest = [f for f in result.findings if not f.extra.get("blocking")]
    if rest:
        lines.append("NON-BLOCKING")
        for f in rest[:50]:
            tag = "baselined" if f.extra.get("baselined") else ("existing" if not f.extra.get("new") else "info")
            lines.append(f"  · [{f.severity}] {_loc(f)} — {f.title} ({tag}, {f.fingerprint[:8]})")
        if len(rest) > 50:
            lines.append(f"  … {len(rest) - 50} more in findings.json")
        lines.append("")
    if result.blocking:
        lines += ["How to resolve:",
                  "  • real secret → remove it AND rotate it (it is in git history now)",
                  "  • false positive on one line → add a `leakwatch:ignore` comment on that line",
                  "  • accept existing debt → `leakwatch ci baseline` and commit .leakwatch-baseline.json"]
    return "\n".join(lines)


def _summary(result, p: Path) -> Path:
    p.write_text(summary_text(result) + "\n", "utf-8")
    return p
