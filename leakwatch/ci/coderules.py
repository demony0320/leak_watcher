"""Lightweight code rules for leak paths that secret/PII patterns can't see.

They are heuristics meant for review, not proof — severities are medium/low by
default so they don't block a merge unless a team raises them in .leakwatch.toml.
Teams add their own rules ([[ci.rules]]) when runtime finds something new — that is
the runtime → CI feedback path.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".cs", ".go", ".php", ".rb", ".scala"}
CONFIG_EXT = {".py", ".env", ".ini", ".cfg", ".toml", ".yaml", ".yml", ".json", ".properties", ".xml", ".conf"}


@dataclass
class CodeRule:
    id: str
    severity: str
    category: str
    message: str
    pattern: re.Pattern
    globs: tuple = ("*",)
    exts: frozenset = frozenset()


R = re.compile
BUILTIN: list[CodeRule] = [
    CodeRule("code.tls_verify_disabled", "medium", "exposure",
             "TLS certificate verification disabled — traffic (and credentials) can be intercepted",
             R(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
               r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|ServerCertificateValidationCallback\s*=.*=>\s*true|"
               r"ssl\._create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
             exts=frozenset(CODE_EXT)),
    CodeRule("code.debug_enabled", "medium", "exposure",
             "Debug mode enabled — stack traces and config can leak in responses",
             R(r"(?m)^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|"
               r"UseDeveloperExceptionPage\(\)|display_errors\s*=\s*On"),
             exts=frozenset(CODE_EXT | CONFIG_EXT)),
    CodeRule("code.secret_logged", "medium", "secret",
             "Sensitive value written to logs/stdout",
             R(r"(?i)(?:print|console\.(?:log|error|info)|log(?:ger)?\.(?:debug|info|warn(?:ing)?|error)|"
               r"System\.out\.println|fmt\.Print\w*)\s*\([^)\n]*\b(?:password|passwd|secret|api_?key|token|"
               r"authorization|credential|jumin|rrn|card_?no)\b"),
             exts=frozenset(CODE_EXT)),
    CodeRule("code.sql_string_build", "medium", "authz",
             "SQL built from request input by string formatting — injection can dump whole tables",
             R(r"(?i)(?:execute|query|raw|executeQuery|createQuery)\s*\(\s*(?:f[\"']|[\"'][^\"']*(?:select|update|delete|insert)"
               r"[^\"']*[\"']\s*(?:\+|%|\.format))"),
             exts=frozenset(CODE_EXT)),
    CodeRule("code.cors_any_origin_credentials", "high", "exposure",
             "CORS allows any origin together with credentials",
             R(r"(?is)(?:origin\s*[:=]\s*['\"]?\*|allow_origins\s*=\s*\[\s*['\"]\*).{0,200}credentials\s*[:=]\s*(?:true|True)"),
             exts=frozenset(CODE_EXT)),
]

# Routes that take an object id. The handler body is then checked for any sign of an
# ownership / authentication check (Shinhan 2026: lookup by customer number, no owner check).
ROUTE_WITH_ID = R(
    r"""(?x)
    @(?:\w+\.)?(?:route|get|post|put|delete|patch|api_route)\(\s*['"][^'"]*(?:<[^>]*(?:id|no|num)[^>]*>|\{[^}]*(?:id|no|num)[^}]*\})  # Flask/FastAPI
  | \b(?:app|router)\.(?:get|post|put|delete|patch)\(\s*['"`][^'"`]*:\w*(?:id|Id|no|No)\b                                          # Express
  | @(?:Get|Post|Put|Delete|Patch|Request)Mapping\([^)]*\{\w*(?:id|Id|no|No)\}                                                     # Spring
  | \[Http(?:Get|Post|Put|Delete|Patch)\(\s*"[^"]*\{\w*(?:id|Id|no|No)[^}]*\}                                                      # ASP.NET
    """, re.I)
AUTH_HINT = R(r"(?i)current_user|request\.user|g\.user|get_current_user|Depends\(|req\.user|principal|"
              r"@PreAuthorize|@Secured|\[Authorize|User\.Identity|ClaimsPrincipal|login_required|permission|"
              r"owner|user_?id\s*(?:==|!=|=)|\.userId|session\[|authorize|check_access|has_access|tenant")


TOP_LEVEL_START = re.compile(r"^(?:@|def |async def |class |function |export |app\.|router\.|\[Http|public |private )")


def _handler_block(lines: list[str], i: int, max_lines: int = 40) -> list[str]:
    """Decorators/annotations directly above the route line + the handler, up to the next
    top-level declaration (so a neighbouring handler's auth check doesn't hide this one)."""
    start = i
    while start > 0 and lines[start - 1].lstrip().startswith(("@", "[")):
        start -= 1
    end, seen_body = i + 1, False
    while end < len(lines) and end < i + max_lines:
        cur = lines[end]
        if cur.strip() and not cur[0].isspace():
            if seen_body and TOP_LEVEL_START.match(cur):
                break
            if cur.startswith(("def ", "async def ", "function ", "public ", "private ")) or "=>" in cur:
                seen_body = True
        elif cur.strip():
            seen_body = True
        end += 1
    return lines[start:end]


def _custom(rules: list[dict]) -> list[CodeRule]:
    out = []
    for r in rules:
        out.append(CodeRule(r["id"] if r["id"].startswith("code.") else "code." + r["id"],
                            r.get("severity", "medium"), r.get("category", "exposure"), r.get("message", r["id"]),
                            re.compile(r["pattern"]), tuple(r.get("globs", ["*"]))))
    return out


def scan_file(rel: str, text: str, custom: list[dict] | None = None, disabled: set[str] | None = None):
    """Yield (rule_id, severity, category, message, line_no)."""
    disabled = disabled or set()
    ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
    lines = text.splitlines()
    for rule in BUILTIN + _custom(custom or []):
        if rule.id in disabled:
            continue
        if rule.exts and ext not in rule.exts:
            continue
        if not any(fnmatch.fnmatch(rel, g) for g in rule.globs):
            continue
        for m in rule.pattern.finditer(text):
            yield rule.id, rule.severity, rule.category, rule.message, text.count("\n", 0, m.start()) + 1

    if "code.idor_review" in disabled or ext not in CODE_EXT:
        return
    for i, ln in enumerate(lines):
        if ROUTE_WITH_ID.search(ln):
            body = "\n".join(_handler_block(lines, i))
            if not AUTH_HINT.search(body):
                yield ("code.idor_review", "medium", "authz",
                       "Endpoint takes an object id but no owner/auth check is visible — verify server-side authorization",
                       i + 1)
