"""Content detectors shared by every scanner: secrets and personal data.

Each match returns (rule, category, severity, raw_value). Callers mask before storing.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class Rule:
    name: str
    category: str
    severity: str
    regex: re.Pattern
    group: int = 0
    validator: object = None  # callable(str) -> bool


def _luhn_ok(num: str) -> bool:
    if re.fullmatch(r"\d{6}[- ]?\d{7}", num.strip()):
        return False  # RRN-shaped, not a card
    digits = [int(c) for c in num if c.isdigit()]
    if not digits or digits[0] not in (3, 4, 5, 6):
        return False
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _rrn_ok(value: str) -> bool:
    """Korean resident registration number: valid date + gender digit.

    Checksum is not required (numbers issued since Oct 2020 don't follow it).
    """
    d = re.sub(r"\D", "", value)
    if len(d) != 13:
        return False
    yy, mm, dd, g = int(d[0:2]), int(d[2:4]), int(d[4:6]), d[6]
    century = {"1": 1900, "2": 1900, "5": 1900, "6": 1900,
               "3": 2000, "4": 2000, "7": 2000, "8": 2000,
               "9": 1800, "0": 1800}.get(g)
    if century is None:
        return False
    try:
        date(century + yy, mm, dd)
    except ValueError:
        return False
    return True


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _high_entropy(value: str) -> bool:
    v = value.strip("'\" ")
    if len(v) < 12 or v.lower() in {"changeme", "password", "your_api_key_here"}:
        return False
    if re.fullmatch(r"\$\{[^}]+\}|<[^>]+>|%\([^)]+\)s|\{\{[^}]+\}\}|x+|\*+", v):
        return False  # template placeholders
    return shannon_entropy(v) >= 3.3


def _plain_password(value: str) -> bool:
    v = value.strip("'\" ")
    if len(v) < 6 or re.fullmatch(r"\$\{[^}]+\}|<[^>]+>|\*+|x+|os\.environ.*|getenv.*", v, re.I):
        return False
    return v.lower() not in {"password", "changeme", "none", "null", "true", "false"}


R = re.compile
SECRET_RULES: list[Rule] = [
    Rule("secret.private_key", "secret", "critical", R(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    Rule("secret.aws_access_key", "secret", "critical", R(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("secret.azure_storage_key", "secret", "critical", R(r"AccountKey=([A-Za-z0-9+/=]{60,})"), 1),
    Rule("secret.azure_sas_token", "secret", "high", R(r"[?&]sig=([A-Za-z0-9%+/=]{30,})"), 1),
    Rule("secret.github_token", "secret", "critical", R(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    Rule("secret.slack_token", "secret", "high", R(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b")),
    Rule("secret.google_api_key", "secret", "high", R(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("secret.openai_key", "secret", "critical", R(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    Rule("secret.anthropic_key", "secret", "critical", R(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b")),
    Rule("secret.databricks_token", "secret", "critical", R(r"\bdapi[0-9a-f]{32}(?:-\d)?\b")),
    Rule("secret.huggingface_token", "secret", "high", R(r"\bhf_[A-Za-z0-9]{30,}\b")),
    Rule("secret.jwt", "secret", "medium", R(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    Rule("secret.conn_string_password", "secret", "high",
         R(r"(?i)\b(?:[a-z0-9+]+)://[^\s:/@'\"]+:([^\s@'\"]{4,})@[^\s'\"]+"), 1, _plain_password),
    Rule("secret.generic_api_key", "secret", "high",
         R(r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|signing[_-]?key)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{12,})"),
         1, _high_entropy),
    Rule("secret.password_assignment", "secret", "medium",
         R(r"(?i)\b(?:password|passwd|pwd)\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']"), 1, _plain_password),
]

PII_RULES: list[Rule] = [
    Rule("pii.kr_rrn", "pii", "critical", R(r"(?<!\d)(\d{6}[- ]?[0-9]\d{6})(?!\d)"), 1, _rrn_ok),
    Rule("pii.card_number", "pii", "critical", R(r"(?<!\d)((?:\d[ -]?){13,19})(?!\d)"), 1, _luhn_ok),
    Rule("pii.kr_mobile", "pii", "low", R(r"(?<!\d)(01[016789][- .]?\d{3,4}[- .]?\d{4})(?!\d)"), 1),
    Rule("pii.email", "pii", "low", R(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Rule("pii.kr_passport", "pii", "high", R(r"(?i)(?:passport|여권)[^\n]{0,20}?\b([MSRGD]\d{8}|[MSRGD]\d{3}[A-Z]\d{4})\b"), 1),
]

ALL_RULES = SECRET_RULES + PII_RULES  # order = priority when one value matches several rules


def scan_text(text: str, rules: list[Rule] | None = None, max_hits: int = 200):
    """Yield (rule, raw_value, start_offset)."""
    hits = 0
    for rule in rules or ALL_RULES:
        for m in rule.regex.finditer(text):
            value = m.group(rule.group)
            if rule.validator and not rule.validator(value):
                continue
            yield rule, value, m.start(rule.group)
            hits += 1
            if hits >= max_hits:
                return


def mask(value: str) -> str:
    v = value.strip()
    if "-----BEGIN" in v:
        return v[:30] + "…"
    if len(v) <= 6:
        return "*" * len(v)
    keep_head = 4 if len(v) > 12 else 2
    return v[:keep_head] + "*" * (len(v) - keep_head - 2) + v[-2:]


# ---- helpers for storage scanning --------------------------------------------------

HASH_PATTERNS = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt", True),
    (re.compile(r"^\$argon2(id|i|d)\$"), "argon2", True),
    (re.compile(r"^(pbkdf2|\$pbkdf2)[_:$-]"), "pbkdf2", True),
    (re.compile(r"^\$(5|6)\$"), "sha-crypt", True),
    (re.compile(r"^scrypt[:$]"), "scrypt", True),
    (re.compile(r"^[a-f0-9]{32}$", re.I), "md5(unsalted?)", False),
    (re.compile(r"^[a-f0-9]{40}$", re.I), "sha1(unsalted?)", False),
    (re.compile(r"^[a-f0-9]{64}$", re.I), "sha256(unsalted?)", False),
]


def classify_password_value(value: str) -> tuple[str, bool | None]:
    """Return (kind, strong). strong=None means it looks like plaintext."""
    for rx, kind, strong in HASH_PATTERNS:
        if rx.search(value):
            return kind, strong
    return "plaintext", None


PASSWORD_COLUMN = re.compile(r"(?i)(passw|passwd|pwd|pass_?word|secret|pin_?no|비밀번호)")
SENSITIVE_COLUMN = re.compile(r"(?i)(rrn|ssn|jumin|resident|주민|card_?no|card_?num|account_?no|계좌|passport|여권|door_?code|공동현관)")
