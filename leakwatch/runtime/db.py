"""Sample database columns for plaintext personal data, secrets and weak password storage.

SQLite works out of the box. Other engines (PostgreSQL, MySQL, MSSQL, Oracle, Databricks SQL)
use SQLAlchemy URLs if `sqlalchemy` and the driver are installed. Read-only: SELECT ... LIMIT n.
Use a read-only DB account.
"""
from __future__ import annotations

import re
import sqlite3

from ..common.config import secret_from
from ..common.models import Finding, value_hash
from ..common.patterns import (ALL_RULES, PASSWORD_COLUMN, SENSITIVE_COLUMN, classify_password_value,
                        mask, scan_text)

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$.]*$")


class _Conn:
    def __init__(self, url: str):
        self.kind = "sqlite" if url.startswith("sqlite:///") else "sqla"
        if self.kind == "sqlite":
            path = url[len("sqlite:///"):]
            self.c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        else:
            try:
                import sqlalchemy as sa  # optional
            except ImportError as e:
                raise RuntimeError("pip install sqlalchemy + driver to scan non-SQLite databases") from e
            self.sa = sa
            self.engine = sa.create_engine(url)
            self.c = self.engine.connect()

    def tables(self) -> dict[str, list[str]]:
        if self.kind == "sqlite":
            names = [r[0] for r in self.c.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            return {t: [r[1] for r in self.c.execute(f'PRAGMA table_info("{t}")')] for t in names}
        insp = self.sa.inspect(self.engine)
        out = {}
        for schema in [None]:
            for t in insp.get_table_names(schema=schema):
                out[t] = [c["name"] for c in insp.get_columns(t, schema=schema)]
        return out

    def sample(self, table: str, column: str, n: int) -> list[str]:
        if not (IDENT.match(table) and IDENT.match(column)):
            return []
        q = f'SELECT "{column}" FROM "{table}" WHERE "{column}" IS NOT NULL LIMIT {int(n)}'
        if self.kind == "sqlite":
            rows = self.c.execute(q).fetchall()
        else:
            rows = self.c.execute(self.sa.text(q)).fetchall()
        return [str(r[0]) for r in rows if r[0] is not None]

    def close(self):
        self.c.close()


def scan(cfg, log, scanned: set | None = None) -> list[Finding]:
    scanned = scanned if scanned is not None else set()
    out: list[Finding] = []
    for spec in cfg.section("db"):
        name = spec["name"]
        url = secret_from(spec, "url")
        if url and url.startswith("sqlite:///") and not url.startswith("sqlite:////"):
            url = "sqlite:///" + str(cfg.path(url[len("sqlite:///"):]))
        try:
            conn = _Conn(url)
        except Exception as e:  # noqa: BLE001 — report and continue with other targets
            log.error("db[%s]: cannot connect: %s", name, e)
            continue
        scanned.add(("db", name))
        n = int(spec.get("sample_rows", 200))
        include = spec.get("tables")
        try:
            for table, cols in conn.tables().items():
                if include and table not in include:
                    continue
                for col in cols:
                    try:
                        values = conn.sample(table, col, n)
                    except Exception as e:  # noqa: BLE001
                        log.debug("db[%s]: %s.%s skipped: %s", name, table, col, e)
                        continue
                    out.extend(_check_column(name, table, col, values))
        finally:
            conn.close()
    return out


def _check_column(target: str, table: str, col: str, values: list[str]) -> list[Finding]:
    loc = f"{table}.{col}"
    out = []
    if not values:
        return out
    if PASSWORD_COLUMN.search(col):
        kinds = [classify_password_value(v) for v in values]
        plain = sum(1 for _, strong in kinds if strong is None)
        weak = sum(1 for _, strong in kinds if strong is False)
        if plain:
            out.append(Finding("db", "storage.plaintext_password", "storage", "critical", target, loc,
                               f"Passwords stored in plaintext ({plain}/{len(values)} sampled rows)",
                               mask(next(v for v, (_, s) in zip(values, kinds) if s is None)),
                               dedup_key="plain", extra={"sampled": len(values), "plaintext": plain}))
        elif weak:
            kind = next(k for k, s in kinds if s is False)
            out.append(Finding("db", "storage.weak_password_hash", "storage", "high", target, loc,
                               f"Passwords hashed with {kind} ({weak}/{len(values)} rows) — use bcrypt/argon2",
                               dedup_key="weak"))
        return out

    hits: dict[str, set] = {}
    secret_hits = []
    for v in values:
        for rule, val, _ in scan_text(v[:5000], ALL_RULES, max_hits=5):
            if rule.category == "pii":
                hits.setdefault(rule.name, set()).add(value_hash(val))
            elif len(secret_hits) < 3:
                secret_hits.append((rule, val))
    for rname, hs in hits.items():
        rule = next(r for r in ALL_RULES if r.name == rname)
        ratio = len(hs) / len(values)
        if rule.severity == "low" and ratio < 0.2:
            continue  # occasional email/phone inside free text — not the column's purpose
        out.append(Finding("db", f"storage.plaintext_{rname.split('.', 1)[1]}", "storage",
                           "critical" if rule.severity == "critical" else "medium", target, loc,
                           f"Unencrypted {rname.split('.', 1)[1]} in column ({len(hs)} distinct values in {len(values)} sampled rows)",
                           f"ratio={ratio:.0%}", dedup_key=rname, extra={"sampled": len(values)}))
    for rule, val in secret_hits:
        out.append(Finding("db", rule.name, "secret", rule.severity, target, loc,
                           f"{rule.name.split('.', 1)[1]} stored in column", mask(val), value_hash(val)))
    if not out and SENSITIVE_COLUMN.search(col):
        # column name says sensitive but values didn't match → probably encrypted; note for review
        out.append(Finding("db", "storage.sensitive_column_review", "storage", "info", target, loc,
                           "Sensitive-looking column; values don't match plaintext patterns (verify encryption)",
                           dedup_key="review"))
    return out
