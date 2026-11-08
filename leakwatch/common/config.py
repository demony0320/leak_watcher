"""TOML config (stdlib tomllib — no extra dependency in a closed network)."""
from __future__ import annotations

import fnmatch
import os
import re
import tomllib
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


class Config:
    def __init__(self, data: dict, base_dir: Path):
        self.data = data
        self.base_dir = base_dir
        g = data.get("general", {})
        self.data_dir = self.path(g.get("data_dir", "./data"))
        self.interval_minutes = int(g.get("interval_minutes", 30))
        scope = data.get("scope", {})
        self.allowed_hosts: list[str] = [h.lower() for h in scope.get("allowed_hosts", [])]
        self.http_delay = float(scope.get("request_delay_sec", 0.2))
        self.http_timeout = float(scope.get("timeout_sec", 8))

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        p = Path(path).resolve()
        with open(p, "rb") as f:
            data = tomllib.load(f)
        return cls(_expand(data), p.parent)

    def path(self, value: str) -> Path:
        p = Path(os.path.expandvars(os.path.expanduser(value)))
        return p if p.is_absolute() else (self.base_dir / p).resolve()

    def section(self, name: str) -> list[dict]:
        v = self.data.get(name, [])
        return v if isinstance(v, list) else [v]

    def get(self, name: str, default=None):
        return self.data.get(name, default)

    def check_scope(self, url: str) -> None:
        """Active probes only ever go to hosts the operator listed explicitly."""
        host = (urlparse(url).hostname or "").lower()
        if not host or not any(fnmatch.fnmatch(host, pat) for pat in self.allowed_hosts):
            raise ScopeError(f"{host!r} is not in scope.allowed_hosts — refusing to probe {url}")


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(v):
    """${VAR} / ${VAR:-default} in config strings (hosts, paths) — not for secrets, use *_env keys."""
    if isinstance(v, dict):
        return {k: _expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_expand(x) for x in v]
    if isinstance(v, str):
        return _VAR.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), v)
    return v


def secret_from(spec: dict, key: str) -> str | None:
    """Values like `token_env = "DEMO_TOKEN"` are read from the environment, never the file."""
    env = spec.get(f"{key}_env")
    return os.environ.get(env) if env else spec.get(key)
