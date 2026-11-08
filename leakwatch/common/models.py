from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    """One detected leak or leak path.

    Raw secrets / personal data are never stored: `evidence` is masked and
    `evidence_hash` lets us dedup without keeping the value.
    """

    detector: str          # files | http | cloud | db | logs
    rule: str              # e.g. secret.aws_access_key, authz.idor
    category: str          # secret | pii | exposure | authz | storage | behavior | ioc
    severity: str          # critical | high | medium | low | info
    target: str            # configured target name
    location: str          # file:line, URL, table.column, client id ...
    title: str
    evidence: str = ""     # masked
    evidence_hash: str = ""
    extra: dict = field(default_factory=dict)
    dedup_key: str = ""    # optional override for fingerprint stability

    @property
    def fingerprint(self) -> str:
        key = self.dedup_key or f"{self.evidence_hash}"
        raw = "|".join([self.detector, self.rule, self.target, self.location, key])
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def value_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]
