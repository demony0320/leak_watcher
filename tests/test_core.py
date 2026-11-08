import json
import logging
import subprocess
import tempfile
import unittest
from pathlib import Path

from leakwatch.ci import coderules
from leakwatch.ci.scan import CIOptions, run
from leakwatch.common.config import Config, ScopeError
from leakwatch.common.models import Finding
from leakwatch.common.patterns import classify_password_value, mask, scan_text
from leakwatch.common.store import Store
from leakwatch.runtime import ingest

log = logging.getLogger("test")


def rules_hit(text):
    return {r.name for r, _, _ in scan_text(text)}


class Patterns(unittest.TestCase):
    def test_rrn(self):
        self.assertIn("pii.kr_rrn", rules_hit("주민번호 900101-1234567"))
        self.assertNotIn("pii.kr_rrn", rules_hit("order 991399-1234567"))

    def test_card_luhn_and_not_rrn(self):
        self.assertIn("pii.card_number", rules_hit("card 4111 1111 1111 1111"))
        self.assertNotIn("pii.card_number", rules_hit("4111 1111 1111 1112"))
        self.assertNotIn("pii.card_number", rules_hit("600101-1123456"))

    def test_secrets_and_placeholders(self):
        self.assertIn("secret.aws_access_key", rules_hit("key=AKIAEXAMPLEDEMOKEY01"))
        self.assertNotIn("secret.password_assignment", rules_hit('password = "changeme"'))
        self.assertNotIn("secret.generic_api_key", rules_hit("api_key = ${API_KEY_FROM_VAULT}"))

    def test_mask_and_hash_classification(self):
        self.assertNotEqual(mask("AKIAEXAMPLEDEMOKEY01"), "AKIAEXAMPLEDEMOKEY01")
        self.assertIsNone(classify_password_value("hunter2")[1])
        self.assertFalse(classify_password_value("5f4dcc3b5aa765d61d8327deb882cf99")[1])


class CodeRules(unittest.TestCase):
    def ids(self, rel, text, custom=None):
        return [r[0] for r in coderules.scan_file(rel, text, custom)]

    def test_idor_review_is_per_handler(self):
        src = ('@app.get("/loans/<int:loan_no>")\ndef a(loan_no):\n    return db.get(loan_no)\n\n\n'
               '@app.get("/me")\ndef b():\n    return get_current_user()\n')
        self.assertIn("code.idor_review", self.ids("api.py", src))
        safe = '@app.get("/loans/<int:loan_no>")\ndef a(loan_no, user=Depends(get_current_user)):\n    return 1\n'
        self.assertNotIn("code.idor_review", self.ids("api.py", safe))

    def test_builtin_and_custom(self):
        self.assertIn("code.tls_verify_disabled", self.ids("c.py", "requests.get(u, verify=False)"))
        self.assertIn("code.debug_enabled", self.ids("settings.py", "import os\nDEBUG = True\n"))
        rule = [{"id": "no-legacy", "pattern": r"legacy_export\(", "severity": "high"}]
        self.assertIn("code.no-legacy", self.ids("x.py", "legacy_export(all)", rule))


class CIDiff(unittest.TestCase):
    def test_pr_blocks_only_new_and_history(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)  # noqa: E731
            git("init", "-q", "-b", "main"); git("config", "user.email", "t@t"); git("config", "user.name", "t")
            (repo / "old.py").write_text('KEY = "sk-proj-' + "a1" * 20 + '"\n')
            git("add", "."); git("commit", "-qm", "old debt")
            git("checkout", "-qb", "pr")
            (repo / "new.py").write_text('T = "AKIAEXAMPLEDEMOKEY02"\nx = 1  # AKIAEXAMPLEDEMOKEY03 leakwatch:ignore\n')
            (repo / "tmp.sh").write_text('export GH="ghp_' + "Q7" * 18 + '"\n')
            git("add", "."); git("commit", "-qm", "pr1")
            (repo / "tmp.sh").write_text("export GH=$GH\n")
            git("commit", "-qam", "pr2")
            res = run(CIOptions(repo=repo, mode="diff", base="main", use_gitleaks="off"), log)
            blocking = {(f.rule, f.extra["path"]) for f in res.blocking}
            self.assertIn(("secret.aws_access_key", "new.py"), blocking)
            self.assertIn(("secret.github_token.history", "tmp.sh"), blocking)
            self.assertFalse(any(f.extra["path"] == "old.py" for f in res.findings))  # untouched file
            self.assertEqual(sum(f.rule == "secret.aws_access_key" for f in res.findings), 1)  # ignore marker


class Scope(unittest.TestCase):
    def test_out_of_scope_refused(self):
        cfg = Config({"scope": {"allowed_hosts": ["*.corp.internal"]}}, Path("."))
        cfg.check_scope("https://app.corp.internal/x")
        with self.assertRaises(ScopeError):
            cfg.check_scope("https://example.com/")


class Lifecycle(unittest.TestCase):
    def _f(self):
        return Finding("http", "authz.idor", "authz", "critical", "app", "/x", "idor", dedup_key="/x")

    def test_new_resolve_reopen_suppress(self):
        with tempfile.TemporaryDirectory() as d:
            s, f, sc = Store(Path(d)), self._f(), {("http", "app")}
            self.assertEqual(len(s.ingest([f], {"http": True}, sc)[0]), 1)
            self.assertEqual(s.ingest([f], {"http": True}, sc)[0], [])
            self.assertEqual(len(s.ingest([], {"http": True}, sc)[3]), 1)
            self.assertEqual(len(s.ingest([f], {"http": True}, sc)[1]), 1)
            s.add_suppression(fingerprint=f.fingerprint, reason="fp")
            s.ingest([], {"http": True}, sc)
            self.assertEqual(s.ingest([f], {"http": True}, sc)[:2], ([], []))

    def test_unreachable_target_not_resolved(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d))
            s.ingest([self._f()], {"http": True}, {("http", "app")})
            self.assertEqual(s.ingest([], {"http": True}, set())[3], [])

    def test_ci_ingest_full_resolves_diff_does_not(self):
        with tempfile.TemporaryDirectory() as d:
            s = Store(Path(d))
            f = Finding("ci", "secret.aws_access_key", "secret", "critical", "r", "a.py", "t", evidence_hash="h1")
            doc = lambda mode, fs: {"meta": {"repo": "r", "mode": mode}, "findings": [x.to_dict() for x in fs]}  # noqa: E731
            p = Path(d) / "f.json"
            p.write_text(json.dumps(doc("full", [f])))
            self.assertEqual(len(ingest.ingest_file(s, p, log)[0]), 1)
            p.write_text(json.dumps(doc("diff", [])))
            self.assertEqual(ingest.ingest_file(s, p, log)[3], [])      # partial view → no resolve
            p.write_text(json.dumps(doc("full", [])))
            self.assertEqual(len(ingest.ingest_file(s, p, log)[3]), 1)  # full view → resolved


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    unittest.main()
