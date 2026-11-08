"""A deliberately leaky internal app for testing LeakWatch. Do NOT expose it.

  /api/me                         requires Bearer token (correct)
  /api/customers?id=<n>           requires token but no owner check  → IDOR
  /api/loan-status?customerNo=<n> no auth at all                      → missing auth
  /.env                           exposed config with secrets
  /test                           leftover test page
  /bucket/?restype=container&comp=list   public blob container listing

Run:  python demo/leaky_app.py  (port 8088)
"""
import json
import os
import random
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TOKEN = os.environ.get("DEMO_TOKEN", "demo-user-token-1001")
FIXED = os.environ.get("FIXED", "") == "1"   # FIXED=1 → leaks patched, to test auto-resolve


def person(cid: int) -> dict:
    rnd = random.Random(cid)
    yy, mm, dd = rnd.randint(60, 99), rnd.randint(1, 12), rnd.randint(1, 28)
    return {"customerNo": cid, "name": f"고객{cid}", "phone": f"010-{rnd.randint(1000, 9999)}-{rnd.randint(1000, 9999)}",
            "rrn": f"{yy:02d}{mm:02d}{dd:02d}-{rnd.choice('12')}{rnd.randint(100000, 999999)}",
            "income": rnd.randint(3000, 9000) * 10000}


class H(BaseHTTPRequestHandler):
    server_version = "DemoApp/1.4.2"

    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "Express 4.17.1")
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def do_GET(self):  # noqa: N802
        u = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/":
            return self.send(200, "<html><body>Demo internal app</body></html>", "text/html")
        if u.path == "/.env" and not FIXED:
            return self.send(200, "DB_URL=postgres://app:Sup3rS3cret!@db.internal:5432/core\n"
                                  "AWS_ACCESS_KEY_ID=AKIAEXAMPLEDEMOKEY01\nSIGNING_KEY=q8Xz2LmP9vRt4KwN7bYc\n", "text/plain")
        if u.path == "/test" and not FIXED:
            return self.send(200, "<html>retail test page — no auth</html>", "text/html")
        if u.path == "/api/me":
            if not self.authed():
                return self.send(401, '{"error":"unauthorized"}')
            return self.send(200, json.dumps(person(1001), ensure_ascii=False))
        if u.path == "/api/customers":
            if not self.authed():
                return self.send(401, '{"error":"unauthorized"}')
            cid = int(q.get("id", "0") or 0)
            if FIXED and cid != 1001:
                return self.send(403, '{"error":"forbidden"}')
            return self.send(200, json.dumps(person(cid), ensure_ascii=False))
        if u.path == "/api/loan-status":
            if FIXED and not self.authed():
                return self.send(401, '{"error":"unauthorized"}')
            cid = int(q.get("customerNo", "0") or 0)
            return self.send(200, json.dumps({**person(cid), "loanLimit": 50_000_000}, ensure_ascii=False))
        if u.path == "/bucket/" and q.get("comp") == "list" and not FIXED:
            return self.send(200, "<?xml version='1.0'?><EnumerationResults><Blobs>"
                                  "<Blob><Name>export/customers_2026.csv</Name></Blob>"
                                  "<Blob><Name>backup/core.bak</Name></Blob></Blobs></EnumerationResults>",
                             "application/xml")
        return self.send(404, '{"error":"not found"}')


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8088))
    print(f"leaky demo app on :{port} (FIXED={FIXED})")
    ThreadingHTTPServer(("0.0.0.0", port), H).serve_forever()
