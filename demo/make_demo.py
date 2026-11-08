"""Build demo targets under demo/work/ (all values fake):

  repo/    git repo: `main` carries old debt, branch `feature/loan-api` is a PR that adds
           new leaks — used to test `leakwatch ci scan` in full and diff (PR) mode
  app.db   SQLite with bad storage — used by the runtime db check
The runtime HTTP target is demo/leaky_app.py.
"""
import random
import shutil
import sqlite3
import subprocess
from pathlib import Path

W = Path(__file__).parent / "work"
rnd = random.Random(42)


def rrn(i):
    r = random.Random(i)
    return f"{r.randint(60, 99):02d}{r.randint(1, 12):02d}{r.randint(1, 28):02d}-{r.choice('12')}{r.randint(100000, 999999)}"


def repo():
    d = W / "repo"
    d.mkdir(parents=True)
    run = lambda *a: subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q", "-b", "main")
    run("config", "user.email", "dev@example.internal"); run("config", "user.name", "dev")

    # --- main: existing debt -------------------------------------------------------------
    (d / "settings.py").write_text('DATABRICKS_TOKEN = "dapi0123456789abcdef0123456789abcdef"\n')
    run("add", "."); run("commit", "-qm", "init")
    (d / "settings.py").write_text('import os\nDATABRICKS_TOKEN = os.environ["DATABRICKS_TOKEN"]\nDEBUG = True\n')
    run("commit", "-qam", "move token to env")                    # removed, still in history
    (d / "client.py").write_text('API_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789demo"\n'
                                 'password = "changeme"  # placeholder, ignored\n'
                                 'LEGACY = "AKIAEXAMPLEDEMOKEY01"  # leakwatch:ignore  (revoked test key)\n')
    (d / ".env").write_text("AZURE_STORAGE=DefaultEndpointsProtocol=https;AccountName=demo;AccountKey="
                            + "A" * 20 + "b9Xk2Qz7Lm4Pw8Rt6Yv3Nc1Hd5Jf0Gs" + "==" + "Kx" * 10 + ";\n")
    run("add", "."); run("commit", "-qm", "client")

    # --- feature/loan-api: the PR ----------------------------------------------------------
    run("checkout", "-qb", "feature/loan-api")
    (d / "loan_api.py").write_text('''from flask import Flask, request
import requests

app = Flask(__name__)


@app.get("/api/loans/<int:loan_no>")
def loan_status(loan_no):
    row = db.execute(f"SELECT * FROM loans WHERE no = {loan_no}")
    return row


@app.get("/api/me")
def me():
    user = get_current_user()
    return user.profile


def call_partner(token):
    print("calling partner with token", token)
    return requests.get("https://partner.internal/api", verify=False,
                        headers={"Authorization": "Bearer " + token})
''')
    (d / "tests").mkdir()
    (d / "tests" / "fixtures.csv").write_text(
        "name,rrn,card\n" + "\n".join(f"고객{i},{rrn(i)},4111111111111111" for i in range(1, 6)) + "\n",
        encoding="utf-8")
    run("add", "."); run("commit", "-qm", "loan api")
    (d / "deploy.sh").write_text('export GH_TOKEN="ghp_' + "Z9" * 18 + '"\n')
    run("add", "."); run("commit", "-qm", "deploy helper")
    (d / "deploy.sh").write_text('export GH_TOKEN="${GH_TOKEN:?}"\n')
    run("commit", "-qam", "oops, use env var")                   # added then removed inside the PR


def db():
    c = sqlite3.connect(W / "app.db")
    c.execute("CREATE TABLE users(id INTEGER, login TEXT, password TEXT, email TEXT)")
    c.execute("CREATE TABLE admins(id INTEGER, login TEXT, pwd_hash TEXT)")
    c.execute("CREATE TABLE customers(id INTEGER, name TEXT, jumin_no TEXT, card_no TEXT, memo TEXT)")
    c.execute("CREATE TABLE customers_secure(id INTEGER, rrn_enc TEXT)")
    for i in range(1, 101):
        c.execute("INSERT INTO users VALUES (?,?,?,?)", (i, f"user{i}", f"Pass{i}word!", f"user{i}@example.internal"))
        c.execute("INSERT INTO admins VALUES (?,?,?)", (i, f"adm{i}", f"{rnd.getrandbits(128):032x}"))
        c.execute("INSERT INTO customers VALUES (?,?,?,?,?)", (i, f"고객{i}", rrn(i), "4111111111111111", "VIP"))
        c.execute("INSERT INTO customers_secure VALUES (?,?)", (i, f"gAAAAAB{rnd.getrandbits(256):064x}"))
    c.commit(); c.close()


if __name__ == "__main__":
    shutil.rmtree(W, ignore_errors=True)
    W.mkdir(parents=True)
    repo(); db()
    print(f"demo targets ready in {W}")
    print("  repo branches: main (existing debt), feature/loan-api (PR with new leaks)")
