"""Patched version of vulnapp.py. Each change maps to a finding in REPORT.md."""
import os, sqlite3, time, secrets
from collections import defaultdict
from flask import Flask, request, session, jsonify, abort
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET") or secrets.token_hex(32)   # F-05
DB = "lab_fixed.db"
FAILS = defaultdict(list)                                                # F-07
MAX_FAILS, WINDOW = 5, 300

def init_db():
    con = sqlite3.connect(DB); c = con.cursor()
    c.execute("DROP TABLE IF EXISTS users"); c.execute("DROP TABLE IF EXISTS notes")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, pw_hash TEXT, role TEXT)")
    c.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT)")
    c.executemany("INSERT INTO users (username,pw_hash,role) VALUES (?,?,?)",
        [("admin", generate_password_hash("admin123"), "admin"),
         ("alice", generate_password_hash("password1"), "user"),
         ("bob",   generate_password_hash("qwerty"), "user")])
    c.executemany("INSERT INTO notes (owner_id,body) VALUES (?,?)",
        [(1, "Admin note"), (2, "Alice private note"), (3, "Bob private note")])
    con.commit(); con.close()

@app.after_request
def headers(r):                                                          # F-08
    r.headers["Content-Security-Policy"] = "default-src 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    return r

@app.route("/login", methods=["POST"])
def login():
    ip, u, p = request.remote_addr, request.form.get("username", ""), request.form.get("password", "")
    now = time.time()
    FAILS[ip] = [t for t in FAILS[ip] if now - t < WINDOW]
    if len(FAILS[ip]) >= MAX_FAILS:
        return "Too many attempts", 429
    con = sqlite3.connect(DB)
    row = con.execute("SELECT id, username, role, pw_hash FROM users WHERE username=?", (u,)).fetchone()  # F-01
    if row and check_password_hash(row[3], p):
        session["uid"], session["role"] = row[0], row[2]
        return f"Welcome {escape(row[1])}"
    FAILS[ip].append(now)
    return "Invalid credentials", 401                                    # F-06 generic error

@app.route("/search")
def search():
    return f"<html><body><h1>Results for: {escape(request.args.get('q', ''))}</h1></body></html>"   # F-02

@app.route("/note/<int:note_id>")
def note(note_id):
    if "uid" not in session: abort(401)                                  # F-03
    con = sqlite3.connect(DB)
    row = con.execute("SELECT id, owner_id, body FROM notes WHERE id=?", (note_id,)).fetchone()
    if not row or (row[1] != session["uid"] and session.get("role") != "admin"):
        abort(404)
    return jsonify({"id": row[0], "body": row[2]})
# F-04: /debug route removed entirely

if __name__ == "__main__":
    init_db(); app.run(host="127.0.0.1", port=5001, debug=False)
