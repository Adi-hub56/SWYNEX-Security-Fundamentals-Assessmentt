"""
Intentionally vulnerable training app. For local lab use ONLY (127.0.0.1).
Do NOT deploy. Vulnerabilities are deliberate and are documented in REPORT.md.
"""
import sqlite3
from flask import Flask, request, session, redirect, jsonify, make_response

app = Flask(__name__)
app.secret_key = "supersecret123"          # hardcoded secret (F-05)

DB = "lab.db"

def init_db():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS notes")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    c.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, body TEXT)")
    c.executemany("INSERT INTO users (username,password,role) VALUES (?,?,?)",
                  [("admin", "admin123", "admin"), ("alice", "password1", "user"), ("bob", "qwerty", "user")])
    c.executemany("INSERT INTO notes (owner_id,body) VALUES (?,?)",
                  [(1, "Admin note: backup key is K-9921"), (2, "Alice private note"), (3, "Bob private note")])
    con.commit(); con.close()

@app.route("/")
def index():
    return "Training app. Routes: /login /search /note/<id> /debug"

@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    con = sqlite3.connect(DB)
    # F-01: string-built SQL query -> SQL injection
    q = f"SELECT id, username, role FROM users WHERE username='{u}' AND password='{p}'"
    try:
        row = con.execute(q).fetchone()
    except Exception as e:
        return f"SQL error: {e}", 500       # F-06: verbose error disclosure
    if row:
        session["uid"], session["user"], session["role"] = row
        return f"Welcome {row[1]} (role={row[2]})"
    return "Invalid credentials", 401       # F-07: no rate limiting / lockout

@app.route("/search")
def search():
    term = request.args.get("q", "")
    # F-02: user input reflected without output encoding -> reflected XSS
    return f"<html><body><h1>Results for: {term}</h1></body></html>"

@app.route("/note/<int:note_id>")
def note(note_id):
    con = sqlite3.connect(DB)
    # F-03: no ownership check -> IDOR / broken access control
    row = con.execute("SELECT id, owner_id, body FROM notes WHERE id=?", (note_id,)).fetchone()
    if not row:
        return "Not found", 404
    return jsonify({"id": row[0], "owner_id": row[1], "body": row[2]})

@app.route("/debug")
def debug():
    # F-04: sensitive config exposed without authentication
    return jsonify({"secret_key": app.secret_key, "db": DB, "env": "development"})

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
