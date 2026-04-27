# license_server.py
# PIKA License Server PRO for Render
# Admin: /admin?token=YOUR_ADMIN_TOKEN
# Client API: /api/activate

from __future__ import annotations

import os
import sqlite3
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request, url_for

APP = Flask(__name__)

DB_PATH = os.environ.get("LICENSE_DB", "license.db")
ADMIN_TOKEN = os.environ.get("PIKA_ADMIN_TOKEN", os.environ.get("ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN"))
APP_ID = os.environ.get("PIKA_APP_ID", "PIKA_TOOL")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utc_now()).isoformat()


def parse_iso(value: str | None):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        app_id TEXT NOT NULL DEFAULT 'PIKA_TOOL',
        status TEXT NOT NULL DEFAULT 'active',
        max_devices INTEGER NOT NULL DEFAULT 1,
        expires_at TEXT,
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL,
        device_id TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        user_agent TEXT,
        ip TEXT,
        UNIQUE(license_key, device_id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        license_key TEXT,
        event TEXT NOT NULL,
        device_id TEXT,
        ip TEXT,
        user_agent TEXT,
        message TEXT
    )
    """)

    con.commit()
    con.close()


def make_key(prefix: str = "PIKA") -> str:
    alphabet = string.ascii_uppercase + string.digits
    parts = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4)]
    return prefix + "-" + "-".join(parts)


def client_ip() -> str:
    return (request.headers.get("x-forwarded-for") or request.remote_addr or "").split(",")[0].strip()


def ua() -> str:
    return request.headers.get("user-agent", "")


def log_event(license_key: str | None, event: str, device_id: str = "", message: str = ""):
    con = db()
    con.execute(
        "INSERT INTO events(created_at, license_key, event, device_id, ip, user_agent, message) VALUES(?,?,?,?,?,?,?)",
        (iso(), license_key, event, device_id, client_ip(), ua(), message),
    )
    con.commit()
    con.close()


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.args.get("token") or request.form.get("token") or ""
        if token != ADMIN_TOKEN:
            return "Unauthorized. Add ?token=YOUR_ADMIN_TOKEN", 401
        return fn(*args, **kwargs)
    return wrapper


@APP.route("/")
def home():
    return jsonify(ok=True, app="PIKA License Server PRO", admin="/admin?token=YOUR_ADMIN_TOKEN")


@APP.route("/health")
def health():
    return jsonify(ok=True, time=iso())


@APP.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.get_json(force=True, silent=True) or {}

    license_key = str(data.get("license_key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()
    app_id = str(data.get("app") or data.get("app_id") or APP_ID).strip()

    if not license_key or not device_id:
        log_event(license_key or None, "bad_request", device_id, "missing license_key/device_id")
        return jsonify(ok=False, message="Missing license_key or device_id"), 400

    con = db()
    lic = con.execute("SELECT * FROM licenses WHERE license_key=?", (license_key,)).fetchone()

    if not lic:
        con.close()
        log_event(license_key, "invalid_key", device_id)
        return jsonify(ok=False, message="Key không tồn tại"), 403

    if lic["app_id"] != app_id and lic["app_id"] != APP_ID:
        con.close()
        log_event(license_key, "wrong_app", device_id, f"app={app_id}")
        return jsonify(ok=False, message="Key không đúng app"), 403

    if lic["status"] != "active":
        con.close()
        log_event(license_key, "blocked", device_id)
        return jsonify(ok=False, message="Key đã bị khóa"), 403

    exp = parse_iso(lic["expires_at"])
    if exp and exp < utc_now():
        con.execute("UPDATE licenses SET status='expired', updated_at=? WHERE license_key=?", (iso(), license_key))
        con.commit()
        con.close()
        log_event(license_key, "expired", device_id)
        return jsonify(ok=False, message="Key đã hết hạn"), 403

    existing = con.execute(
        "SELECT * FROM devices WHERE license_key=? AND device_id=?",
        (license_key, device_id)
    ).fetchone()

    device_count = con.execute(
        "SELECT COUNT(*) AS c FROM devices WHERE license_key=?",
        (license_key,)
    ).fetchone()["c"]

    if not existing and device_count >= int(lic["max_devices"]):
        con.close()
        log_event(license_key, "device_limit", device_id, f"limit={lic['max_devices']}")
        return jsonify(ok=False, message="Key đã đạt giới hạn số máy"), 403

    if existing:
        con.execute(
            "UPDATE devices SET last_seen=?, ip=?, user_agent=? WHERE id=?",
            (iso(), client_ip(), ua(), existing["id"])
        )
        event = "checked"
    else:
        con.execute(
            "INSERT INTO devices(license_key, device_id, first_seen, last_seen, ip, user_agent) VALUES(?,?,?,?,?,?)",
            (license_key, device_id, iso(), iso(), client_ip(), ua())
        )
        event = "activated"

    con.commit()
    con.close()
    log_event(license_key, event, device_id)

    return jsonify(
        ok=True,
        message="License OK",
        status=lic["status"],
        expires_at=lic["expires_at"],
        max_devices=lic["max_devices"],
    )


@APP.route("/admin")
@require_admin
def admin():
    token = request.args.get("token", "")
    con = db()

    keys = con.execute("""
        SELECT l.*,
               (SELECT COUNT(*) FROM devices d WHERE d.license_key=l.license_key) AS device_count
        FROM licenses l
        ORDER BY l.created_at DESC
    """).fetchall()

    events = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 80").fetchall()
    con.close()

    html = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PIKA License Admin PRO</title>
<style>
body{font-family:Arial,sans-serif;background:#08111f;color:#e5eefc;margin:0;padding:24px}
h1{font-size:34px;margin:0 0 18px}
.card{background:#111c33;border:1px solid #263653;border-radius:16px;padding:18px;margin:16px 0;box-shadow:0 12px 28px rgba(0,0,0,.25)}
input,select,button{padding:10px;border-radius:10px;border:1px solid #334155;background:#0f172a;color:#e5eefc}
button{background:#38bdf8;color:#06111f;font-weight:bold;cursor:pointer}
table{width:100%;border-collapse:collapse;margin-top:12px}
th,td{border-bottom:1px solid #263653;padding:10px;font-size:13px;vertical-align:top}
th{text-align:left;color:#93c5fd}
code{background:#020617;padding:4px 7px;border-radius:8px;color:#facc15}
a{color:#67e8f9;text-decoration:none}
.badge{padding:4px 8px;border-radius:999px;font-weight:bold;font-size:12px}
.active{background:#14532d;color:#86efac}.blocked{background:#7f1d1d;color:#fecaca}.expired{background:#713f12;color:#fde68a}
.small{color:#94a3b8;font-size:12px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
</style>
</head>
<body>
<h1>⚡ PIKA License Admin PRO</h1>
<div class="small">Server OK · App: {{ app_id }}</div>

<div class="card">
<h2>Create Key</h2>
<form method="post" action="/admin/create">
<input type="hidden" name="token" value="{{ token }}">
<div class="row">
<label>Expire days <input name="days" value="30" size="6"></label>
<label>Max devices <input name="max_devices" value="1" size="6"></label>
<label>Note <input name="note" placeholder="customer name / memo" size="30"></label>
<button>Create</button>
</div>
</form>
</div>

<div class="card">
<h2>Keys</h2>
<table>
<tr><th>Key</th><th>Status</th><th>Expire</th><th>Devices</th><th>Note</th><th>Actions</th></tr>
{% for k in keys %}
<tr>
<td><code>{{ k.license_key }}</code></td>
<td><span class="badge {{ k.status }}">{{ k.status }}</span></td>
<td>{{ k.expires_at or "" }}</td>
<td>{{ k.device_count }} / {{ k.max_devices }}</td>
<td>{{ k.note or "" }}</td>
<td>
<a href="/admin/devices?token={{ token }}&key={{ k.license_key }}">devices</a> |
<a href="/admin/reset?token={{ token }}&key={{ k.license_key }}">reset</a> |
<a href="/admin/block?token={{ token }}&key={{ k.license_key }}">block</a> |
<a href="/admin/unblock?token={{ token }}&key={{ k.license_key }}">unblock</a> |
<a href="/admin/delete?token={{ token }}&key={{ k.license_key }}" onclick="return confirm('Delete key?')">delete</a>
</td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h2>Recent Events</h2>
<table>
<tr><th>Time</th><th>Key</th><th>Event</th><th>Device</th><th>IP</th><th>Message</th></tr>
{% for e in events %}
<tr>
<td>{{ e.created_at }}</td><td><code>{{ e.license_key or "" }}</code></td><td>{{ e.event }}</td>
<td>{{ e.device_id or "" }}</td><td>{{ e.ip or "" }}</td><td>{{ e.message or "" }}</td>
</tr>
{% endfor %}
</table>
</div>
</body>
</html>
"""
    return render_template_string(html, token=token, keys=keys, events=events, app_id=APP_ID)


@APP.route("/admin/create", methods=["POST"])
@require_admin
def admin_create():
    token = request.form.get("token", "")
    days = int(request.form.get("days") or 30)
    max_devices = int(request.form.get("max_devices") or 1)
    note = request.form.get("note", "")
    license_key = make_key()
    expires_at = iso(utc_now() + timedelta(days=days)) if days > 0 else None

    con = db()
    con.execute("""
        INSERT INTO licenses(license_key, app_id, status, max_devices, expires_at, note, created_at, updated_at)
        VALUES(?,?,?,?,?,?,?,?)
    """, (license_key, APP_ID, "active", max_devices, expires_at, note, iso(), iso()))
    con.commit()
    con.close()

    log_event(license_key, "created", "", f"days={days}, max_devices={max_devices}")
    return redirect(f"/admin?token={token}")


@APP.route("/admin/block")
@require_admin
def admin_block():
    token = request.args.get("token", "")
    key = request.args.get("key", "")
    con = db()
    con.execute("UPDATE licenses SET status='blocked', updated_at=? WHERE license_key=?", (iso(), key))
    con.commit()
    con.close()
    log_event(key, "admin_block")
    return redirect(f"/admin?token={token}")


@APP.route("/admin/unblock")
@require_admin
def admin_unblock():
    token = request.args.get("token", "")
    key = request.args.get("key", "")
    con = db()
    con.execute("UPDATE licenses SET status='active', updated_at=? WHERE license_key=?", (iso(), key))
    con.commit()
    con.close()
    log_event(key, "admin_unblock")
    return redirect(f"/admin?token={token}")


@APP.route("/admin/reset")
@require_admin
def admin_reset():
    token = request.args.get("token", "")
    key = request.args.get("key", "")
    con = db()
    con.execute("DELETE FROM devices WHERE license_key=?", (key,))
    con.commit()
    con.close()
    log_event(key, "admin_reset_devices")
    return redirect(f"/admin?token={token}")


@APP.route("/admin/delete")
@require_admin
def admin_delete():
    token = request.args.get("token", "")
    key = request.args.get("key", "")
    con = db()
    con.execute("DELETE FROM devices WHERE license_key=?", (key,))
    con.execute("DELETE FROM licenses WHERE license_key=?", (key,))
    con.commit()
    con.close()
    log_event(key, "admin_delete_key")
    return redirect(f"/admin?token={token}")


@APP.route("/admin/devices")
@require_admin
def admin_devices():
    token = request.args.get("token", "")
    key = request.args.get("key", "")
    con = db()
    devices = con.execute("SELECT * FROM devices WHERE license_key=? ORDER BY last_seen DESC", (key,)).fetchall()
    con.close()

    rows = "".join(
        f"<tr><td>{d['device_id']}</td><td>{d['first_seen']}</td><td>{d['last_seen']}</td><td>{d['ip'] or ''}</td><td>{d['user_agent'] or ''}</td></tr>"
        for d in devices
    )

    return f"""
    <html><head><meta charset="utf-8"><title>Devices</title>
    <style>body{{font-family:Arial;background:#08111f;color:#e5eefc;padding:24px}}table{{width:100%;border-collapse:collapse}}td,th{{border-bottom:1px solid #263653;padding:10px}}a{{color:#67e8f9}}</style>
    </head><body>
    <h1>Devices for {key}</h1>
    <a href="/admin?token={token}">← Back</a>
    <table><tr><th>Device ID</th><th>First seen</th><th>Last seen</th><th>IP</th><th>User Agent</th></tr>{rows}</table>
    </body></html>
    """


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    APP.run(host="0.0.0.0", port=port)
