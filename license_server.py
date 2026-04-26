
from __future__ import annotations

import os
import secrets
import sqlite3
import string
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, render_template_string, redirect, url_for

DB_PATH = Path(os.environ.get("PIKA_LICENSE_DB", "license.db"))
ADMIN_TOKEN = os.environ.get("PIKA_ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN")
APP_ID = "PIKA_TOOL"

app = Flask(__name__)


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    if isinstance(dt, str):
        return dt
    return dt.astimezone(timezone.utc).isoformat()


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            app_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT NOT NULL,
            max_devices INTEGER NOT NULL DEFAULT 1,
            note TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL,
            hwid TEXT NOT NULL,
            device_name TEXT DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            FOREIGN KEY(license_key) REFERENCES licenses(key)
        )
        """)
        con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            hwid TEXT,
            event TEXT NOT NULL,
            message TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
        """)
        con.commit()


def log_event(con, key, hwid, event, message=""):
    con.execute(
        "INSERT INTO events (license_key, hwid, event, message, created_at) VALUES (?, ?, ?, ?, ?)",
        (key, hwid, event, message, iso(utc_now()))
    )


def parse_expire(s):
    # accept YYYY-MM-DD or ISO
    if not s:
        return None
    try:
        if len(s) == 10:
            return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.args.get("token") or request.headers.get("X-Admin-Token") or request.form.get("token")
        if token != ADMIN_TOKEN:
            return "Unauthorized. Add ?token=YOUR_ADMIN_TOKEN", 401
        return fn(*args, **kwargs)
    return wrapper


def gen_key(prefix="PIKA", groups=4, size=4):
    alphabet = string.ascii_uppercase + string.digits
    return prefix + "-" + "-".join("".join(secrets.choice(alphabet) for _ in range(size)) for _ in range(groups))


@app.route("/api/activate", methods=["POST"])
def api_activate():
    init_db()
    data = request.get_json(force=True, silent=True) or {}

    key = (data.get("key") or "").strip()
    app_id = data.get("app_id") or ""
    hwid = (data.get("hwid") or "").strip()
    device_name = (data.get("device_name") or "").strip()

    if app_id != APP_ID:
        return jsonify(ok=False, message="App không hợp lệ."), 400
    if not key or not hwid:
        return jsonify(ok=False, message="Thiếu key hoặc HWID."), 400

    with db() as con:
        lic = con.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not lic:
            log_event(con, key, hwid, "denied", "key not found")
            con.commit()
            return jsonify(ok=False, message="Key không tồn tại."), 404

        if lic["status"] != "active":
            log_event(con, key, hwid, "denied", f"status={lic['status']}")
            con.commit()
            return jsonify(ok=False, message=f"Key đang bị khoá: {lic['status']}"), 403

        exp = parse_expire(lic["expires_at"])
        if not exp or utc_now() > exp:
            log_event(con, key, hwid, "denied", "expired")
            con.commit()
            return jsonify(ok=False, message="Key đã hết hạn."), 403

        acts = con.execute("SELECT * FROM activations WHERE license_key=? ORDER BY id", (key,)).fetchall()
        existing = [a for a in acts if a["hwid"] == hwid]

        if existing:
            con.execute(
                "UPDATE activations SET last_seen=?, device_name=? WHERE license_key=? AND hwid=?",
                (iso(utc_now()), device_name, key, hwid)
            )
            log_event(con, key, hwid, "check_ok", "existing device")
            con.commit()
            return jsonify(
                ok=True,
                message="OK",
                key=key,
                expires_at=lic["expires_at"],
                max_devices=lic["max_devices"],
                device_count=len(acts),
            )

        if len(acts) >= int(lic["max_devices"]):
            log_event(con, key, hwid, "denied", "device limit")
            con.commit()
            return jsonify(ok=False, message="Key đã được dùng trên máy khác / vượt giới hạn thiết bị."), 403

        con.execute(
            "INSERT INTO activations (license_key, hwid, device_name, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (key, hwid, device_name, iso(utc_now()), iso(utc_now()))
        )
        log_event(con, key, hwid, "activated", device_name)
        con.commit()

        return jsonify(
            ok=True,
            message="Kích hoạt thành công.",
            key=key,
            expires_at=lic["expires_at"],
            max_devices=lic["max_devices"],
            device_count=len(acts) + 1,
        )


@app.route("/api/check", methods=["POST"])
def api_check():
    # activate endpoint already handles existing device check.
    return api_activate()


ADMIN_HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>PIKA License Admin</title>
<style>
body{font-family:Arial;background:#07111f;color:#e5e7eb;margin:24px}
.card{background:#0f172a;border:1px solid #1e293b;border-radius:14px;padding:16px;margin-bottom:16px}
input,select{background:#111827;color:white;border:1px solid #334155;border-radius:8px;padding:8px;margin:4px}
button{background:#2563eb;color:white;border:none;border-radius:8px;padding:9px 12px;cursor:pointer}
table{width:100%;border-collapse:collapse;background:#0f172a}
td,th{border-bottom:1px solid #1e293b;padding:8px;text-align:left;font-size:13px}
.badge{padding:4px 8px;border-radius:10px;background:#14532d}
.badge.bad{background:#7f1d1d}
a{color:#38bdf8}
</style>
</head>
<body>
<h1>⚡ PIKA License Admin</h1>

<div class="card">
<h3>Create key</h3>
<form method="post" action="/admin/create?token={{token}}">
  Expire: <input name="days" value="30" size="5"> days
  Max devices: <input name="max_devices" value="1" size="5">
  Note: <input name="note" value="">
  <button>Create</button>
</form>
</div>

<div class="card">
<h3>Keys</h3>
<table>
<tr><th>Key</th><th>Status</th><th>Expire</th><th>Devices</th><th>Note</th><th>Actions</th></tr>
{% for k in keys %}
<tr>
<td><b>{{k.key}}</b></td>
<td><span class="badge {% if k.status!='active' %}bad{% endif %}">{{k.status}}</span></td>
<td>{{k.expires_at}}</td>
<td>{{k.device_count}} / {{k.max_devices}}</td>
<td>{{k.note}}</td>
<td>
<form style="display:inline" method="post" action="/admin/status?token={{token}}">
<input type="hidden" name="key" value="{{k.key}}">
<input type="hidden" name="status" value="{% if k.status=='active' %}revoked{% else %}active{% endif %}">
<button>{% if k.status=='active' %}Revoke{% else %}Activate{% endif %}</button>
</form>
<form style="display:inline" method="post" action="/admin/reset_device?token={{token}}">
<input type="hidden" name="key" value="{{k.key}}">
<button>Reset devices</button>
</form>
</td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h3>Recent events</h3>
<table>
<tr><th>Time</th><th>Key</th><th>Event</th><th>HWID</th><th>Message</th></tr>
{% for e in events %}
<tr><td>{{e.created_at}}</td><td>{{e.license_key}}</td><td>{{e.event}}</td><td>{{e.hwid[:12]}}...</td><td>{{e.message}}</td></tr>
{% endfor %}
</table>
</div>
</body>
</html>
"""


@app.route("/admin")
@admin_required
def admin():
    init_db()
    token = request.args.get("token")
    with db() as con:
        keys = con.execute("""
        SELECT l.*, COUNT(a.id) AS device_count
        FROM licenses l
        LEFT JOIN activations a ON a.license_key = l.key
        GROUP BY l.key
        ORDER BY l.created_at DESC
        """).fetchall()
        events = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100").fetchall()
    return render_template_string(ADMIN_HTML, keys=keys, events=events, token=token)


@app.route("/admin/create", methods=["POST"])
@admin_required
def admin_create():
    init_db()
    days = int(request.form.get("days") or 30)
    max_devices = int(request.form.get("max_devices") or 1)
    note = request.form.get("note") or ""
    key = gen_key()
    now = iso(utc_now())
    exp = iso(utc_now() + timedelta(days=days))
    with db() as con:
        con.execute(
            "INSERT INTO licenses (key, app_id, status, expires_at, max_devices, note, created_at, updated_at) VALUES (?, ?, 'active', ?, ?, ?, ?, ?)",
            (key, APP_ID, exp, max_devices, note, now, now)
        )
        con.commit()
    return redirect(url_for("admin", token=request.args.get("token")))


@app.route("/admin/status", methods=["POST"])
@admin_required
def admin_status():
    init_db()
    key = request.form.get("key")
    status = request.form.get("status")
    with db() as con:
        con.execute("UPDATE licenses SET status=?, updated_at=? WHERE key=?", (status, iso(utc_now()), key))
        con.commit()
    return redirect(url_for("admin", token=request.args.get("token")))


@app.route("/admin/reset_device", methods=["POST"])
@admin_required
def admin_reset_device():
    init_db()
    key = request.form.get("key")
    with db() as con:
        con.execute("DELETE FROM activations WHERE license_key=?", (key,))
        con.commit()
    return redirect(url_for("admin", token=request.args.get("token")))


@app.route("/health")
def health():
    return jsonify(ok=True, app=APP_ID, time=iso(utc_now()))


if __name__ == "__main__":
    init_db()
    print("PIKA License Server running...")
    print("Admin:", f"http://127.0.0.1:5000/admin?token={ADMIN_TOKEN}")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
