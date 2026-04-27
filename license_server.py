# license_server.py
# PIKA License Server PRO + Admin APIs + Online Stats
# requirements.txt: flask

from __future__ import annotations

import os, sqlite3, secrets, string
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, jsonify, request

APP = Flask(__name__)
DB_PATH = os.environ.get("LICENSE_DB", "license.db")
ADMIN_TOKEN = os.environ.get("PIKA_ADMIN_TOKEN", os.environ.get("ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN"))
APP_ID = os.environ.get("PIKA_APP_ID", "PIKA_TOOL")


def utc_now(): return datetime.now(timezone.utc)
def iso(dt=None): return (dt or utc_now()).isoformat()
def parse_iso(v):
    if not v: return None
    try: return datetime.fromisoformat(v)
    except Exception: return None

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def rowdict(row): return dict(row) if row else None

def init_db():
    con = db(); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS licenses (
        license_key TEXT PRIMARY KEY,
        app_id TEXT NOT NULL DEFAULT 'PIKA_TOOL',
        status TEXT NOT NULL DEFAULT 'active',
        max_devices INTEGER NOT NULL DEFAULT 1,
        expires_at TEXT,
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        license_key TEXT NOT NULL,
        device_id TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        user_agent TEXT,
        ip TEXT,
        UNIQUE(license_key, device_id)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        license_key TEXT,
        event TEXT NOT NULL,
        device_id TEXT,
        ip TEXT,
        user_agent TEXT,
        message TEXT
    )""")
    con.commit(); con.close()

def make_key(prefix="PIKA"):
    alphabet = string.ascii_uppercase + string.digits
    return prefix + "-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))

def client_ip():
    return (request.headers.get("x-forwarded-for") or request.remote_addr or "").split(",")[0].strip()

def ua(): return request.headers.get("user-agent", "")

def log_event(license_key, event, device_id="", message=""):
    con = db()
    con.execute("INSERT INTO events(created_at, license_key, event, device_id, ip, user_agent, message) VALUES(?,?,?,?,?,?,?)",
                (iso(), license_key, event, device_id, client_ip(), ua(), message))
    con.commit(); con.close()

def get_token():
    data = request.get_json(silent=True) or {}
    return request.args.get("token") or request.form.get("token") or data.get("token") or ""

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if get_token() != ADMIN_TOKEN:
            return jsonify(ok=False, message="Unauthorized"), 401
        return fn(*args, **kwargs)
    return wrapper

@APP.route("/")
def home(): return jsonify(ok=True, app="PIKA License Server PRO", admin_api=True)

@APP.route("/health")
def health(): return jsonify(ok=True, time=iso())

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
        con.close(); log_event(license_key, "invalid_key", device_id)
        return jsonify(ok=False, message="Key không tồn tại"), 403
    if lic["app_id"] != app_id and lic["app_id"] != APP_ID:
        con.close(); log_event(license_key, "wrong_app", device_id, f"app={app_id}")
        return jsonify(ok=False, message="Key không đúng app"), 403
    if lic["status"] != "active":
        con.close(); log_event(license_key, "blocked", device_id)
        return jsonify(ok=False, message="Key đã bị khóa"), 403

    exp = parse_iso(lic["expires_at"])
    if exp and exp < utc_now():
        con.execute("UPDATE licenses SET status='expired', updated_at=? WHERE license_key=?", (iso(), license_key))
        con.commit(); con.close(); log_event(license_key, "expired", device_id)
        return jsonify(ok=False, message="Key đã hết hạn"), 403

    existing = con.execute("SELECT * FROM devices WHERE license_key=? AND device_id=?", (license_key, device_id)).fetchone()
    count = con.execute("SELECT COUNT(*) AS c FROM devices WHERE license_key=?", (license_key,)).fetchone()["c"]

    if not existing and count >= int(lic["max_devices"]):
        con.close(); log_event(license_key, "device_limit", device_id, f"limit={lic['max_devices']}")
        return jsonify(ok=False, message="Key đã được kích hoạt trên máy khác"), 403

    if existing:
        con.execute("UPDATE devices SET last_seen=?, ip=?, user_agent=? WHERE id=?", (iso(), client_ip(), ua(), existing["id"]))
        event = "checked"
    else:
        con.execute("INSERT INTO devices(license_key, device_id, first_seen, last_seen, ip, user_agent) VALUES(?,?,?,?,?,?)",
                    (license_key, device_id, iso(), iso(), client_ip(), ua()))
        event = "activated"

    con.commit(); con.close(); log_event(license_key, event, device_id)
    return jsonify(ok=True, message="License OK", expires_at=lic["expires_at"], max_devices=lic["max_devices"])

@APP.route("/api/admin/keys")
@require_admin
def api_admin_keys():
    con = db()
    rows = con.execute("""SELECT l.*,
        (SELECT COUNT(*) FROM devices d WHERE d.license_key=l.license_key) AS device_count
        FROM licenses l ORDER BY l.created_at DESC""").fetchall()
    con.close()
    return jsonify(ok=True, keys=[rowdict(r) for r in rows])

@APP.route("/api/admin/stats")
@require_admin
def api_admin_stats():
    con = db()
    total = con.execute("SELECT COUNT(*) c FROM licenses").fetchone()["c"]
    active = con.execute("SELECT COUNT(*) c FROM licenses WHERE status='active'").fetchone()["c"]
    blocked = con.execute("SELECT COUNT(*) c FROM licenses WHERE status='blocked'").fetchone()["c"]
    expired = con.execute("SELECT COUNT(*) c FROM licenses WHERE status='expired'").fetchone()["c"]
    devices = con.execute("SELECT COUNT(*) c FROM devices").fetchone()["c"]
    online_cutoff = (utc_now() - timedelta(minutes=10)).isoformat()
    online = con.execute("SELECT COUNT(*) c FROM devices WHERE last_seen>=?", (online_cutoff,)).fetchone()["c"]
    con.close()
    return jsonify(ok=True, stats={
        "total_keys": total, "active_keys": active, "blocked_keys": blocked,
        "expired_keys": expired, "total_devices": devices, "online_10m": online
    })

@APP.route("/api/admin/events")
@require_admin
def api_admin_events():
    limit = int(request.args.get("limit", 80))
    con = db()
    rows = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return jsonify(ok=True, events=[rowdict(r) for r in rows])

@APP.route("/api/admin/create", methods=["POST"])
@require_admin
def api_admin_create():
    data = request.get_json(silent=True) or {}
    days = int(data.get("days") or 30)
    max_devices = int(data.get("max_devices") or 1)
    note = str(data.get("note") or "")
    key = make_key()
    expires_at = iso(utc_now() + timedelta(days=days)) if days > 0 else None
    con = db()
    con.execute("""INSERT INTO licenses(license_key, app_id, status, max_devices, expires_at, note, created_at, updated_at)
                   VALUES(?,?,?,?,?,?,?,?)""", (key, APP_ID, "active", max_devices, expires_at, note, iso(), iso()))
    con.commit(); con.close()
    log_event(key, "created", "", f"days={days}, max_devices={max_devices}, note={note}")
    return jsonify(ok=True, license_key=key)

def _update_status(status):
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    con = db()
    con.execute("UPDATE licenses SET status=?, updated_at=? WHERE license_key=?", (status, iso(), key))
    con.commit(); con.close()
    log_event(key, f"admin_{status}")
    return jsonify(ok=True)

@APP.route("/api/admin/block", methods=["POST"])
@require_admin
def api_admin_block(): return _update_status("blocked")

@APP.route("/api/admin/unblock", methods=["POST"])
@require_admin
def api_admin_unblock(): return _update_status("active")

@APP.route("/api/admin/reset", methods=["POST"])
@require_admin
def api_admin_reset():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    con = db()
    con.execute("DELETE FROM devices WHERE license_key=?", (key,))
    con.commit(); con.close()
    log_event(key, "admin_reset_devices")
    return jsonify(ok=True)

@APP.route("/api/admin/delete", methods=["POST"])
@require_admin
def api_admin_delete():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    con = db()
    con.execute("DELETE FROM devices WHERE license_key=?", (key,))
    con.execute("DELETE FROM licenses WHERE license_key=?", (key,))
    con.commit(); con.close()
    log_event(key, "admin_delete_key")
    return jsonify(ok=True)

init_db()
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    APP.run(host="0.0.0.0", port=port)
