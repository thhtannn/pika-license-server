# license_server.py
# PIKA License Server - STEALTH + TOKEN + PASSWORD
# requirements.txt: flask

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request, render_template, redirect

APP = Flask(__name__)
APP.secret_key = os.environ.get("PIKA_FLASK_SECRET", secrets.token_hex(24))

DB_PATH = os.environ.get("LICENSE_DB", "license.db")
APP_ID = os.environ.get("PIKA_APP_ID", "PIKA_TOOL")

# =========================
# ADMIN SECURITY SETTINGS
# =========================
# Không dùng /admin nữa. Dùng đường dẫn bí mật.
ADMIN_PATH = os.environ.get("PIKA_ADMIN_PATH", "pika-admin-7l728obyhd").strip("/")

# Token + Password: nhập trên dashboard web.
ADMIN_TOKEN = os.environ.get("PIKA_ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN")
ADMIN_PASSWORD = os.environ.get("PIKA_ADMIN_PASSWORD", "CHANGE_ME_ADMIN_PASSWORD")

# Anti-share
STRICT_DEVICE_BIND = os.environ.get("PIKA_STRICT_DEVICE_BIND", "1") == "1"
AUTO_BLOCK_SHARE = os.environ.get("PIKA_AUTO_BLOCK_SHARE", "0") == "1"
AUTO_BLOCK_THRESHOLD = int(os.environ.get("PIKA_AUTO_BLOCK_THRESHOLD", "5"))

# Anti brute-force admin login
ADMIN_FAIL_LIMIT = int(os.environ.get("PIKA_ADMIN_FAIL_LIMIT", "8"))
ADMIN_FAIL_WINDOW_MIN = int(os.environ.get("PIKA_ADMIN_FAIL_WINDOW_MIN", "20"))


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or utc_now()).isoformat()


def parse_iso(value):
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


def rowdict(row):
    return dict(row) if row else None


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
        device_label TEXT,
        fingerprint_json TEXT,
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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS share_violations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        license_key TEXT NOT NULL,
        attempted_device_id TEXT,
        attempted_device_label TEXT,
        ip TEXT,
        fingerprint_json TEXT,
        message TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        reason TEXT
    )
    """)

    con.commit()
    con.close()


def make_key(prefix="PIKA"):
    alphabet = string.ascii_uppercase + string.digits
    return prefix + "-" + "-".join(
        "".join(secrets.choice(alphabet) for _ in range(4))
        for _ in range(4)
    )

LATEST_VERSION = os.environ.get("PIKA_LATEST_VERSION", "2.1.0")
UPDATE_URL = os.environ.get("PIKA_UPDATE_URL", "")
UPDATE_SHA256 = os.environ.get("PIKA_UPDATE_SHA256", "")
UPDATE_NOTES = os.environ.get("PIKA_UPDATE_NOTES", "New PIKA BOT update is available.")


def _parse_version(v):
    parts = []
    for x in str(v).strip().split("."):
        try:
            parts.append(int(x))
        except Exception:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


@APP.route("/api/update/check")
def api_update_check():
    current = request.args.get("version", "0.0.0")
    app_id = request.args.get("app", "PIKA_BOT")

    if app_id != APP_ID and app_id != "PIKA_BOT":
        return jsonify(ok=False, message="wrong app"), 400

    has_update = _parse_version(LATEST_VERSION) > _parse_version(current)

    return jsonify(
        ok=True,
        current_version=current,
        latest_version=LATEST_VERSION,
        has_update=has_update,
        download_url=UPDATE_URL if has_update else "",
        sha256=UPDATE_SHA256 if has_update else "",
        notes=UPDATE_NOTES,
    )

def client_ip():
    return (request.headers.get("x-forwarded-for") or request.remote_addr or "").split(",")[0].strip()


def ua():
    return request.headers.get("user-agent", "")


def log_event(license_key, event, device_id="", message=""):
    con = db()
    con.execute(
        "INSERT INTO events(created_at, license_key, event, device_id, ip, user_agent, message) VALUES(?,?,?,?,?,?,?)",
        (iso(), license_key, event, device_id, client_ip(), ua(), message),
    )
    con.commit()
    con.close()


def log_share_violation(license_key, device_id, device_label, fingerprint, message):
    con = db()
    con.execute(
        "INSERT INTO share_violations(created_at, license_key, attempted_device_id, attempted_device_label, ip, fingerprint_json, message) VALUES(?,?,?,?,?,?,?)",
        (iso(), license_key, device_id, device_label, client_ip(), json.dumps(fingerprint or {}, ensure_ascii=False), message),
    )

    if AUTO_BLOCK_SHARE:
        count = con.execute(
            "SELECT COUNT(*) AS c FROM share_violations WHERE license_key=?",
            (license_key,),
        ).fetchone()["c"]
        if count + 1 >= AUTO_BLOCK_THRESHOLD:
            con.execute("UPDATE licenses SET status='blocked', updated_at=? WHERE license_key=?", (iso(), license_key))

    con.commit()
    con.close()


def log_admin_fail(reason):
    con = db()
    con.execute(
        "INSERT INTO admin_failures(created_at, ip, user_agent, reason) VALUES(?,?,?,?)",
        (iso(), client_ip(), ua(), reason),
    )
    con.commit()
    con.close()


def too_many_admin_failures():
    cutoff = (utc_now() - timedelta(minutes=ADMIN_FAIL_WINDOW_MIN)).isoformat()
    con = db()
    count = con.execute(
        "SELECT COUNT(*) AS c FROM admin_failures WHERE ip=? AND created_at>=?",
        (client_ip(), cutoff),
    ).fetchone()["c"]
    con.close()
    return count >= ADMIN_FAIL_LIMIT


def get_token():
    data = request.get_json(silent=True) or {}
    return request.args.get("token") or request.form.get("token") or data.get("token") or ""


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if get_token() != ADMIN_TOKEN:
            log_admin_fail("bad_api_token")
            return jsonify(ok=False, message="Unauthorized"), 401
        return fn(*args, **kwargs)
    return wrapper


@APP.route("/")
def home():
    return jsonify(ok=True, app="PIKA License Server", status="running")


@APP.route("/admin")
def fake_admin():
    # Cố tình ẩn dashboard thật.
    return "Not Found", 404


@APP.route("/health")
def health():
    return jsonify(ok=True, time=iso(), strict_device_bind=STRICT_DEVICE_BIND)


@APP.route(f"/{ADMIN_PATH}")
def admin_dashboard():
    return render_template("admin_stealth.html", admin_path=ADMIN_PATH)


@APP.route(f"/{ADMIN_PATH}/login", methods=["POST"])
def admin_login():
    if too_many_admin_failures():
        return jsonify(ok=False, message="Too many failed attempts. Try later."), 429

    data = request.get_json(silent=True) or {}
    token = str(data.get("token") or "").strip()
    password = str(data.get("password") or "").strip()

    if token != ADMIN_TOKEN or password != ADMIN_PASSWORD:
        log_admin_fail("bad_token_or_password")
        return jsonify(ok=False, message="Invalid token/password"), 401

    return jsonify(ok=True, message="Login OK")


@APP.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    device_id = str(data.get("device_id", "")).strip()
    device_label = str(data.get("device_label", "")).strip()
    fingerprint = data.get("fingerprint") or {}
    app_id = str(data.get("app") or data.get("app_id") or APP_ID).strip()

    if not license_key or not device_id:
        log_event(license_key or None, "bad_request", device_id, "missing license_key/device_id")
        return jsonify(ok=False, code="BAD_REQUEST", message="Missing license_key or device_id"), 400

    con = db()
    lic = con.execute("SELECT * FROM licenses WHERE license_key=?", (license_key,)).fetchone()

    if not lic:
        con.close()
        log_event(license_key, "invalid_key", device_id)
        return jsonify(ok=False, code="INVALID_KEY", message="Key không tồn tại"), 403

    if lic["app_id"] != app_id and lic["app_id"] != APP_ID:
        con.close()
        log_event(license_key, "wrong_app", device_id, f"app={app_id}")
        return jsonify(ok=False, code="WRONG_APP", message="Key không đúng app"), 403

    if lic["status"] != "active":
        con.close()
        log_event(license_key, "blocked", device_id)
        return jsonify(ok=False, code="BLOCKED", message="Key đã bị khóa"), 403

    exp = parse_iso(lic["expires_at"])
    if exp and exp < utc_now():
        con.execute("UPDATE licenses SET status='expired', updated_at=? WHERE license_key=?", (iso(), license_key))
        con.commit()
        con.close()
        log_event(license_key, "expired", device_id)
        return jsonify(ok=False, code="EXPIRED", message="Key đã hết hạn"), 403

    existing = con.execute(
        "SELECT * FROM devices WHERE license_key=? AND device_id=?",
        (license_key, device_id),
    ).fetchone()

    device_count = con.execute(
        "SELECT COUNT(*) AS c FROM devices WHERE license_key=?",
        (license_key,),
    ).fetchone()["c"]

    max_devices = int(lic["max_devices"])

    if not existing and STRICT_DEVICE_BIND and device_count >= max_devices:
        first_device = con.execute(
            "SELECT device_id, device_label, ip, first_seen, last_seen FROM devices WHERE license_key=? ORDER BY id ASC LIMIT 1",
            (license_key,),
        ).fetchone()
        con.close()

        msg = "Key đã được kích hoạt trên máy khác"
        if first_device:
            msg += f" ({first_device['device_label'] or first_device['device_id'][:10]})"

        log_share_violation(license_key, device_id, device_label, fingerprint, msg)
        log_event(license_key, "share_blocked", device_id, msg)

        return jsonify(
            ok=False,
            code="DEVICE_LIMIT",
            message=msg,
            bound_device=rowdict(first_device) if first_device else None,
        ), 403

    fp_json = json.dumps(fingerprint, ensure_ascii=False)

    if existing:
        con.execute(
            "UPDATE devices SET device_label=?, fingerprint_json=?, last_seen=?, ip=?, user_agent=? WHERE id=?",
            (device_label, fp_json, iso(), client_ip(), ua(), existing["id"]),
        )
        event = "checked"
    else:
        con.execute(
            "INSERT INTO devices(license_key, device_id, device_label, fingerprint_json, first_seen, last_seen, ip, user_agent) VALUES(?,?,?,?,?,?,?,?)",
            (license_key, device_id, device_label, fp_json, iso(), iso(), client_ip(), ua()),
        )
        event = "activated"

    con.commit()
    con.close()
    log_event(license_key, event, device_id, f"label={device_label}")

    return jsonify(ok=True, code="OK", message="License OK", expires_at=lic["expires_at"], max_devices=max_devices, device_id=device_id)


@APP.route("/api/admin/keys")
@require_admin
def api_admin_keys():
    con = db()
    rows = con.execute("""
        SELECT l.*,
               (SELECT COUNT(*) FROM devices d WHERE d.license_key=l.license_key) AS device_count,
               (SELECT MAX(last_seen) FROM devices d WHERE d.license_key=l.license_key) AS last_seen,
               (SELECT COUNT(*) FROM share_violations s WHERE s.license_key=l.license_key) AS share_violations
        FROM licenses l
        ORDER BY l.created_at DESC
    """).fetchall()
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
    violations = con.execute("SELECT COUNT(*) c FROM share_violations").fetchone()["c"]
    online_cutoff = (utc_now() - timedelta(minutes=10)).isoformat()
    online = con.execute("SELECT COUNT(*) c FROM devices WHERE last_seen>=?", (online_cutoff,)).fetchone()["c"]
    con.close()
    return jsonify(ok=True, stats={
        "total_keys": total,
        "active_keys": active,
        "blocked_keys": blocked,
        "expired_keys": expired,
        "total_devices": devices,
        "online_10m": online,
        "share_violations": violations,
    })


@APP.route("/api/admin/devices")
@require_admin
def api_admin_devices():
    key = request.args.get("license_key", "").strip()
    con = db()
    if key:
        rows = con.execute("SELECT * FROM devices WHERE license_key=? ORDER BY last_seen DESC", (key,)).fetchall()
    else:
        rows = con.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 300").fetchall()
    con.close()
    return jsonify(ok=True, devices=[rowdict(r) for r in rows])


@APP.route("/api/admin/violations")
@require_admin
def api_admin_violations():
    limit = int(request.args.get("limit", 200))
    con = db()
    rows = con.execute("SELECT * FROM share_violations ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return jsonify(ok=True, violations=[rowdict(r) for r in rows])


@APP.route("/api/admin/events")
@require_admin
def api_admin_events():
    limit = int(request.args.get("limit", 200))
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
    con.execute("""
        INSERT INTO licenses(license_key, app_id, status, max_devices, expires_at, note, created_at, updated_at)
        VALUES(?,?,?,?,?,?,?,?)
    """, (key, APP_ID, "active", max_devices, expires_at, note, iso(), iso()))
    con.commit()
    con.close()
    log_event(key, "created", "", f"days={days}, max_devices={max_devices}, note={note}")
    return jsonify(ok=True, license_key=key)


def _update_status(status):
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    con = db()
    con.execute("UPDATE licenses SET status=?, updated_at=? WHERE license_key=?", (status, iso(), key))
    con.commit()
    con.close()
    log_event(key, f"admin_{status}")
    return jsonify(ok=True)


@APP.route("/api/admin/block", methods=["POST"])
@require_admin
def api_admin_block():
    return _update_status("blocked")


@APP.route("/api/admin/unblock", methods=["POST"])
@require_admin
def api_admin_unblock():
    return _update_status("active")


@APP.route("/api/admin/reset", methods=["POST"])
@require_admin
def api_admin_reset():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    con = db()
    con.execute("DELETE FROM devices WHERE license_key=?", (key,))
    con.commit()
    con.close()
    log_event(key, "admin_reset_devices")
    return jsonify(ok=True)


@APP.route("/api/admin/delete", methods=["POST"])
@require_admin
def api_admin_delete():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    con = db()
    con.execute("DELETE FROM devices WHERE license_key=?", (key,))
    con.execute("DELETE FROM share_violations WHERE license_key=?", (key,))
    con.execute("DELETE FROM licenses WHERE license_key=?", (key,))
    con.commit()
    con.close()
    log_event(key, "admin_delete_key")
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    APP.run(host="0.0.0.0", port=port)
