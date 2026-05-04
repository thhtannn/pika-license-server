# license_server.py
# PIKA License Server - PRODUCTION POSTGRES/SUPABASE PHASE 2

from __future__ import annotations
import json, os, secrets, string
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, jsonify, request, render_template
import psycopg2, psycopg2.extras

APP = Flask(__name__)
APP.secret_key = os.environ.get("PIKA_FLASK_SECRET", secrets.token_hex(24))

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
APP_ID = os.environ.get("PIKA_APP_ID", "PIKA_TOOL")
ADMIN_PATH = os.environ.get("PIKA_ADMIN_PATH", "pika-admin-7l728obyhd").strip("/")
ADMIN_TOKEN = os.environ.get("PIKA_ADMIN_TOKEN", "CHANGE_ME_ADMIN_TOKEN")
ADMIN_PASSWORD = os.environ.get("PIKA_ADMIN_PASSWORD", "CHANGE_ME_ADMIN_PASSWORD")
STRICT_DEVICE_BIND = os.environ.get("PIKA_STRICT_DEVICE_BIND", "1") == "1"
AUTO_BLOCK_SHARE = os.environ.get("PIKA_AUTO_BLOCK_SHARE", "0") == "1"
AUTO_BLOCK_THRESHOLD = int(os.environ.get("PIKA_AUTO_BLOCK_THRESHOLD", "5"))
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
        return datetime.fromisoformat(str(value))
    except Exception:
        return None

def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def rowdict(row):
    return dict(row) if row else None

def init_db():
    with db() as con:
        with con.cursor() as cur:
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
                id SERIAL PRIMARY KEY,
                license_key TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_label TEXT,
                fingerprint_json TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                user_agent TEXT,
                ip TEXT,
                UNIQUE(license_key, device_id)
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                license_key TEXT,
                event TEXT NOT NULL,
                device_id TEXT,
                ip TEXT,
                user_agent TEXT,
                message TEXT
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS share_violations (
                id SERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                license_key TEXT NOT NULL,
                attempted_device_id TEXT,
                attempted_device_label TEXT,
                ip TEXT,
                fingerprint_json TEXT,
                message TEXT
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS admin_failures (
                id SERIAL PRIMARY KEY,
                created_at TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                reason TEXT
            )""")
            cur.execute("""CREATE TABLE IF NOT EXISTS cloud_accounts (
                id SERIAL PRIMARY KEY,
                license_key TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT,
                recovery TEXT,
                status TEXT DEFAULT 'active',
                source TEXT,
                created_at TEXT,
                updated_at TEXT,
                raw_json TEXT,
                server_updated_at TEXT NOT NULL,
                deleted BOOLEAN NOT NULL DEFAULT FALSE,
                deleted_at TEXT,
                UNIQUE(license_key, email)
            )""")
            # Migration for older table
            cur.execute("ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS deleted_at TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cloud_accounts_license ON cloud_accounts(license_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cloud_accounts_license_email ON cloud_accounts(license_key, email)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cloud_accounts_license_updated ON cloud_accounts(license_key, server_updated_at)")
        con.commit()

def make_key(prefix="PIKA"):
    alphabet = string.ascii_uppercase + string.digits
    return prefix + "-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))

def client_ip():
    return (request.headers.get("x-forwarded-for") or request.remote_addr or "").split(",")[0].strip()

def ua():
    return request.headers.get("user-agent", "")

def log_event(license_key, event, device_id="", message=""):
    try:
        with db() as con:
            with con.cursor() as cur:
                cur.execute("INSERT INTO events(created_at, license_key, event, device_id, ip, user_agent, message) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (iso(), license_key, event, device_id, client_ip(), ua(), message))
            con.commit()
    except Exception:
        pass

def log_share_violation(license_key, device_id, device_label, fingerprint, message):
    with db() as con:
        with con.cursor() as cur:
            cur.execute("INSERT INTO share_violations(created_at, license_key, attempted_device_id, attempted_device_label, ip, fingerprint_json, message) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (iso(), license_key, device_id, device_label, client_ip(), json.dumps(fingerprint or {}, ensure_ascii=False), message))
            if AUTO_BLOCK_SHARE:
                cur.execute("SELECT COUNT(*) AS c FROM share_violations WHERE license_key=%s", (license_key,))
                if cur.fetchone()["c"] >= AUTO_BLOCK_THRESHOLD:
                    cur.execute("UPDATE licenses SET status='blocked', updated_at=%s WHERE license_key=%s", (iso(), license_key))
        con.commit()

def log_admin_fail(reason):
    try:
        with db() as con:
            with con.cursor() as cur:
                cur.execute("INSERT INTO admin_failures(created_at, ip, user_agent, reason) VALUES(%s,%s,%s,%s)", (iso(), client_ip(), ua(), reason))
            con.commit()
    except Exception:
        pass

def too_many_admin_failures():
    cutoff = (utc_now() - timedelta(minutes=ADMIN_FAIL_WINDOW_MIN)).isoformat()
    with db() as con:
        with con.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM admin_failures WHERE ip=%s AND created_at >= %s", (client_ip(), cutoff))
            return cur.fetchone()["c"] >= ADMIN_FAIL_LIMIT

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
    return jsonify(ok=True, app="PIKA License Server", status="running", db="postgres", phase="2")

@APP.route("/health")
def health():
    try:
        with db() as con:
            with con.cursor() as cur:
                cur.execute("SELECT 1 AS ok")
                cur.fetchone()
        return jsonify(ok=True, db_ok=True, phase="2", time=iso())
    except Exception as e:
        return jsonify(ok=False, db_ok=False, error=str(e)), 500

@APP.route(f"/{ADMIN_PATH}")
def admin_dashboard():
    return render_template("admin_stealth.html", admin_path=ADMIN_PATH)

@APP.route(f"/{ADMIN_PATH}/login", methods=["POST"])
def admin_login():
    if too_many_admin_failures():
        return jsonify(ok=False, message="Too many failed attempts. Try later."), 429
    data = request.get_json(silent=True) or {}
    if str(data.get("token") or "").strip() != ADMIN_TOKEN or str(data.get("password") or "").strip() != ADMIN_PASSWORD:
        log_admin_fail("bad_token_or_password")
        return jsonify(ok=False, message="Invalid token/password"), 401
    return jsonify(ok=True, message="Login OK")

def validate_license_for_cloud(license_key, device_id, device_label="", fingerprint=None, app_id=None):
    license_key = str(license_key or "").strip()
    device_id = str(device_id or "").strip()
    device_label = str(device_label or "").strip()
    fingerprint = fingerprint or {}
    app_id = str(app_id or APP_ID).strip()
    if not license_key or not device_id:
        return False, (jsonify(ok=False, code="BAD_REQUEST", message="Missing license_key or device_id"), 400), None
    with db() as con:
        with con.cursor() as cur:
            cur.execute("SELECT * FROM licenses WHERE license_key=%s", (license_key,))
            lic = cur.fetchone()
            if not lic:
                return False, (jsonify(ok=False, code="INVALID_KEY", message="Key không tồn tại"), 403), None
            if lic["app_id"] != app_id and lic["app_id"] != APP_ID:
                return False, (jsonify(ok=False, code="WRONG_APP", message="Key không đúng app"), 403), None
            if lic["status"] != "active":
                return False, (jsonify(ok=False, code="BLOCKED", message="Key đã bị khóa"), 403), None
            exp = parse_iso(lic["expires_at"])
            if exp and exp < utc_now():
                cur.execute("UPDATE licenses SET status='expired', updated_at=%s WHERE license_key=%s", (iso(), license_key))
                con.commit()
                return False, (jsonify(ok=False, code="EXPIRED", message="Key đã hết hạn"), 403), None
            cur.execute("SELECT * FROM devices WHERE license_key=%s AND device_id=%s", (license_key, device_id))
            existing = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS c FROM devices WHERE license_key=%s", (license_key,))
            device_count = cur.fetchone()["c"]
            if not existing and STRICT_DEVICE_BIND and device_count >= int(lic["max_devices"]):
                cur.execute("SELECT device_id, device_label, ip, first_seen, last_seen FROM devices WHERE license_key=%s ORDER BY id ASC LIMIT 1", (license_key,))
                first_device = cur.fetchone()
                msg = "Key đã được kích hoạt trên máy khác"
                if first_device:
                    msg += f" ({first_device['device_label'] or first_device['device_id'][:10]})"
                log_share_violation(license_key, device_id, device_label, fingerprint, msg)
                log_event(license_key, "share_blocked", device_id, msg)
                return False, (jsonify(ok=False, code="DEVICE_LIMIT", message=msg, bound_device=rowdict(first_device)), 403), None
            fp_json = json.dumps(fingerprint, ensure_ascii=False)
            if existing:
                cur.execute("UPDATE devices SET device_label=%s, fingerprint_json=%s, last_seen=%s, ip=%s, user_agent=%s WHERE id=%s",
                    (device_label, fp_json, iso(), client_ip(), ua(), existing["id"]))
                event = "checked"
            else:
                cur.execute("INSERT INTO devices(license_key, device_id, device_label, fingerprint_json, first_seen, last_seen, ip, user_agent) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                    (license_key, device_id, device_label, fp_json, iso(), iso(), client_ip(), ua()))
                event = "activated"
        con.commit()
    log_event(license_key, event, device_id, f"label={device_label}")
    return True, None, lic

@APP.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.get_json(force=True, silent=True) or {}
    ok, err, lic = validate_license_for_cloud(
        data.get("license_key", ""),
        data.get("device_id", ""),
        data.get("device_label", ""),
        data.get("fingerprint") or {},
        data.get("app") or data.get("app_id") or APP_ID,
    )
    if not ok:
        return err
    return jsonify(ok=True, code="OK", message="License OK", expires_at=lic["expires_at"], max_devices=int(lic["max_devices"]), device_id=data.get("device_id", ""))

def _account_to_dict(r):
    item = {}
    try:
        raw = json.loads(r.get("raw_json") or "{}")
        if isinstance(raw, dict):
            item.update(raw)
    except Exception:
        pass
    item["email"] = r.get("email") or item.get("email", "")
    item["password"] = r.get("password") or item.get("password", "")
    item["recovery"] = r.get("recovery") or item.get("recovery", "")
    item["status"] = r.get("status") or item.get("status", "active")
    item["source"] = r.get("source") or item.get("source", "")
    item["created_at"] = r.get("created_at") or item.get("created_at", "")
    item["updated_at"] = r.get("updated_at") or item.get("updated_at", "")
    item["server_updated_at"] = r.get("server_updated_at", "")
    return item

@APP.route("/api/accounts/upsert", methods=["POST"])
def api_accounts_upsert():
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    ok, err, _ = validate_license_for_cloud(license_key, data.get("device_id", ""), data.get("device_label", ""), data.get("fingerprint") or {}, data.get("app") or data.get("app_id") or APP_ID)
    if not ok:
        return err
    accounts = data.get("accounts")
    if accounts is None and isinstance(data.get("account"), dict):
        accounts = [data.get("account")]
    if not isinstance(accounts, list):
        return jsonify(ok=False, code="BAD_ACCOUNTS", message="accounts must be list"), 400
    now = iso()
    clean = []
    seen = set()
    for raw in accounts:
        if not isinstance(raw, dict):
            continue
        email = str(raw.get("email", "")).strip().lower()
        if not email or "@" not in email or email in seen:
            continue
        seen.add(email)
        clean.append(raw)
    with db() as con:
        with con.cursor() as cur:
            for raw in clean:
                email = str(raw.get("email", "")).strip().lower()
                raw_copy = dict(raw)
                raw_copy["email"] = str(raw.get("email", "")).strip()
                cur.execute("""
                    INSERT INTO cloud_accounts(
                        license_key, email, password, recovery, status, source,
                        created_at, updated_at, raw_json, server_updated_at, deleted, deleted_at
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,FALSE,NULL)
                    ON CONFLICT (license_key, email)
                    DO UPDATE SET
                        password=EXCLUDED.password,
                        recovery=EXCLUDED.recovery,
                        status=EXCLUDED.status,
                        source=EXCLUDED.source,
                        updated_at=EXCLUDED.updated_at,
                        raw_json=EXCLUDED.raw_json,
                        server_updated_at=EXCLUDED.server_updated_at,
                        deleted=FALSE,
                        deleted_at=NULL
                """, (
                    license_key, email,
                    str(raw.get("password", "") or ""),
                    str(raw.get("recovery", "") or ""),
                    str(raw.get("status", "active") or "active"),
                    str(raw.get("source", "") or ""),
                    str(raw.get("created_at", "") or ""),
                    str(raw.get("updated_at", "") or now),
                    json.dumps(raw_copy, ensure_ascii=False),
                    now,
                ))
        con.commit()
    log_event(license_key, "cloud_accounts_upsert", data.get("device_id", ""), f"count={len(clean)}")
    return jsonify(ok=True, count=len(clean), server_time=now)

@APP.route("/api/accounts/delete", methods=["POST"])
def api_accounts_delete():
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    ok, err, _ = validate_license_for_cloud(license_key, data.get("device_id", ""), data.get("device_label", ""), data.get("fingerprint") or {}, data.get("app") or data.get("app_id") or APP_ID)
    if not ok:
        return err
    emails = data.get("emails") or []
    if isinstance(data.get("email"), str):
        emails.append(data.get("email"))
    emails = sorted({str(e).strip().lower() for e in emails if str(e).strip()})
    now = iso()
    with db() as con:
        with con.cursor() as cur:
            for email in emails:
                cur.execute("UPDATE cloud_accounts SET deleted=TRUE, deleted_at=%s, server_updated_at=%s WHERE license_key=%s AND email=%s", (now, now, license_key, email))
        con.commit()
    log_event(license_key, "cloud_accounts_delete", data.get("device_id", ""), f"count={len(emails)}")
    return jsonify(ok=True, count=len(emails), server_time=now)

@APP.route("/api/accounts/sync", methods=["POST"])
def api_accounts_sync():
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    ok, err, _ = validate_license_for_cloud(license_key, data.get("device_id", ""), data.get("device_label", ""), data.get("fingerprint") or {}, data.get("app") or data.get("app_id") or APP_ID)
    if not ok:
        return err
    since = str(data.get("since") or "").strip()
    force = bool(data.get("force"))
    now = iso()
    with db() as con:
        with con.cursor() as cur:
            if force or not since:
                cur.execute("SELECT * FROM cloud_accounts WHERE license_key=%s AND deleted=FALSE ORDER BY id ASC", (license_key,))
                rows = cur.fetchall()
                deleted = []
            else:
                cur.execute("SELECT * FROM cloud_accounts WHERE license_key=%s AND server_updated_at > %s ORDER BY server_updated_at ASC", (license_key, since))
                rows = cur.fetchall()
                deleted = [r["email"] for r in rows if r.get("deleted")]
                rows = [r for r in rows if not r.get("deleted")]
    accounts = [_account_to_dict(r) for r in rows]
    log_event(license_key, "cloud_accounts_sync", data.get("device_id", ""), f"accounts={len(accounts)}, deleted={len(deleted)}")
    return jsonify(ok=True, accounts=accounts, deleted_emails=deleted, server_time=now)

# Backward endpoints for old clients
@APP.route("/api/accounts/list", methods=["POST"])
def api_accounts_list():
    data = request.get_json(force=True, silent=True) or {}
    data["force"] = True
    with APP.test_request_context(json=data):
        return api_accounts_sync()

@APP.route("/api/accounts/upload-all", methods=["POST"])
def api_accounts_upload_all():
    data = request.get_json(force=True, silent=True) or {}
    data["accounts"] = data.get("accounts") or []
    with APP.test_request_context(json=data):
        return api_accounts_upsert()

@APP.route("/api/admin/keys")
@require_admin
def api_admin_keys():
    with db() as con:
        with con.cursor() as cur:
            cur.execute("""
                SELECT l.*,
                       (SELECT COUNT(*) FROM devices d WHERE d.license_key=l.license_key) AS device_count,
                       (SELECT MAX(last_seen) FROM devices d WHERE d.license_key=l.license_key) AS last_seen,
                       (SELECT COUNT(*) FROM share_violations s WHERE s.license_key=l.license_key) AS share_violations
                FROM licenses l
                ORDER BY l.created_at DESC
            """)
            rows = cur.fetchall()
    return jsonify(ok=True, keys=[rowdict(r) for r in rows])

@APP.route("/api/admin/stats")
@require_admin
def api_admin_stats():
    online_cutoff = (utc_now() - timedelta(minutes=10)).isoformat()
    with db() as con:
        with con.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM licenses"); total = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM licenses WHERE status='active'"); active = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM licenses WHERE status='blocked'"); blocked = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM licenses WHERE status='expired'"); expired = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM devices"); devices = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM share_violations"); violations = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM devices WHERE last_seen >= %s", (online_cutoff,)); online = cur.fetchone()["c"]
    return jsonify(ok=True, stats={"total_keys": total, "active_keys": active, "blocked_keys": blocked, "expired_keys": expired, "total_devices": devices, "online_10m": online, "share_violations": violations})

@APP.route("/api/admin/devices")
@require_admin
def api_admin_devices():
    key = request.args.get("license_key", "").strip()
    with db() as con:
        with con.cursor() as cur:
            if key:
                cur.execute("SELECT * FROM devices WHERE license_key=%s ORDER BY last_seen DESC", (key,))
            else:
                cur.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT 300")
            rows = cur.fetchall()
    return jsonify(ok=True, devices=[rowdict(r) for r in rows])

@APP.route("/api/admin/violations")
@require_admin
def api_admin_violations():
    limit = int(request.args.get("limit", 200))
    with db() as con:
        with con.cursor() as cur:
            cur.execute("SELECT * FROM share_violations ORDER BY id DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
    return jsonify(ok=True, violations=[rowdict(r) for r in rows])

@APP.route("/api/admin/events")
@require_admin
def api_admin_events():
    limit = int(request.args.get("limit", 200))
    with db() as con:
        with con.cursor() as cur:
            cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
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
    with db() as con:
        with con.cursor() as cur:
            cur.execute("INSERT INTO licenses(license_key, app_id, status, max_devices, expires_at, note, created_at, updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                (key, APP_ID, "active", max_devices, expires_at, note, iso(), iso()))
        con.commit()
    log_event(key, "created", "", f"days={days}, max_devices={max_devices}, note={note}")
    return jsonify(ok=True, license_key=key)

def _update_status(status):
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    with db() as con:
        with con.cursor() as cur:
            cur.execute("UPDATE licenses SET status=%s, updated_at=%s WHERE license_key=%s", (status, iso(), key))
        con.commit()
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
    with db() as con:
        with con.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE license_key=%s", (key,))
        con.commit()
    log_event(key, "admin_reset_devices")
    return jsonify(ok=True)

@APP.route("/api/admin/delete", methods=["POST"])
@require_admin
def api_admin_delete():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key") or "")
    with db() as con:
        with con.cursor() as cur:
            cur.execute("DELETE FROM devices WHERE license_key=%s", (key,))
            cur.execute("DELETE FROM share_violations WHERE license_key=%s", (key,))
            cur.execute("DELETE FROM cloud_accounts WHERE license_key=%s", (key,))
            cur.execute("DELETE FROM cloud_tokens WHERE license_key=%s", (key,))
            cur.execute("DELETE FROM licenses WHERE license_key=%s", (key,))
        con.commit()
    log_event(key, "admin_delete_key")
    return jsonify(ok=True)


# ============================================================
# INSTANT LOGIN TOKEN CLOUD SYNC - ADD-ONLY EXTENSION
# Stores/restores local MSAL token_cache files per license key.
# ============================================================
def instant_login_init_db():
    with db() as con:
        with con.cursor() as cur:
            cur.execute("""CREATE TABLE IF NOT EXISTS cloud_tokens (
                id SERIAL PRIMARY KEY,
                license_key TEXT NOT NULL,
                email TEXT NOT NULL,
                filename TEXT,
                token_text TEXT,
                token_size INTEGER DEFAULT 0,
                local_mtime TEXT,
                created_at TEXT NOT NULL,
                server_updated_at TEXT NOT NULL,
                deleted BOOLEAN NOT NULL DEFAULT FALSE,
                deleted_at TEXT,
                UNIQUE(license_key, email)
            )""")
            cur.execute("ALTER TABLE cloud_tokens ADD COLUMN IF NOT EXISTS filename TEXT")
            cur.execute("ALTER TABLE cloud_tokens ADD COLUMN IF NOT EXISTS token_text TEXT")
            cur.execute("ALTER TABLE cloud_tokens ADD COLUMN IF NOT EXISTS token_size INTEGER DEFAULT 0")
            cur.execute("ALTER TABLE cloud_tokens ADD COLUMN IF NOT EXISTS local_mtime TEXT")
            cur.execute("ALTER TABLE cloud_tokens ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT FALSE")
            cur.execute("ALTER TABLE cloud_tokens ADD COLUMN IF NOT EXISTS deleted_at TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cloud_tokens_license ON cloud_tokens(license_key)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cloud_tokens_license_email ON cloud_tokens(license_key, email)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_cloud_tokens_license_updated ON cloud_tokens(license_key, server_updated_at)")
        con.commit()


def _instant_token_to_dict(r):
    return {
        "email": r.get("email") or "",
        "filename": r.get("filename") or "",
        "token_text": r.get("token_text") or "",
        "token_size": int(r.get("token_size") or 0),
        "local_mtime": r.get("local_mtime") or "",
        "server_updated_at": r.get("server_updated_at") or "",
    }


@APP.route("/api/tokens/upsert", methods=["POST"])
def api_tokens_upsert():
    instant_login_init_db()
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    ok, err, _ = validate_license_for_cloud(
        license_key,
        data.get("device_id", ""),
        data.get("device_label", ""),
        data.get("fingerprint") or {},
        data.get("app") or data.get("app_id") or APP_ID,
    )
    if not ok:
        return err

    tokens = data.get("tokens")
    if tokens is None and isinstance(data.get("token"), dict):
        tokens = [data.get("token")]
    if not isinstance(tokens, list):
        return jsonify(ok=False, code="BAD_TOKENS", message="tokens must be list"), 400

    now = iso()
    clean = []
    seen = set()
    for raw in tokens:
        if not isinstance(raw, dict):
            continue
        email = str(raw.get("email", "")).strip().lower()
        token_text = str(raw.get("token_text", "") or "")
        if not email or "@" not in email or not token_text or email in seen:
            continue
        seen.add(email)
        clean.append({
            "email": email,
            "filename": str(raw.get("filename", "") or ""),
            "token_text": token_text,
            "token_size": int(raw.get("token_size") or len(token_text.encode("utf-8", errors="ignore"))),
            "local_mtime": str(raw.get("local_mtime", "") or ""),
        })

    with db() as con:
        with con.cursor() as cur:
            for item in clean:
                cur.execute("""
                    INSERT INTO cloud_tokens(
                        license_key, email, filename, token_text, token_size,
                        local_mtime, created_at, server_updated_at, deleted, deleted_at
                    )
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,FALSE,NULL)
                    ON CONFLICT (license_key, email)
                    DO UPDATE SET
                        filename=EXCLUDED.filename,
                        token_text=EXCLUDED.token_text,
                        token_size=EXCLUDED.token_size,
                        local_mtime=EXCLUDED.local_mtime,
                        server_updated_at=EXCLUDED.server_updated_at,
                        deleted=FALSE,
                        deleted_at=NULL
                """, (
                    license_key, item["email"], item["filename"], item["token_text"],
                    item["token_size"], item["local_mtime"], now, now,
                ))
        con.commit()
    log_event(license_key, "cloud_tokens_upsert", data.get("device_id", ""), f"count={len(clean)}")
    return jsonify(ok=True, count=len(clean), server_time=now)


@APP.route("/api/tokens/sync", methods=["POST"])
def api_tokens_sync():
    instant_login_init_db()
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    ok, err, _ = validate_license_for_cloud(
        license_key,
        data.get("device_id", ""),
        data.get("device_label", ""),
        data.get("fingerprint") or {},
        data.get("app") or data.get("app_id") or APP_ID,
    )
    if not ok:
        return err

    since = str(data.get("since") or "").strip()
    force = bool(data.get("force"))
    now = iso()
    with db() as con:
        with con.cursor() as cur:
            if force or not since:
                cur.execute("SELECT * FROM cloud_tokens WHERE license_key=%s AND deleted=FALSE ORDER BY id ASC", (license_key,))
                rows = cur.fetchall()
                deleted = []
            else:
                cur.execute("SELECT * FROM cloud_tokens WHERE license_key=%s AND server_updated_at > %s ORDER BY server_updated_at ASC", (license_key, since))
                rows = cur.fetchall()
                deleted = [r["email"] for r in rows if r.get("deleted")]
                rows = [r for r in rows if not r.get("deleted")]
    tokens = [_instant_token_to_dict(r) for r in rows]
    log_event(license_key, "cloud_tokens_sync", data.get("device_id", ""), f"tokens={len(tokens)}, deleted={len(deleted)}")
    return jsonify(ok=True, tokens=tokens, deleted_emails=deleted, server_time=now)


@APP.route("/api/tokens/delete", methods=["POST"])
def api_tokens_delete():
    instant_login_init_db()
    data = request.get_json(force=True, silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    ok, err, _ = validate_license_for_cloud(
        license_key,
        data.get("device_id", ""),
        data.get("device_label", ""),
        data.get("fingerprint") or {},
        data.get("app") or data.get("app_id") or APP_ID,
    )
    if not ok:
        return err
    emails = data.get("emails") or []
    if isinstance(data.get("email"), str):
        emails.append(data.get("email"))
    emails = sorted({str(e).strip().lower() for e in emails if str(e).strip()})
    now = iso()
    with db() as con:
        with con.cursor() as cur:
            for email in emails:
                cur.execute("UPDATE cloud_tokens SET deleted=TRUE, deleted_at=%s, server_updated_at=%s WHERE license_key=%s AND email=%s", (now, now, license_key, email))
        con.commit()
    log_event(license_key, "cloud_tokens_delete", data.get("device_id", ""), f"count={len(emails)}")
    return jsonify(ok=True, count=len(emails), server_time=now)

try:
    init_db()
    instant_login_init_db()
except Exception as e:
    print("[DB_INIT_ERROR]", e)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    APP.run(host="0.0.0.0", port=port)
