"""
Thornfield Estate Management System — Backend API
Flask + PostgreSQL | Run: python server.py
API available at http://localhost:5000/api
"""

import psycopg2
import psycopg2.extras
from decimal import Decimal
import json
import os
import secrets
import time
import re
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory, make_response

# bcrypt is the only acceptable algorithm for password storage.
# SHA-256 (even salted) is a fast hash — brute-forceable at billions/sec on GPUs.
# bcrypt is deliberately slow (cost factor 12 = ~0.3s/hash), making offline attacks impractical.
import bcrypt

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path='')

class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super().default(o)

app.json_encoder = DecimalEncoder
DATABASE_URL = os.environ["DATABASE_URL"]

# Role hierarchy — what each role can access
ROLE_PAGES = {
    "owner":   ["dashboard","assets","livestock","crops","workers","inventory","finance","reports","compliance","settings","users",'erp-dashboard','erp-profitability','erp-budgets','erp-activities','erp-costing','erp-production','erp-depreciation','erp-units','erp-seasons'],
    "manager": ["dashboard","assets","livestock","crops","workers","inventory","finance","reports","compliance",'erp-dashboard','erp-profitability','erp-budgets','erp-activities','erp-costing','erp-production','erp-depreciation','erp-units','erp-seasons'],
    "finance": ["dashboard","finance","reports","erp-dashboard","erp-profitability","erp-budgets","erp-costing"],
    "field":   ["dashboard","assets","livestock","crops"],
}

def hash_password(password: str) -> str:
    """Hash a password with bcrypt (cost 12). Returns a self-contained hash string."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

def verify_password(password: str, stored: str) -> bool:
    """Constant-time bcrypt comparison. Also handles legacy SHA-256 hashes for migration."""
    try:
        # bcrypt hashes start with $2b$ or $2a$
        if stored.startswith("$2"):
            return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
        # Legacy SHA-256 migration path — accept once, then re-hash on next login
        if ":" in stored:
            import hashlib
            salt, hashed = stored.split(":", 1)
            return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
        return False
    except Exception:
        return False


# ─── DB helpers ────────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

# ─── AUTH DECORATORS ───────────────────────────────────────────────────────────

def get_current_user():
    """
    Authenticate the request via the httpOnly session cookie.
    Falls back to Bearer token for API clients that cannot use cookies
    (e.g. server-to-server integrations) — but the primary path is cookie-based.
    Tokens are NEVER returned to or stored by the browser frontend.
    """
    token = None

    # Primary: httpOnly cookie (browser clients)
    cookie_token = request.cookies.get(SESSION_COOKIE)
    if cookie_token:
        token = cookie_token
    else:
        # Fallback: Bearer header (programmatic API clients only)
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]

    if not token:
        return None

    return query(
        "SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.id "
        "WHERE s.token=%s AND s.expires_at > NOW() AND u.active=1",
        (token,), one=True
    )


def _validate_csrf():
    """
    Validate the CSRF double-submit token on state-changing requests.
    The frontend stores the CSRF token in sessionStorage and sends it
    as X-CSRF-Token. We compare it against the value stored in the session.
    Safe methods (GET, HEAD, OPTIONS) are exempt.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True  # safe method
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not csrf_header:
        return False
    # Validate the token exists in the active session
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        # API clients using Bearer auth skip CSRF (they can't get CSRF tokens anyway)
        auth = request.headers.get("Authorization", "")
        return auth.startswith("Bearer ")
    row = query(
        "SELECT csrf_token FROM sessions WHERE token=%s AND expires_at > NOW()",
        (token,), one=True
    )
    if not row or not row["csrf_token"]:
        return False
    return secrets.compare_digest(csrf_header, row["csrf_token"])


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not _validate_csrf():
            log_security("CSRF_REJECTED", f"path={request.path}")
            return jsonify({"error": "Invalid or missing CSRF token"}), 403
        user = get_current_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        g.user = user
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not _validate_csrf():
                log_security("CSRF_REJECTED", f"path={request.path}")
                return jsonify({"error": "Invalid or missing CSRF token"}), 403
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            if user["role"] not in roles:
                log_security("AUTHZ_DENIED", f"role={user['role']} required={roles} path={request.path}", user_id=user["id"])
                return jsonify({"error": "Forbidden"}), 403
            g.user = user
            return f(*args, **kwargs)
        return decorated
    return decorator




def require_write_access(f):
    """
    Enforce write access. Field workers are read-only.
    Allowed to write: owner, manager, finance (finance routes only — enforced per-route).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(g, "user"):
            return jsonify({"error": "Unauthorized"}), 401
        if g.user["role"] == "field":
            log_security("WRITE_DENIED", f"role=field path={request.path}", user_id=g.user["id"])
            return jsonify({"error": "Forbidden — read-only role"}), 403
        return f(*args, **kwargs)
    return decorated


def query(sql, args=(), one=False):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def mutate(sql, args=()):
    """
    Execute a single-statement write and commit immediately.
    Use db_transaction() instead when you need multi-statement atomicity.
    """
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, args)
    returned_id = None
    if 'RETURNING' in sql.upper():
        try:
            row = cur.fetchone()
            returned_id = row["id"] if row and "id" in row else None
        except Exception:
            pass
    db.commit()
    return returned_id


from contextlib import contextmanager

@contextmanager
def db_transaction():
    """
    Context manager for atomic multi-statement transactions.

    Usage:
        with db_transaction() as (db, cur):
            cur.execute(...)
            cur.execute(...)
        # commits on clean exit, rolls back on any exception

    The caller should never call db.commit() or db.rollback() manually;
    the context manager owns those calls.
    """
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield db, cur
        db.commit()
    except Exception:
        db.rollback()
        raise


def tx_mutate(cur, sql, args=()):
    """
    Execute a single write statement within an existing db_transaction() cursor.
    Returns the RETURNING id if present, otherwise None.
    Never commits — the enclosing db_transaction() owns the commit.
    """
    cur.execute(sql, args)
    returned_id = None
    if 'RETURNING' in sql.upper():
        try:
            row = cur.fetchone()
            returned_id = row["id"] if row and "id" in row else None
        except Exception:
            pass
    return returned_id


def tx_query(cur, sql, args=(), one=False):
    """
    Execute a read statement within an existing db_transaction() cursor.
    Use this to read-with-lock (SELECT FOR UPDATE) inside a transaction.
    """
    cur.execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def write_audit(cur, action, record_type, record_id=None, record_label="",
                before=None, after=None, user_id=None):
    """
    Write an audit entry inside an existing transaction cursor.
    'before' and 'after' should be dicts; they are stored as JSONB.
    Call this inside every db_transaction() block that mutates financial
    or operational data.
    """
    cur.execute(
        """INSERT INTO audit_log
               (action, record_type, record_id, record_label,
                before_state, after_state, performed_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (
            action, record_type, record_id, record_label,
            json.dumps(before) if before else None,
            json.dumps(after)  if after  else None,
            user_id,
        )
    )


def check_idempotency(idempotency_key: str) -> bool:
    """
    Returns True if this key has been seen before (request is a duplicate).
    Inserts the key atomically on first use so concurrent retries are safe.
    Uses INSERT ... ON CONFLICT DO NOTHING — lockless and concurrency-safe.
    """
    if not idempotency_key:
        return False
    db = get_db()
    cur = db.cursor()
    cur.execute(
        """INSERT INTO idempotency_keys (key, created_at)
           VALUES (%s, NOW())
           ON CONFLICT (key) DO NOTHING""",
        (idempotency_key,)
    )
    inserted = cur.rowcount  # 1 = new key; 0 = already existed (duplicate)
    db.commit()
    return inserted == 0  # True means duplicate


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows):
    return [dict(r) for r in rows]


# ─── SECURITY CONFIGURATION ────────────────────────────────────────────────────

# Allowed origins for CORS. In production this must match your exact deployed domain.
# Set ALLOWED_ORIGIN env var to override (e.g. https://thornfield.yourdomain.com).
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "http://localhost:5000")

# Session cookie name
SESSION_COOKIE = "tf_session"
SESSION_DAYS   = 7

# Pre-computed dummy hash used in login() to prevent user-enumeration timing
# oracles. Generated once at startup so the ~0.3s bcrypt cost is not per-request.
# bcrypt.checkpw against this always returns False (wrong password by design).
_DUMMY_HASH = bcrypt.hashpw(
    b"dummy-timing-protection-placeholder",
    bcrypt.gensalt(rounds=12)
).decode("utf-8")

# ─── SECURITY LOGGING ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
security_log = logging.getLogger("security")

def log_security(event: str, detail: str = "", user_id=None):
    """Log security events without exposing passwords or tokens."""
    ip = request.remote_addr or "unknown"
    uid_str = f" user={user_id}" if user_id else ""
    security_log.warning(f"SECURITY [{event}] ip={ip}{uid_str} {detail}")


# ─── SERVER-SIDE RATE LIMITING (in-memory, per IP) ────────────────────────────
# For multi-process deployments, replace _rate_store with a Redis backend.
_rate_store: dict = {}   # ip -> {"count": int, "window_start": float, "locked_until": float}
RATE_LOGIN_MAX    = 10   # attempts per window
RATE_LOGIN_WINDOW = 900  # 15 minutes (seconds)
RATE_LOGIN_LOCK   = 900  # lockout duration (seconds)

def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Returns (allowed, seconds_remaining). Thread-safe only for single-process."""
    now = time.time()
    entry = _rate_store.get(ip, {"count": 0, "window_start": now, "locked_until": 0})

    if now < entry["locked_until"]:
        remaining = int(entry["locked_until"] - now)
        return False, remaining

    if now - entry["window_start"] > RATE_LOGIN_WINDOW:
        # Window expired — reset
        entry = {"count": 0, "window_start": now, "locked_until": 0}

    entry["count"] += 1
    if entry["count"] > RATE_LOGIN_MAX:
        entry["locked_until"] = now + RATE_LOGIN_LOCK
        _rate_store[ip] = entry
        log_security("RATE_LIMIT_TRIGGERED", f"ip={ip} count={entry['count']}")
        return False, RATE_LOGIN_LOCK

    _rate_store[ip] = entry
    return True, 0

def _reset_rate_limit(ip: str):
    _rate_store.pop(ip, None)


# ─── CORS (strict — no wildcard) ───────────────────────────────────────────────

@app.after_request
def add_security_headers(response):
    origin = request.headers.get("Origin", "")

    # CORS — only allow the configured origin, never wildcard
    if origin == ALLOWED_ORIGIN:
        response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,X-CSRF-Token"
    # Never expose Authorization in ACAO — tokens live in cookies now
    response.headers.pop("Access-Control-Allow-Headers-Authorization", None)

    # Security headers (also set these at the reverse-proxy / Railway level)
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]            = "DENY"
    response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"]  = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    # Remove headers that leak server info
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200


# ─── SCHEMA ────────────────────────────────────────────────────────────────────

def init_db():
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()
    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL,
            email       TEXT    NOT NULL UNIQUE,
            password    TEXT    NOT NULL,
            role        TEXT    NOT NULL DEFAULT 'field' CHECK(role IN ('owner','manager','finance','field')),
            active      INTEGER NOT NULL DEFAULT 1,
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            last_login  TIMESTAMPTZ
        )""",
        """CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT    PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf_token  TEXT    NOT NULL DEFAULT '',
            expires_at  TIMESTAMPTZ NOT NULL,
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            user_agent  TEXT,
            ip_address  TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS assets (
            id          SERIAL PRIMARY KEY,
            asset_id    TEXT    NOT NULL UNIQUE,
            description TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            location    TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'Operational',
            last_service TEXT,
            notes       TEXT,
            value       NUMERIC DEFAULT 0,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS livestock (
            id          SERIAL PRIMARY KEY,
            herd_name   TEXT    NOT NULL,
            breed       TEXT    NOT NULL,
            count       INTEGER NOT NULL DEFAULT 0,
            avg_weight  NUMERIC DEFAULT 0,
            health      TEXT    NOT NULL DEFAULT 'Good',
            status      TEXT    NOT NULL DEFAULT 'Grazing',
            location    TEXT,
            notes       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS livestock_events (
            id          SERIAL PRIMARY KEY,
            livestock_id INTEGER REFERENCES livestock(id) ON DELETE CASCADE,
            event_type  TEXT    NOT NULL,
            description TEXT    NOT NULL,
            event_date  TEXT    NOT NULL,
            status      TEXT    DEFAULT 'Pending',
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS crops (
            id          SERIAL PRIMARY KEY,
            block       TEXT    NOT NULL UNIQUE,
            crop        TEXT,
            area_ha     NUMERIC NOT NULL,
            planted     TEXT,
            est_harvest TEXT,
            status      TEXT    NOT NULL DEFAULT 'Fallow',
            irrigation  TEXT,
            irrigation_pct INTEGER DEFAULT 0,
            est_yield_value NUMERIC DEFAULT 0,
            notes       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS workers (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL,
            initials    TEXT    NOT NULL,
            role        TEXT    NOT NULL,
            department  TEXT,
            status      TEXT    NOT NULL DEFAULT 'Present',
            salary      NUMERIC DEFAULT 0,
            phone       TEXT,
            email       TEXT,
            start_date  TEXT,
            notes       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS inventory (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL UNIQUE,
            category    TEXT    NOT NULL,
            unit        TEXT    NOT NULL,
            on_hand     NUMERIC NOT NULL DEFAULT 0,
            par_level   NUMERIC NOT NULL DEFAULT 0,
            max_level   NUMERIC NOT NULL DEFAULT 0,
            unit_cost   NUMERIC DEFAULT 0,
            supplier    TEXT,
            notes       TEXT,
            last_updated TIMESTAMPTZ DEFAULT NOW(),
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS finance (
            id          SERIAL PRIMARY KEY,
            type        TEXT    NOT NULL CHECK(type IN ('income','expense')),
            category    TEXT    NOT NULL,
            description TEXT    NOT NULL,
            amount      NUMERIC NOT NULL,
            date        TEXT    NOT NULL,
            reference   TEXT,
            notes       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS compliance (
            id          SERIAL PRIMARY KEY,
            title       TEXT    NOT NULL,
            category    TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'Compliant',
            issued_date TEXT,
            expiry_date TEXT,
            issuing_body TEXT,
            notes       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS invite_tokens (
            token       TEXT    PRIMARY KEY,
            role        TEXT    NOT NULL DEFAULT 'field',
            created_by  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            used_by     INTEGER REFERENCES users(id),
            expires_at  TIMESTAMPTZ NOT NULL,
            used_at     TIMESTAMPTZ,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS password_reset_tokens (
            token       TEXT    PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at  TIMESTAMPTZ NOT NULL,
            used_at     TIMESTAMPTZ,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS audit_log (
            id           SERIAL PRIMARY KEY,
            action       TEXT    NOT NULL,
            record_type  TEXT    NOT NULL,
            record_id    INTEGER,
            record_label TEXT,
            before_state JSONB,
            after_state  JSONB,
            performed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at   TIMESTAMPTZ DEFAULT NOW()
        )""",
        # Idempotency keys — prevent duplicate processing of retried requests
        """CREATE TABLE IF NOT EXISTS idempotency_keys (
            key         TEXT        PRIMARY KEY,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        """CREATE TABLE IF NOT EXISTS reports (
            id          SERIAL PRIMARY KEY,
            title       TEXT    NOT NULL,
            type        TEXT,
            status      TEXT    DEFAULT 'Draft',
            created_by  TEXT,
            content     TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
    ]
    for ddl in tables:
        cur.execute(ddl)
    # ── Migrations: safe to run on every startup ──────────────────────────────
    migrations = [
        # Sessions
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS csrf_token TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address TEXT",
        # Audit log — before/after state columns
        "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS before_state JSONB",
        "ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS after_state  JSONB",
        # Finance — amount must be positive; type constrained
        "ALTER TABLE finance ADD CONSTRAINT IF NOT EXISTS finance_amount_positive CHECK (amount > 0)",
        # Inventory — on_hand cannot go below zero
        "ALTER TABLE inventory ADD CONSTRAINT IF NOT EXISTS inventory_nonneg_stock CHECK (on_hand >= 0)",
        # Inventory lots — quantities cannot go negative
        "ALTER TABLE inventory_lots ADD CONSTRAINT IF NOT EXISTS lot_nonneg_remaining CHECK (quantity_remaining >= 0)",
        "ALTER TABLE inventory_lots ADD CONSTRAINT IF NOT EXISTS lot_nonneg_received  CHECK (quantity_received >= 0)",
        # Livestock — count cannot be negative
        "ALTER TABLE livestock ADD CONSTRAINT IF NOT EXISTS livestock_nonneg_count CHECK (count >= 0)",
        # Workers — salary non-negative
        "ALTER TABLE workers ADD CONSTRAINT IF NOT EXISTS workers_nonneg_salary CHECK (salary >= 0)",
        # Idempotency key TTL index (allows cleaning up old keys)
        "CREATE INDEX IF NOT EXISTS idx_idem_created ON idempotency_keys(created_at)",
    ]
    for sql in migrations:
        try:
            cur.execute(sql)
        except Exception:
            pass  # Constraint/column already exists
    db.commit()
    db.close()
# seed_owner() removed — create your owner account via the /api/auth/register
# endpoint using an invite token, or directly in the database.
# Never hardcode credentials in production code.

# ─── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
def register():
    """
    Public registration using a valid invite token.
    The invite must exist, be unused, and not expired.
    No auth header required — the invite token is the credential.
    """
    d = request.get_json() or {}
    name     = d.get("name", "").strip()
    email    = d.get("email", "").strip().lower()
    password = d.get("password", "")
    token    = d.get("invite_token", "").strip()

    if not name or not email or not password or not token:
        return jsonify({"error": "Name, email, password and invite_token are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    # Validate the invite token
    invite = query(
        "SELECT * FROM invite_tokens WHERE token=%s AND used_at IS NULL AND expires_at > NOW()",
        (token,), one=True
    )
    if not invite:
        return jsonify({"error": "Invalid or expired invite code"}), 400

    # Check email not already taken
    if query("SELECT id FROM users WHERE email=%s", (email,), one=True):
        return jsonify({"error": "An account with that email already exists"}), 409

    role = invite["role"]
    if role not in ROLE_PAGES:
        role = "field"

    pw = hash_password(password)
    new_id = mutate(
        "INSERT INTO users (name,email,password,role) VALUES (%s,%s,%s,%s) RETURNING id",
        (name, email, pw, role)
    )

    # Mark invite as consumed
    mutate(
        "UPDATE invite_tokens SET used_at=NOW(), used_by=%s WHERE token=%s",
        (new_id, token)
    )

    row = query("SELECT id,name,email,role,active,created_at FROM users WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/auth/invite", methods=["POST"])
@require_role("owner", "manager")
def create_invite():
    """
    Generate a single-use invite token (owner or manager only).
    Token expires in 24 hours.
    """
    d = request.get_json() or {}
    role = d.get("role", "field")
    if role not in ROLE_PAGES:
        role = "field"
    # Managers can only invite field/finance users, not owners
    if g.user["role"] == "manager" and role in ("owner", "manager"):
        return jsonify({"error": "Managers can only invite field or finance users"}), 403

    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    mutate(
        "INSERT INTO invite_tokens (token, role, created_by, expires_at) VALUES (%s,%s,%s,%s)",
        (token, role, g.user["id"], expires)
    )
    return jsonify({
        "invite_token": token,
        "role": role,
        "expires_at": expires,
        "expires_in": "24 hours"
    }), 201


@app.route("/api/auth/invite", methods=["GET"])
@require_role("owner")
def list_invites():
    """List all invite tokens (owner only) — useful for auditing."""
    rows = query("""
        SELECT i.token, i.role, i.expires_at, i.used_at, i.created_at,
               u.name as created_by_name,
               uu.name as used_by_name
        FROM invite_tokens i
        JOIN users u ON i.created_by = u.id
        LEFT JOIN users uu ON i.used_by = uu.id
        ORDER BY i.created_at DESC
        LIMIT 50
    """)
    return jsonify(rows_to_list(rows))


@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    """
    Request a password reset link.
    Always returns 200 — never reveals whether the email exists (prevents enumeration).
    In production, send the token via email. Here we return it in the response
    so you can wire up email sending (e.g. SendGrid) without breaking the contract.
    """
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()
    if not email:
        return jsonify({"message": "If that email exists, a reset link has been sent"}), 200

    user = query("SELECT id FROM users WHERE email=%s AND active=1", (email,), one=True)
    if not user:
        # Return 200 regardless — don't leak whether email exists
        return jsonify({"message": "If that email exists, a reset link has been sent"}), 200

    # Invalidate any existing unused tokens for this user
    mutate(
        "UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=%s AND used_at IS NULL",
        (user["id"],)
    )

    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    mutate(
        "INSERT INTO password_reset_tokens (token, user_id, expires_at) VALUES (%s,%s,%s)",
        (token, user["id"], expires)
    )

    # TODO: Send email here via SendGrid / Mailgun / SES:
    #   send_reset_email(email, token)
    # Reset link would be: https://your-domain.com/%sreset_token=<token>
    # For now we log it so you can test end-to-end without email infra
    print(f"  [PASSWORD RESET] token for {email}: {token} (expires {expires})")

    return jsonify({"message": "If that email exists, a reset link has been sent"}), 200


@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    """
    Consume a reset token and set a new password.
    """
    d = request.get_json() or {}
    token    = d.get("token", "").strip()
    password = d.get("password", "")

    if not token or not password:
        return jsonify({"error": "Token and new password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    row = query(
        "SELECT * FROM password_reset_tokens WHERE token=%s AND used_at IS NULL AND expires_at > NOW()",
        (token,), one=True
    )
    if not row:
        return jsonify({"error": "Reset link is invalid or has expired"}), 400

    pw = hash_password(password)
    mutate("UPDATE users SET password=%s WHERE id=%s", (pw, row["user_id"]))
    mutate(
        "UPDATE password_reset_tokens SET used_at=NOW() WHERE token=%s",
        (token,)
    )
    # Invalidate all sessions for this user so stolen sessions can't persist after a reset
    mutate("DELETE FROM sessions WHERE user_id=%s", (row["user_id"],))

    return jsonify({"message": "Password updated. Please sign in with your new password."}), 200





@app.route("/api/auth/login", methods=["POST"])
def login():
    import traceback
    try:
        ip = request.remote_addr or "unknown"

        # ── Server-side rate limiting ─────────────────────────────────────────
        allowed, wait_secs = _check_rate_limit(ip)
        if not allowed:
            log_security("LOGIN_RATE_LIMITED", f"ip={ip} retry_after={wait_secs}s")
            return jsonify({
                "error": f"Too many login attempts. Please wait {wait_secs} seconds before trying again."
            }), 429

        d = request.get_json() or {}
        email    = (d.get("email") or "").strip().lower()
        password = d.get("password") or ""

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        # Basic email format check — prevent abuse of long inputs
        if len(email) > 254 or len(password) > 1024:
            return jsonify({"error": "Invalid credentials"}), 400

        user = query("SELECT * FROM users WHERE email=%s AND active=1", (email,), one=True)

        # Always run password verification even on miss (prevents timing oracle).
        # _DUMMY_HASH is a valid bcrypt hash generated at startup — guaranteed not
        # to throw, and always returns False (wrong password by design).
        stored = user["password"] if user else _DUMMY_HASH
        pw_ok  = verify_password(password, stored)

        if not user or not pw_ok:
            log_security("LOGIN_FAILED", f"email={email}")
            return jsonify({"error": "Invalid email or password"}), 401

        # ── Re-hash legacy SHA-256 passwords to bcrypt on first successful login ──
        if user["password"].startswith("$2") is False and ":" in user["password"]:
            new_hash = hash_password(password)
            mutate("UPDATE users SET password=%s WHERE id=%s", (new_hash, user["id"]))
            log_security("PASSWORD_REHASHED", "legacy SHA-256 → bcrypt", user_id=user["id"])

        # ── Create session ────────────────────────────────────────────────────
        token      = secrets.token_hex(32)
        csrf_token = secrets.token_urlsafe(32)
        expires    = datetime.utcnow() + timedelta(days=SESSION_DAYS)
        expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

        mutate(
            "INSERT INTO sessions (token, user_id, csrf_token, expires_at, user_agent, ip_address) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (token, user["id"], csrf_token, expires_str,
             request.headers.get("User-Agent", "")[:512], ip)
        )
        mutate("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))
        _reset_rate_limit(ip)  # Clear failed attempts on success

        log_security("LOGIN_SUCCESS", f"email={email}", user_id=user["id"])

        # ── Set httpOnly session cookie ───────────────────────────────────────
        # The cookie is:
        #   httpOnly  — inaccessible to JavaScript (prevents XSS token theft)
        #   Secure    — only sent over HTTPS
        #   SameSite=Strict — not sent on cross-site requests (CSRF defence layer 1)
        is_production = os.environ.get("FLASK_ENV") != "development"
        resp = make_response(jsonify({
            "user": {
                "id":    user["id"],
                "name":  user["name"],
                "email": user["email"],
                "role":  user["role"],
                "pages": ROLE_PAGES.get(user["role"], [])
            },
            # Return the CSRF token in the JSON body — the frontend stores it in
            # sessionStorage and sends it as X-CSRF-Token on every mutating request.
            # This implements the double-submit cookie CSRF pattern.
            "csrf_token": csrf_token
        }))
        resp.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            secure=is_production,
            samesite="Strict",
            max_age=SESSION_DAYS * 86400,
            path="/",
        )
        return resp

    except Exception as e:
        import traceback as tb
        tb.print_exc()
        # Never leak internal error details to the client
        log_security("LOGIN_ERROR", str(e))
        return jsonify({"error": "Server error. Please try again."}), 500


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        # Fallback: Bearer header (API clients)
        auth = request.headers.get("Authorization", "")[7:]
        token = auth
    if token:
        mutate("DELETE FROM sessions WHERE token=%s", (token,))
        log_security("LOGOUT", "", user_id=g.user.get("id"))

    resp = make_response(jsonify({"message": "Logged out"}))
    # Overwrite the cookie with an expired one to force the browser to delete it
    resp.set_cookie(
        SESSION_COOKIE, "",
        httponly=True, secure=True, samesite="Strict",
        max_age=0, path="/"
    )
    return resp


@app.route("/api/auth/me", methods=["GET", "HEAD"])
def me():
    """
    Session validation endpoint. Called on page load to restore a session.
    For GET: returns user profile + a fresh CSRF token.
    For HEAD: just confirms the session is valid (used by connectivity monitor).
    No @require_auth here — we handle auth manually to skip CSRF check on GET
    (this is a safe read-only endpoint used to bootstrap auth state).
    """
    if request.method == "HEAD":
        user = get_current_user()
        return ("", 200) if user else ("", 401)

    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    # Fetch the csrf_token for the current session so the frontend can send it
    token = request.cookies.get(SESSION_COOKIE) or ""
    sess  = query("SELECT csrf_token FROM sessions WHERE token=%s", (token,), one=True)
    csrf  = sess["csrf_token"] if sess else ""

    return jsonify({
        "id":         user["id"],
        "name":       user["name"],
        "email":      user["email"],
        "role":       user["role"],
        "pages":      ROLE_PAGES.get(user["role"], []),
        "csrf_token": csrf,
    })


@app.route("/api/health", methods=["GET", "HEAD"])
def health():
    """Lightweight liveness probe — no auth required."""
    if request.method == "HEAD":
        return "", 200
    return jsonify({"status": "ok", "service": "thornfield-estate"}), 200

# ─── FIRST-TIME SETUP (owner bootstrap — only works when zero users exist) ─────

@app.route("/api/auth/bootstrap", methods=["POST"])
def bootstrap_owner():
    """
    Creates the first owner account. Only works when the users table is empty.
    Call this once after deploying to a fresh database, then remove or lock it.
    POST { "name": "...", "email": "...", "password": "..." }
    """
    # Refuse if any users already exist — prevents privilege escalation
    existing = query("SELECT COUNT(*) as n FROM users", one=True)
    if int(existing["n"]) > 0:
        return jsonify({"error": "Setup already complete. This endpoint is disabled."}), 403

    d = request.get_json() or {}
    name     = d.get("name", "").strip()
    email    = d.get("email", "").strip().lower()
    password = d.get("password", "")

    if not name or not email or not password:
        return jsonify({"error": "name, email and password are required"}), 400
    if len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters for the owner account"}), 400

    pw = hash_password(password)
    new_id = mutate(
        "INSERT INTO users (name,email,password,role) VALUES (%s,%s,%s,%s) RETURNING id",
        (name, email, pw, "owner")
    )
    print(f"[bootstrap] Owner account created: {email}")
    row = query("SELECT id,name,email,role,created_at FROM users WHERE id=%s", (new_id,), one=True)
    return jsonify({"message": "Owner account created. Sign in to continue.", "user": row_to_dict(row)}), 201




# ─── USER MANAGEMENT (owner only) ──────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
@require_role("owner")
def get_users():
    rows = query("SELECT id,name,email,role,active,created_at,last_login FROM users ORDER BY name")
    return jsonify(rows_to_list(rows))


@app.route("/api/users", methods=["POST"])
@require_role("owner")
def create_user():
    """
    Owner-direct user creation — no invite token required.
    Used when the owner adds a user from the Users management page.
    """
    d = request.get_json() or {}
    name     = d.get("name", "").strip()
    email    = d.get("email", "").strip().lower()
    password = d.get("password", "")
    role     = d.get("role", "field")
    active   = int(d.get("active", 1))

    if not name or not email or not password:
        return jsonify({"error": "Name, email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if role not in ROLE_PAGES:
        role = "field"
    if query("SELECT id FROM users WHERE email=%s", (email,), one=True):
        return jsonify({"error": "An account with that email already exists"}), 409

    pw = hash_password(password)
    new_id = mutate(
        "INSERT INTO users (name,email,password,role,active) VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (name, email, pw, role, active)
    )
    row = query("SELECT id,name,email,role,active,created_at FROM users WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/users/<int:uid>", methods=["PUT"])
@require_role("owner")
def update_user(uid):
    d = request.get_json()
    if "password" in d and d["password"]:
        pw = hash_password(d["password"])
        mutate("UPDATE users SET name=%s,email=%s,role=%s,active=%s,password=%s WHERE id=%s",
               (d["name"], d["email"], d["role"], int(d.get("active",1)), pw, uid))
    else:
        mutate("UPDATE users SET name=%s,email=%s,role=%s,active=%s WHERE id=%s",
               (d["name"], d["email"], d["role"], int(d.get("active",1)), uid))
    row = query("SELECT id,name,email,role,active,created_at FROM users WHERE id=%s", (uid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@require_role("owner")
def delete_user(uid):
    if uid == g.user["id"]:
        return jsonify({"error": "Cannot delete your own account"}), 400
    mutate("DELETE FROM users WHERE id=%s", (uid,))
    return jsonify({"deleted": uid})


# ─── ASSETS ────────────────────────────────────────────────────────────────────

@app.route("/api/assets", methods=["GET"])
@require_auth
def get_assets():
    rows = query("SELECT * FROM assets ORDER BY asset_id")
    return jsonify(rows_to_list(rows))


@app.route("/api/assets/<int:asset_id>", methods=["GET"])
@require_auth
def get_asset(asset_id):
    row = query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row))


@app.route("/api/assets", methods=["POST"])
@require_auth
@require_write_access
def create_asset():
    d = request.get_json()
    # Auto-generate asset_id if not provided
    if not d.get("asset_id"):
        last = query("SELECT asset_id FROM assets ORDER BY id DESC LIMIT 1", one=True)
        if last:
            num = int(last["asset_id"].split("-")[1]) + 1
        else:
            num = 1
        d["asset_id"] = f"AST-{num:03d}"
    try:
        new_id = mutate(
            "INSERT INTO assets (asset_id,description,category,location,status,last_service,notes,value) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (d["asset_id"], d["description"], d["category"], d["location"],
             d.get("status","Operational"), d.get("last_service"), d.get("notes"), d.get("value", 0))
        )
        row = query("SELECT * FROM assets WHERE id=%s", (new_id,), one=True)
        return jsonify(row_to_dict(row)), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/assets/<int:asset_id>", methods=["PUT"])
@require_auth
@require_write_access
def update_asset(asset_id):
    d = request.get_json()
    mutate(
        """UPDATE assets SET description=%s,category=%s,location=%s,status=%s,
           last_service=%s,notes=%s,value=%s WHERE id=%s""",
        (d["description"], d["category"], d["location"], d["status"],
         d.get("last_service"), d.get("notes"), d.get("value", 0), asset_id)
    )
    row = query("SELECT * FROM assets WHERE id=%s", (asset_id,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_asset(asset_id):
    mutate("DELETE FROM assets WHERE id=%s", (asset_id,))
    return jsonify({"deleted": asset_id})


# ─── LIVESTOCK ─────────────────────────────────────────────────────────────────

@app.route("/api/livestock", methods=["GET"])
@require_auth
def get_livestock():
    rows = query("SELECT * FROM livestock ORDER BY id")
    return jsonify(rows_to_list(rows))


@app.route("/api/livestock/<int:lid>", methods=["GET"])
@require_auth
def get_herd(lid):
    row = query("SELECT * FROM livestock WHERE id=%s", (lid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    events = query("SELECT * FROM livestock_events WHERE livestock_id=%s ORDER BY event_date DESC", (lid,))
    d = row_to_dict(row)
    d["events"] = rows_to_list(events)
    return jsonify(d)


@app.route("/api/livestock", methods=["POST"])
@require_auth
@require_write_access
def create_herd():
    d = request.get_json()
    new_id = mutate(
        "INSERT INTO livestock (herd_name,breed,count,avg_weight,health,status,location,notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["herd_name"], d["breed"], d.get("count",0), d.get("avg_weight",0),
         d.get("health","Good"), d.get("status","Grazing"), d.get("location"), d.get("notes"))
    )
    row = query("SELECT * FROM livestock WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/livestock/<int:lid>", methods=["PUT"])
@require_auth
@require_write_access
def update_herd(lid):
    """Update herd record. Count changes are audited with before/after state."""
    d = request.get_json() or {}
    user = g.user
    try:
        with db_transaction() as (db, cur):
            before = tx_query(cur, "SELECT * FROM livestock WHERE id=%s FOR UPDATE", (lid,), one=True)
            if not before:
                raise ValueError("Herd not found")
            new_count = int(d.get("count", 0))
            if new_count < 0:
                raise ValueError("Livestock count cannot be negative")
            cur.execute(
                "UPDATE livestock SET herd_name=%s,breed=%s,count=%s,avg_weight=%s,health=%s,status=%s,location=%s,notes=%s WHERE id=%s",
                (d["herd_name"], d["breed"], new_count, d.get("avg_weight",0),
                 d.get("health","Good"), d.get("status","Grazing"), d.get("location"), d.get("notes"), lid)
            )
            if int(before.get("count") or 0) != new_count:
                write_audit(cur,
                    action="UPDATE",
                    record_type="livestock",
                    record_id=lid,
                    record_label=d["herd_name"],
                    before={"count": before["count"], "health": before["health"]},
                    after={"count": new_count, "health": d.get("health","Good")},
                    user_id=user["id"]
                )
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        return jsonify({"error": "Could not update herd"}), 500
    row = query("SELECT * FROM livestock WHERE id=%s", (lid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/livestock/<int:lid>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_herd(lid):
    """Delete a herd record. Writes an audit entry before deletion."""
    user = g.user
    try:
        with db_transaction() as (db, cur):
            row = tx_query(cur, "SELECT * FROM livestock WHERE id=%s FOR UPDATE", (lid,), one=True)
            if not row:
                raise ValueError("Herd not found")
            cur.execute("DELETE FROM livestock WHERE id=%s", (lid,))
            write_audit(cur,
                action="DELETE",
                record_type="livestock",
                record_id=lid,
                record_label=row["herd_name"],
                before={"herd_name": row["herd_name"], "count": row["count"], "breed": row["breed"]},
                user_id=user["id"]
            )
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception:
        return jsonify({"error": "Could not delete herd"}), 500
    return jsonify({"deleted": lid})


@app.route("/api/livestock/<int:lid>/events", methods=["POST"])
@require_auth
@require_write_access
def add_livestock_event(lid):
    d = request.get_json()
    new_id = mutate(
        "INSERT INTO livestock_events (livestock_id,event_type,description,event_date,status) VALUES (%s,%s,%s,%s,%s)",
        (lid, d["event_type"], d["description"], d["event_date"], d.get("status","Pending"))
    )
    row = query("SELECT * FROM livestock_events WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/livestock/events/all", methods=["GET"])
@require_auth
def get_all_events():
    rows = query("""
        SELECT e.*, l.herd_name FROM livestock_events e
        JOIN livestock l ON e.livestock_id = l.id
        ORDER BY e.event_date DESC
    """)
    return jsonify(rows_to_list(rows))


# ─── CROPS ─────────────────────────────────────────────────────────────────────

@app.route("/api/crops", methods=["GET"])
@require_auth
def get_crops():
    rows = query("SELECT * FROM crops ORDER BY block")
    return jsonify(rows_to_list(rows))


@app.route("/api/crops/<int:cid>", methods=["GET"])
@require_auth
def get_crop(cid):
    row = query("SELECT * FROM crops WHERE id=%s", (cid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row))


@app.route("/api/crops", methods=["POST"])
@require_auth
@require_write_access
def create_crop():
    d = request.get_json()
    new_id = mutate(
        "INSERT INTO crops (block,crop,area_ha,planted,est_harvest,status,irrigation,irrigation_pct,est_yield_value,notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["block"], d.get("crop"), d["area_ha"], d.get("planted"), d.get("est_harvest"),
         d.get("status","Fallow"), d.get("irrigation","—"), d.get("irrigation_pct",0),
         d.get("est_yield_value",0), d.get("notes"))
    )
    row = query("SELECT * FROM crops WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/crops/<int:cid>", methods=["PUT"])
@require_auth
@require_write_access
def update_crop(cid):
    d = request.get_json()
    mutate(
        "UPDATE crops SET block=%s,crop=%s,area_ha=%s,planted=%s,est_harvest=%s,status=%s,irrigation=%s,irrigation_pct=%s,est_yield_value=%s,notes=%s WHERE id=%s",
        (d["block"], d.get("crop"), d["area_ha"], d.get("planted"), d.get("est_harvest"),
         d.get("status","Fallow"), d.get("irrigation","—"), d.get("irrigation_pct",0),
         d.get("est_yield_value",0), d.get("notes"), cid)
    )
    row = query("SELECT * FROM crops WHERE id=%s", (cid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/crops/<int:cid>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_crop(cid):
    mutate("DELETE FROM crops WHERE id=%s", (cid,))
    return jsonify({"deleted": cid})


# ─── WORKERS ───────────────────────────────────────────────────────────────────

@app.route("/api/workers", methods=["GET"])
@require_auth
def get_workers():
    rows = query("SELECT * FROM workers ORDER BY name")
    return jsonify(rows_to_list(rows))


@app.route("/api/workers/<int:wid>", methods=["GET"])
@require_auth
def get_worker(wid):
    row = query("SELECT * FROM workers WHERE id=%s", (wid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row))


@app.route("/api/workers", methods=["POST"])
@require_auth
@require_write_access
def create_worker():
    d = request.get_json()
    initials = d.get("initials") or "".join(w[0].upper() for w in d["name"].split()[:2])
    new_id = mutate(
        "INSERT INTO workers (name,initials,role,department,status,salary,phone,email,start_date,notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["name"], initials, d["role"], d.get("department"), d.get("status","Present"),
         d.get("salary",0), d.get("phone"), d.get("email"), d.get("start_date"), d.get("notes"))
    )
    row = query("SELECT * FROM workers WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/workers/<int:wid>", methods=["PUT"])
@require_auth
@require_write_access
def update_worker(wid):
    d = request.get_json()
    mutate(
        "UPDATE workers SET name=%s,initials=%s,role=%s,department=%s,status=%s,salary=%s,phone=%s,email=%s,start_date=%s,notes=%s WHERE id=%s",
        (d["name"], d.get("initials"), d["role"], d.get("department"), d.get("status","Present"),
         d.get("salary",0), d.get("phone"), d.get("email"), d.get("start_date"), d.get("notes"), wid)
    )
    row = query("SELECT * FROM workers WHERE id=%s", (wid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/workers/<int:wid>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_worker(wid):
    mutate("DELETE FROM workers WHERE id=%s", (wid,))
    return jsonify({"deleted": wid})


# ─── INVENTORY ─────────────────────────────────────────────────────────────────

@app.route("/api/inventory", methods=["GET"])
@require_auth
def get_inventory():
    rows = query("SELECT * FROM inventory ORDER BY name")
    return jsonify(rows_to_list(rows))


@app.route("/api/inventory/<int:iid>", methods=["GET"])
@require_auth
def get_inventory_item(iid):
    row = query("SELECT * FROM inventory WHERE id=%s", (iid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row))


@app.route("/api/inventory", methods=["POST"])
@require_auth
@require_write_access
def create_inventory_item():
    d = request.get_json()
    new_id = mutate(
        "INSERT INTO inventory (name,category,unit,on_hand,par_level,max_level,unit_cost,supplier,notes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["name"], d["category"], d["unit"], d.get("on_hand",0), d.get("par_level",0),
         d.get("max_level",0), d.get("unit_cost",0), d.get("supplier"), d.get("notes"))
    )
    row = query("SELECT * FROM inventory WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/inventory/<int:iid>", methods=["PUT"])
@require_auth
@require_write_access
def update_inventory_item(iid):
    d = request.get_json()
    mutate(
        "UPDATE inventory SET name=%s,category=%s,unit=%s,on_hand=%s,par_level=%s,max_level=%s,unit_cost=%s,supplier=%s,notes=%s,last_updated=NOW() WHERE id=%s",
        (d["name"], d["category"], d["unit"], d.get("on_hand",0), d.get("par_level",0),
         d.get("max_level",0), d.get("unit_cost",0), d.get("supplier"), d.get("notes"), iid)
    )
    row = query("SELECT * FROM inventory WHERE id=%s", (iid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/inventory/<int:iid>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_inventory_item(iid):
    """Soft-delete: marks inventory item inactive rather than erasing stock history."""
    user = g.user
    try:
        with db_transaction() as (db, cur):
            row = tx_query(cur, "SELECT * FROM inventory WHERE id=%s FOR UPDATE", (iid,), one=True)
            if not row:
                raise ValueError("Inventory item not found")
            if float(row.get("on_hand") or 0) > 0:
                raise ValueError(
                    f"Cannot delete '{row['name']}' — it has {row['on_hand']} units on hand. "
                    f"Adjust stock to zero before deleting."
                )
            cur.execute("DELETE FROM inventory WHERE id=%s", (iid,))
            write_audit(cur,
                action="DELETE",
                record_type="inventory",
                record_id=iid,
                record_label=row["name"],
                before={"name": row["name"], "on_hand": float(row["on_hand"] or 0)},
                user_id=user["id"]
            )
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception:
        return jsonify({"error": "Could not delete inventory item"}), 500
    return jsonify({"deleted": iid})


# ─── FINANCE ───────────────────────────────────────────────────────────────────

@app.route("/api/finance", methods=["GET"])
@require_auth
def get_finance():
    rows = query("SELECT * FROM finance ORDER BY date DESC")
    return jsonify(rows_to_list(rows))


@app.route("/api/finance/summary", methods=["GET"])
@require_auth
def get_finance_summary():
    income = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='income'", one=True)
    expense = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='expense'", one=True)
    by_category = query("""
        SELECT type, category, COALESCE(SUM(amount),0) as total
        FROM finance GROUP BY type, category ORDER BY type, total DESC
    """)
    total_income = income["total"]
    total_expense = expense["total"]
    return jsonify({
        "total_income": total_income,
        "total_expense": total_expense,
        "net_profit": total_income - total_expense,
        "margin_pct": round((total_income - total_expense) / total_income * 100, 1) if total_income else 0,
        "by_category": rows_to_list(by_category)
    })


@app.route("/api/finance", methods=["POST"])
@require_auth
@require_write_access
def create_finance_record():
    """
    Manually create a finance entry. Validates required fields server-side.
    Idempotency-Key header supported to prevent double-posting on retry.
    """
    idem_key = request.headers.get("Idempotency-Key", "")
    if idem_key and check_idempotency(idem_key):
        return jsonify({"error": "Duplicate request — this finance entry has already been recorded"}), 409

    d = request.get_json() or {}
    required = ["type", "category", "description", "amount", "date"]
    missing = [f for f in required if not d.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400
    if d["type"] not in ("income", "expense"):
        return jsonify({"error": "type must be 'income' or 'expense'"}), 422
    try:
        amount = float(d["amount"])
        if amount <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify({"error": "amount must be a positive number"}), 422

    user = g.user
    new_id = None
    try:
        with db_transaction() as (db, cur):
            new_id = tx_mutate(cur,
                """INSERT INTO finance (type,category,description,amount,date,reference,notes)
                   VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (d["type"], d["category"], d["description"], amount,
                 d["date"], d.get("reference"), d.get("notes"))
            )
            write_audit(cur,
                action="CREATE",
                record_type="finance",
                record_id=new_id,
                record_label=d["description"],
                after={"type": d["type"], "amount": amount, "category": d["category"]},
                user_id=user["id"]
            )
    except Exception as e:
        log_security("FINANCE_CREATE_ERROR", str(e), user_id=user.get("id"))
        return jsonify({"error": "Finance entry could not be saved"}), 500

    row = query("SELECT * FROM finance WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/finance/<int:fid>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_finance_record(fid):
    """
    Soft-delete a finance record: marks it voided rather than erasing it.
    Financial history must never be permanently destroyed — ERP compliance requirement.
    Hard deletes are only permitted by a DBA directly on the database.
    """
    user = g.user
    try:
        with db_transaction() as (db, cur):
            row = tx_query(cur,
                "SELECT * FROM finance WHERE id=%s FOR UPDATE",
                (fid,), one=True
            )
            if not row:
                raise ValueError("Finance record not found")
            if str(row.get("category", "")).startswith("VOIDED-"):
                return jsonify({"error": "Record is already voided"}), 409

            cur.execute(
                """UPDATE finance
                   SET category = 'VOIDED-' || category,
                       notes    = COALESCE(notes,'') || ' [VOIDED by user]'
                   WHERE id=%s""",
                (fid,)
            )
            write_audit(cur,
                action="SOFT_DELETE",
                record_type="finance",
                record_id=fid,
                record_label=row.get("description", ""),
                before={"type": row["type"], "amount": float(row["amount"] or 0), "category": row["category"]},
                user_id=user["id"]
            )
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": "Could not void finance record"}), 500

    return jsonify({"voided": fid})


# ─── COMPLIANCE ────────────────────────────────────────────────────────────────

@app.route("/api/compliance", methods=["GET"])
@require_auth
def get_compliance():
    rows = query("SELECT * FROM compliance ORDER BY expiry_date")
    return jsonify(rows_to_list(rows))


@app.route("/api/compliance/<int:cid>", methods=["GET"])
@require_auth
def get_compliance_item(cid):
    row = query("SELECT * FROM compliance WHERE id=%s", (cid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row))


@app.route("/api/compliance", methods=["POST"])
@require_auth
@require_write_access
def create_compliance_item():
    d = request.get_json()
    new_id = mutate(
        "INSERT INTO compliance (title,category,status,issued_date,expiry_date,issuing_body,notes) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["title"], d["category"], d.get("status","Compliant"), d.get("issued_date"),
         d.get("expiry_date"), d.get("issuing_body"), d.get("notes"))
    )
    row = query("SELECT * FROM compliance WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/compliance/<int:cid>", methods=["PUT"])
@require_auth
@require_write_access
def update_compliance_item(cid):
    d = request.get_json()
    mutate(
        "UPDATE compliance SET title=%s,category=%s,status=%s,issued_date=%s,expiry_date=%s,issuing_body=%s,notes=%s WHERE id=%s",
        (d["title"], d["category"], d.get("status","Compliant"), d.get("issued_date"),
         d.get("expiry_date"), d.get("issuing_body"), d.get("notes"), cid)
    )
    row = query("SELECT * FROM compliance WHERE id=%s", (cid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/compliance/<int:cid>", methods=["DELETE"])
@require_auth
@require_write_access
def delete_compliance_item(cid):
    mutate("DELETE FROM compliance WHERE id=%s", (cid,))
    return jsonify({"deleted": cid})


# ─── SETTINGS ──────────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
@require_auth
def get_settings():
    rows = query("SELECT * FROM settings")
    return jsonify({r["key"]: r["value"] for r in rows})


@app.route("/api/settings", methods=["PUT"])
@require_auth
def update_settings():
    d = request.get_json()
    for key, value in d.items():
        mutate("INSERT INTO settings (key,value) VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", (key, str(value)))
    return jsonify({"updated": list(d.keys())})


# ─── DASHBOARD SUMMARY ─────────────────────────────────────────────────────────

@app.route("/api/dashboard", methods=["GET"])
@require_auth
def get_dashboard():
    # Livestock count
    livestock = query("SELECT COALESCE(SUM(count),0) as total FROM livestock", one=True)
    # Workers on site
    workers_total = query("SELECT COUNT(*) as total FROM workers", one=True)
    workers_on_site = query("SELECT COUNT(*) as total FROM workers WHERE status='Present'", one=True)
    # Finance
    income = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='income'", one=True)
    expense = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='expense'", one=True)
    # Crops
    crops = query("SELECT COALESCE(SUM(area_ha),0) as total FROM crops", one=True)
    # Low inventory
    low_stock = query("SELECT COUNT(*) as total FROM inventory WHERE on_hand <= par_level", one=True)
    # Compliance issues
    overdue = query("SELECT COUNT(*) as total FROM compliance WHERE status='Overdue'", one=True)
    due_soon = query("SELECT COUNT(*) as total FROM compliance WHERE status='Due Soon'", one=True)
    # Recent events
    events = query("""
        SELECT e.description, e.event_date, e.status, l.herd_name
        FROM livestock_events e JOIN livestock l ON e.livestock_id=l.id
        ORDER BY e.created_at DESC LIMIT 5
    """)

    total_income = income["total"]
    total_expense = expense["total"]

    return jsonify({
        "revenue_ytd": total_income,
        "expenditure_ytd": total_expense,
        "net_profit": total_income - total_expense,
        "livestock_count": livestock["total"],
        "crop_hectares": crops["total"],
        "workers_total": workers_total["total"],
        "workers_on_site": workers_on_site["total"],
        "low_stock_items": low_stock["total"],
        "compliance_overdue": overdue["total"],
        "compliance_due_soon": due_soon["total"],
        "recent_events": rows_to_list(events),
    })


# ─── FINANCE — MONTHLY BREAKDOWN ──────────────────────────────────────────────

@app.route("/api/finance/monthly", methods=["GET"])
@require_auth
def get_finance_monthly():
    """
    Returns monthly income + expense totals for the last 12 months.
    Used by the dashboard revenue bar chart and the finance trend chart.
    """
    rows = query("""
        SELECT
            to_char(TO_DATE(date, 'YYYY-MM-DD'), 'YYYY-MM') as month,
            SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as income,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expense
        FROM finance
        WHERE TO_DATE(date, 'YYYY-MM-DD') >= CURRENT_DATE - INTERVAL '12 months'
        GROUP BY to_char(TO_DATE(date, 'YYYY-MM-DD'), 'YYYY-MM')
        ORDER BY month ASC
    """)
    return jsonify(rows_to_list(rows))


# ─── WEATHER PROXY ─────────────────────────────────────────────────────────────

@app.route("/api/weather", methods=["GET"])
@require_auth
def get_weather():
    """
    Proxies Open-Meteo (free, no API key) for the estate's location.
    Location defaults to Harare, Zimbabwe — overridden by the 'location_lat'
    and 'location_lon' settings keys if set.
    Returns 7 days of daily forecasts.
    """
    import urllib.request

    lat_row = query("SELECT value FROM settings WHERE key='location_lat'", one=True)
    lon_row = query("SELECT value FROM settings WHERE key='location_lon'", one=True)
    lat = lat_row["value"] if lat_row else "-17.8292"   # Harare default
    lon = lon_row["value"] if lon_row else "31.0522"

    url = (
        f"https://api.open-meteo.com/v1/forecast"
        f"?latitude={lat}&longitude={lon}"
        f"&daily=temperature_2m_max,temperature_2m_min,weathercode"
        f"&timezone=Africa%2FHarare&forecast_days=7"
    )

    WMO_ICON = {
        0:'☀',1:'🌤',2:'⛅',3:'☁',
        45:'🌫',48:'🌫',
        51:'🌦',53:'🌦',55:'🌧',
        61:'🌧',63:'🌧',65:'🌧',
        71:'🌨',73:'🌨',75:'🌨',
        80:'🌦',81:'🌧',82:'⛈',
        95:'⛈',96:'⛈',99:'⛈',
    }
    DAYS = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat']

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ThornfieldEstate/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())

        daily = data.get("daily", {})
        dates      = daily.get("time", [])
        temps_max  = daily.get("temperature_2m_max", [])
        temps_min  = daily.get("temperature_2m_min", [])
        codes      = daily.get("weathercode", [])

        result = []
        for i, date_str in enumerate(dates):
            try:
                d = datetime.strptime(date_str, "%Y-%m-%d")
                day_name = DAYS[d.weekday()] if i > 0 else "Today"
            except Exception:
                day_name = date_str
            code = int(codes[i]) if i < len(codes) else 0
            result.append({
                "day":      day_name,
                "icon":     WMO_ICON.get(code, "🌡"),
                "temp_max": round(temps_max[i]) if i < len(temps_max) else "—",
                "temp_min": round(temps_min[i]) if i < len(temps_min) else "—",
                "code":     code,
            })
        return jsonify(result)

    except Exception as e:
        # Graceful degradation — return empty list, frontend handles it
        return jsonify({"error": str(e)}), 503


# ─── REPORTS ───────────────────────────────────────────────────────────────────

@app.route("/api/reports", methods=["GET"])
@require_auth
def get_reports():
    return jsonify(rows_to_list(query("SELECT * FROM reports ORDER BY created_at DESC")))

@app.route("/api/reports", methods=["POST"])
@require_auth
def create_report():
    d = request.get_json() or {}
    user = get_current_user()
    rid = mutate(
        "INSERT INTO reports(title,type,status,created_by,content) VALUES(%s,%s,%s,%s,%s)",
        (d.get("title","Untitled"), d.get("type"), d.get("status","Draft"),
         user["name"] if user else "Unknown", d.get("content",""))
    )
    return jsonify(row_to_dict(query("SELECT * FROM reports WHERE id=%s", (rid,), one=True))), 201

@app.route("/api/reports/<int:rid>", methods=["GET"])
@require_auth
def get_report(rid):
    row = query("SELECT * FROM reports WHERE id=%s", (rid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(row_to_dict(row))

@app.route("/api/reports/<int:rid>", methods=["DELETE"])
@require_auth
def delete_report(rid):
    mutate("DELETE FROM reports WHERE id=%s", (rid,))
    return jsonify({"ok": True})


# ─── FINANCE TRANSACTIONS (alias) ──────────────────────────────────────────────

@app.route("/api/finance/transactions", methods=["GET", "POST"])
@require_auth
def finance_transactions():
    if request.method == "GET":
        t = request.args.get("type")
        if t:
            return jsonify(rows_to_list(query("SELECT * FROM finance WHERE type=%s ORDER BY date DESC", (t,))))
        return jsonify(rows_to_list(query("SELECT * FROM finance ORDER BY date DESC")))
    d = request.get_json() or {}
    rid = mutate(
        "INSERT INTO finance(type,category,description,amount,date,reference,notes) VALUES(%s,%s,%s,%s,%s,%s,%s)",
        (d.get("type","income"), d.get("category"), d.get("description"),
         d.get("amount", 0), d.get("date"), d.get("reference"), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM finance WHERE id=%s", (rid,), one=True))), 201


# ─── AUDIT LOG ─────────────────────────────────────────────────────────────────

@app.route("/api/audit-log", methods=["POST"])
@require_auth
def write_audit_log():
    d = request.get_json() or {}
    mutate(
        """INSERT INTO audit_log (action, record_type, record_id, record_label, performed_by)
           VALUES (%s,%s,%s,%s,%s)""",
        (
            d.get("action", ""),
            d.get("record_type", ""),
            d.get("record_id"),
            d.get("record_label", ""),
            d.get("performed_by"),
        )
    )
    return jsonify({"ok": True}), 201


@app.route("/api/audit-log", methods=["GET"])
@require_role("owner")
def get_audit_log():
    """
    Return audit log entries. Supports filtering by record_type, record_id,
    and action. Returns before_state and after_state for full change history.
    """
    record_type = request.args.get("record_type")
    record_id   = request.args.get("record_id")
    action      = request.args.get("action")
    limit       = min(int(request.args.get("limit", 200)), 1000)

    conditions = []
    params = []
    if record_type:
        conditions.append("a.record_type = %s"); params.append(record_type)
    if record_id:
        conditions.append("a.record_id = %s"); params.append(int(record_id))
    if action:
        conditions.append("a.action = %s"); params.append(action)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    rows = query(f"""
        SELECT a.id, a.action, a.record_type, a.record_id, a.record_label,
               a.before_state, a.after_state, a.created_at, u.name as user_name
        FROM audit_log a
        LEFT JOIN users u ON a.performed_by = u.id
        {where}
        ORDER BY a.created_at DESC
        LIMIT {limit}
    """, tuple(params))
    return jsonify(rows_to_list(rows))


# ─── AI / ANTHROPIC PROXY ─────────────────────────────────────────────────────
# The Anthropic API key NEVER leaves the server. The frontend calls this endpoint,
# which adds the key server-side. This prevents key exposure via browser DevTools.

@app.route("/api/ai/digest", methods=["POST"])
@require_auth
def ai_digest():
    """
    Generate an estate intelligence digest using Claude.
    The ANTHROPIC_API_KEY env var is required. If not set, returns a graceful error.
    Only owner/manager roles can generate AI digests (financial + operational data).
    """
    if g.user["role"] not in ("owner", "manager"):
        return jsonify({"error": "Forbidden — owner or manager role required"}), 403

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return jsonify({"error": "AI digest is not configured on this server (ANTHROPIC_API_KEY not set)"}), 501

    d = request.get_json() or {}

    # Sanitise / clamp all numeric inputs — never trust frontend values for prompts
    def safe_num(v, default=0):
        try: return float(v)
        except: return default
    def safe_int(v, default=0):
        try: return int(v)
        except: return default
    def safe_str_list(lst, max_items=10, max_len=80):
        if not isinstance(lst, list): return []
        return [
            {k: str(v)[:max_len] for k, v in item.items() if isinstance(item, dict)}
            for item in lst[:max_items]
        ]

    farm_data = {
        "revenue_ytd":        safe_num(d.get("revenue_ytd")),
        "net_profit":         safe_num(d.get("net_profit")),
        "livestock_count":    safe_int(d.get("livestock_count")),
        "herd_count":         safe_int(d.get("herd_count")),
        "crop_hectares":      safe_num(d.get("crop_hectares")),
        "active_fields":      safe_int(d.get("active_fields")),
        "workers_on_site":    safe_int(d.get("workers_on_site")),
        "workers_total":      safe_int(d.get("workers_total")),
        "compliance_overdue": safe_int(d.get("compliance_overdue")),
        "compliance_due_soon":safe_int(d.get("compliance_due_soon")),
        "low_stock_items":    safe_int(d.get("low_stock_items")),
        "active_crops":       safe_str_list(d.get("active_crops", [])),
        "herds":              safe_str_list(d.get("herds", [])),
    }

    prompt = f"""You are the estate intelligence system for Thornfield Estate, a commercial farm in Harare, Zimbabwe.

Generate a concise weekly estate digest. Be direct, data-driven. No fluff. Use real numbers from the data.

Farm Data:
- Revenue YTD: ${farm_data['revenue_ytd']:,.0f}, Net Profit: ${farm_data['net_profit']:,.0f}
- Livestock: {farm_data['livestock_count']} head across {farm_data['herd_count']} herds
- Crops: {farm_data['crop_hectares']} ha in production, {farm_data['active_fields']} active fields
- Workers: {farm_data['workers_on_site']}/{farm_data['workers_total']} on site
- Compliance: {farm_data['compliance_overdue']} overdue, {farm_data['compliance_due_soon']} due soon
- Low stock items: {farm_data['low_stock_items']}
- Active crops: {', '.join(f"{c.get('block','')} ({c.get('crop','')}, {c.get('status','')})" for c in farm_data['active_crops'])}
- Herds: {', '.join(f"{h.get('name','')}: {h.get('count','')} head, {h.get('health','')}" for h in farm_data['herds'])}

Respond ONLY with a JSON object (no markdown, no backticks):
{{
  "headline": "2-line executive summary of the week",
  "revenue_status": "one sentence on revenue vs target",
  "livestock_summary": "one sentence on herd health",
  "crop_status": "one sentence on crop pipeline",
  "compliance_note": "one sentence on compliance standing",
  "top_3_actions": ["action 1", "action 2", "action 3"]
}}"""

    import urllib.request as urlreq
    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": prompt}]
    }).encode("utf-8")

    req = urlreq.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST"
    )
    try:
        with urlreq.urlopen(req, timeout=20) as resp:
            result = json.loads(resp.read().decode())
        text = "".join(b.get("text", "") for b in result.get("content", []))
        digest = json.loads(text.strip())
        log_security("AI_DIGEST_GENERATED", "", user_id=g.user["id"])
        return jsonify({"content": [{"text": text}]})
    except Exception as e:
        log_security("AI_DIGEST_ERROR", str(e)[:120], user_id=g.user["id"])
        return jsonify({"error": "Could not generate digest. Please try again."}), 502


# ─── STATIC / FRONTEND ────────────────────────────────────────────────────────

@app.route("/")
@app.route("/<path:path>")
def index(path=None):
    # Serve API routes normally; catch all others for the SPA
    if path and path.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(PUBLIC_DIR, "index.html")


# ═══════════════════════════════════════════════════════════════════════════════
# ERP EXTENSION — SCHEMA, ROUTES, AND BUSINESS LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

def init_erp_db():
    """Create all ERP extension tables."""
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()
    ddls = [
        # FARMS
        """CREATE TABLE IF NOT EXISTS farms (
            id          SERIAL PRIMARY KEY,
            name        TEXT    NOT NULL,
            location    TEXT,
            total_ha    NUMERIC DEFAULT 0,
            currency    TEXT    DEFAULT 'USD',
            notes       TEXT,
            active      BOOLEAN DEFAULT TRUE,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        # OPERATIONAL UNITS
        """CREATE TABLE IF NOT EXISTS operational_units (
            id          SERIAL PRIMARY KEY,
            farm_id     INTEGER REFERENCES farms(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            unit_type   TEXT    NOT NULL DEFAULT 'field',
            area_ha     NUMERIC DEFAULT 0,
            notes       TEXT,
            active      BOOLEAN DEFAULT TRUE,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        # SEASONS
        """CREATE TABLE IF NOT EXISTS seasons (
            id          SERIAL PRIMARY KEY,
            farm_id     INTEGER REFERENCES farms(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            start_date  DATE    NOT NULL,
            end_date    DATE,
            status      TEXT    DEFAULT 'Active',
            notes       TEXT,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        # BUDGETS
        """CREATE TABLE IF NOT EXISTS budgets (
            id              SERIAL PRIMARY KEY,
            season_id       INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
            unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
            category        TEXT    NOT NULL,
            planned_amount  NUMERIC NOT NULL DEFAULT 0,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # REVENUE PROJECTIONS
        """CREATE TABLE IF NOT EXISTS revenue_projections (
            id              SERIAL PRIMARY KEY,
            season_id       INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
            unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
            description     TEXT    NOT NULL,
            projected_amount NUMERIC NOT NULL DEFAULT 0,
            actual_amount   NUMERIC DEFAULT 0,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW(),
            updated_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # CONTINGENCY SETTINGS
        """CREATE TABLE IF NOT EXISTS contingency_settings (
            id              SERIAL PRIMARY KEY,
            season_id       INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
            contingency_type TEXT   DEFAULT 'percentage',
            contingency_pct  NUMERIC DEFAULT 0,
            contingency_fixed NUMERIC DEFAULT 0,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # COST CENTERS
        """CREATE TABLE IF NOT EXISTS cost_centers (
            id          SERIAL PRIMARY KEY,
            farm_id     INTEGER REFERENCES farms(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            code        TEXT,
            description TEXT,
            active      BOOLEAN DEFAULT TRUE,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        )""",
        # INVENTORY LOTS
        """CREATE TABLE IF NOT EXISTS inventory_lots (
            id              SERIAL PRIMARY KEY,
            inventory_id    INTEGER NOT NULL REFERENCES inventory(id) ON DELETE CASCADE,
            lot_number      TEXT,
            quantity_received NUMERIC NOT NULL DEFAULT 0,
            quantity_remaining NUMERIC NOT NULL DEFAULT 0,
            unit_cost       NUMERIC NOT NULL DEFAULT 0,
            received_date   DATE    DEFAULT CURRENT_DATE,
            expiry_date     DATE,
            supplier        TEXT,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # OPERATIONAL ACTIVITIES (core ERP event bus)
        """CREATE TABLE IF NOT EXISTS operational_activities (
            id              SERIAL PRIMARY KEY,
            activity_type   TEXT    NOT NULL,
            unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
            season_id       INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
            cost_center_id  INTEGER REFERENCES cost_centers(id) ON DELETE SET NULL,
            description     TEXT    NOT NULL,
            activity_date   DATE    DEFAULT CURRENT_DATE,
            status          TEXT    DEFAULT 'Completed',
            total_cost      NUMERIC DEFAULT 0,
            notes           TEXT,
            performed_by    INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # INVENTORY CONSUMPTION
        """CREATE TABLE IF NOT EXISTS inventory_consumption (
            id              SERIAL PRIMARY KEY,
            activity_id     INTEGER NOT NULL REFERENCES operational_activities(id) ON DELETE CASCADE,
            inventory_id    INTEGER NOT NULL REFERENCES inventory(id) ON DELETE RESTRICT,
            lot_id          INTEGER REFERENCES inventory_lots(id) ON DELETE SET NULL,
            quantity_used   NUMERIC NOT NULL DEFAULT 0,
            unit_cost       NUMERIC NOT NULL DEFAULT 0,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # LABOR ALLOCATIONS
        """CREATE TABLE IF NOT EXISTS labor_allocations (
            id              SERIAL PRIMARY KEY,
            activity_id     INTEGER REFERENCES operational_activities(id) ON DELETE CASCADE,
            worker_id       INTEGER REFERENCES workers(id) ON DELETE SET NULL,
            unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
            hours           NUMERIC DEFAULT 0,
            hourly_rate     NUMERIC DEFAULT 0,
            allocation_date DATE    DEFAULT CURRENT_DATE,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # PRODUCTION BATCHES
        """CREATE TABLE IF NOT EXISTS production_batches (
            id              SERIAL PRIMARY KEY,
            unit_id         INTEGER REFERENCES operational_units(id) ON DELETE SET NULL,
            season_id       INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
            product_type    TEXT    NOT NULL,
            quantity        NUMERIC NOT NULL DEFAULT 0,
            unit_of_measure TEXT    NOT NULL DEFAULT 'kg',
            actual_revenue  NUMERIC DEFAULT 0,
            batch_date      DATE    DEFAULT CURRENT_DATE,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # ASSET DEPRECIATION
        """CREATE TABLE IF NOT EXISTS asset_depreciation (
            id              SERIAL PRIMARY KEY,
            asset_id        INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            method          TEXT    DEFAULT 'straight_line',
            useful_life_years NUMERIC DEFAULT 5,
            residual_value  NUMERIC DEFAULT 0,
            depreciation_start DATE DEFAULT CURRENT_DATE,
            annual_depreciation NUMERIC DEFAULT 0,
            accumulated_depreciation NUMERIC DEFAULT 0,
            notes           TEXT,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # KPI SNAPSHOTS
        """CREATE TABLE IF NOT EXISTS kpi_snapshots (
            id              SERIAL PRIMARY KEY,
            snapshot_date   DATE    DEFAULT CURRENT_DATE,
            total_revenue   NUMERIC DEFAULT 0,
            total_expenses  NUMERIC DEFAULT 0,
            net_profit      NUMERIC DEFAULT 0,
            inventory_value NUMERIC DEFAULT 0,
            labor_cost      NUMERIC DEFAULT 0,
            livestock_count INTEGER DEFAULT 0,
            crop_ha         NUMERIC DEFAULT 0,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
        # NOTIFICATIONS
        """CREATE TABLE IF NOT EXISTS notifications (
            id              SERIAL PRIMARY KEY,
            user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title           TEXT    NOT NULL,
            message         TEXT    NOT NULL,
            notification_type TEXT  DEFAULT 'info',
            related_type    TEXT,
            related_id      INTEGER,
            read_at         TIMESTAMPTZ,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )""",
    ]
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_oa_unit ON operational_activities(unit_id)",
        "CREATE INDEX IF NOT EXISTS idx_oa_date ON operational_activities(activity_date)",
        "CREATE INDEX IF NOT EXISTS idx_oa_season ON operational_activities(season_id)",
        "CREATE INDEX IF NOT EXISTS idx_ic_activity ON inventory_consumption(activity_id)",
        "CREATE INDEX IF NOT EXISTS idx_ic_inventory ON inventory_consumption(inventory_id)",
        "CREATE INDEX IF NOT EXISTS idx_la_worker ON labor_allocations(worker_id)",
        "CREATE INDEX IF NOT EXISTS idx_pb_unit ON production_batches(unit_id)",
        "CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_finance_date ON finance(date)",
        "CREATE INDEX IF NOT EXISTS idx_finance_type ON finance(type)",
        "CREATE INDEX IF NOT EXISTS idx_il_inventory ON inventory_lots(inventory_id)",
    ]
    for ddl in ddls:
        cur.execute(ddl)
    for idx in indexes:
        cur.execute(idx)
    db.commit()
    db.close()


# ── HELPER: Create auto-notification ─────────────────────────────────────────
def create_notification(user_id, title, message, notif_type="info", related_type=None, related_id=None):
    try:
        mutate(
            "INSERT INTO notifications (user_id,title,message,notification_type,related_type,related_id) VALUES (%s,%s,%s,%s,%s,%s)",
            (user_id, title, message, notif_type, related_type, related_id)
        )
    except Exception:
        pass


# ── HELPER: Recalculate activity total cost ───────────────────────────────────
def recalculate_activity_cost(activity_id):
    """
    Standalone recalculation — opens its own commit.
    Use tx_recalculate_activity_cost() when already inside a db_transaction().
    """
    inv_cost = query(
        "SELECT COALESCE(SUM(quantity_used * unit_cost),0) as total FROM inventory_consumption WHERE activity_id=%s",
        (activity_id,), one=True
    )
    lab_cost = query(
        "SELECT COALESCE(SUM(hours * hourly_rate),0) as total FROM labor_allocations WHERE activity_id=%s",
        (activity_id,), one=True
    )
    total = float(inv_cost["total"]) + float(lab_cost["total"])
    mutate("UPDATE operational_activities SET total_cost=%s WHERE id=%s", (total, activity_id))
    return total


def tx_recalculate_activity_cost(cur, activity_id):
    """
    Recalculate activity cost using an existing transaction cursor.
    Returns the new total without committing.
    """
    cur.execute(
        "SELECT COALESCE(SUM(quantity_used * unit_cost),0) AS total FROM inventory_consumption WHERE activity_id=%s",
        (activity_id,)
    )
    inv_cost = float(cur.fetchone()["total"])
    cur.execute(
        "SELECT COALESCE(SUM(hours * hourly_rate),0) AS total FROM labor_allocations WHERE activity_id=%s",
        (activity_id,)
    )
    lab_cost = float(cur.fetchone()["total"])
    total = inv_cost + lab_cost
    cur.execute("UPDATE operational_activities SET total_cost=%s WHERE id=%s", (total, activity_id))
    return total


# ═══════════════════════════════════════════════════════════════════════════════
# ERP API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

# ── FARMS ────────────────────────────────────────────────────────────────────

@app.route("/api/erp/farms", methods=["GET"])
@require_auth
def get_farms():
    rows = query("SELECT * FROM farms ORDER BY name")
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/farms", methods=["POST"])
@require_role("owner", "manager")
def create_farm():
    d = request.get_json() or {}
    fid = mutate(
        "INSERT INTO farms (name,location,total_ha,currency,notes) VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (d["name"], d.get("location"), d.get("total_ha", 0), d.get("currency", "USD"), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM farms WHERE id=%s", (fid,), one=True))), 201


@app.route("/api/erp/farms/<int:fid>", methods=["PUT"])
@require_role("owner", "manager")
def update_farm(fid):
    d = request.get_json() or {}
    mutate(
        "UPDATE farms SET name=%s,location=%s,total_ha=%s,currency=%s,notes=%s,active=%s WHERE id=%s",
        (d["name"], d.get("location"), d.get("total_ha", 0), d.get("currency", "USD"),
         d.get("notes"), d.get("active", True), fid)
    )
    return jsonify(row_to_dict(query("SELECT * FROM farms WHERE id=%s", (fid,), one=True)))


# ── OPERATIONAL UNITS ────────────────────────────────────────────────────────

@app.route("/api/erp/units", methods=["GET"])
@require_auth
def get_units():
    farm_id = request.args.get("farm_id")
    if farm_id:
        rows = query("SELECT u.*, f.name as farm_name FROM operational_units u JOIN farms f ON u.farm_id=f.id WHERE u.farm_id=%s AND u.active=TRUE ORDER BY u.unit_type, u.name", (farm_id,))
    else:
        rows = query("SELECT u.*, f.name as farm_name FROM operational_units u JOIN farms f ON u.farm_id=f.id WHERE u.active=TRUE ORDER BY u.unit_type, u.name")
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/units", methods=["POST"])
@require_role("owner", "manager")
def create_unit():
    d = request.get_json() or {}
    uid = mutate(
        "INSERT INTO operational_units (farm_id,name,unit_type,area_ha,notes) VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (d["farm_id"], d["name"], d.get("unit_type", "field"), d.get("area_ha", 0), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM operational_units WHERE id=%s", (uid,), one=True))), 201


@app.route("/api/erp/units/<int:uid>", methods=["PUT"])
@require_role("owner", "manager")
def update_unit(uid):
    d = request.get_json() or {}
    mutate(
        "UPDATE operational_units SET name=%s,unit_type=%s,area_ha=%s,notes=%s,active=%s WHERE id=%s",
        (d["name"], d.get("unit_type", "field"), d.get("area_ha", 0), d.get("notes"), d.get("active", True), uid)
    )
    return jsonify(row_to_dict(query("SELECT * FROM operational_units WHERE id=%s", (uid,), one=True)))


# ── SEASONS ──────────────────────────────────────────────────────────────────

@app.route("/api/erp/seasons", methods=["GET"])
@require_auth
def get_seasons():
    rows = query("SELECT s.*, f.name as farm_name FROM seasons s JOIN farms f ON s.farm_id=f.id ORDER BY s.start_date DESC")
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/seasons", methods=["POST"])
@require_role("owner", "manager")
def create_season():
    d = request.get_json() or {}
    sid = mutate(
        "INSERT INTO seasons (farm_id,name,start_date,end_date,status,notes) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["farm_id"], d["name"], d["start_date"], d.get("end_date"), d.get("status", "Active"), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM seasons WHERE id=%s", (sid,), one=True))), 201


@app.route("/api/erp/seasons/<int:sid>", methods=["PUT"])
@require_role("owner", "manager")
def update_season(sid):
    d = request.get_json() or {}
    mutate(
        "UPDATE seasons SET name=%s,start_date=%s,end_date=%s,status=%s,notes=%s WHERE id=%s",
        (d["name"], d["start_date"], d.get("end_date"), d.get("status", "Active"), d.get("notes"), sid)
    )
    return jsonify(row_to_dict(query("SELECT * FROM seasons WHERE id=%s", (sid,), one=True)))


# ── BUDGETS ──────────────────────────────────────────────────────────────────

@app.route("/api/erp/budgets", methods=["GET"])
@require_auth
def get_budgets():
    season_id = request.args.get("season_id")
    if season_id:
        rows = query(
            "SELECT b.*, s.name as season_name FROM budgets b JOIN seasons s ON b.season_id=s.id WHERE b.season_id=%s ORDER BY b.category",
            (season_id,)
        )
    else:
        rows = query("SELECT b.*, s.name as season_name FROM budgets b JOIN seasons s ON b.season_id=s.id ORDER BY s.start_date DESC, b.category")
    # Compute actual vs planned
    result = []
    for b in rows_to_list(rows):
        actual = query(
            "SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='expense' AND category ILIKE %s",
            (f"%{b['category']}%",), one=True
        )
        b["actual_amount"] = float(actual["total"])
        b["variance"] = float(b["planned_amount"]) - float(actual["total"])
        result.append(b)
    return jsonify(result)


@app.route("/api/erp/budgets", methods=["POST"])
@require_role("owner", "manager", "finance")
def create_budget():
    d = request.get_json() or {}
    bid = mutate(
        "INSERT INTO budgets (season_id,unit_id,category,planned_amount,notes) VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (d["season_id"], d.get("unit_id"), d["category"], d["planned_amount"], d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM budgets WHERE id=%s", (bid,), one=True))), 201


@app.route("/api/erp/budgets/<int:bid>", methods=["PUT"])
@require_role("owner", "manager", "finance")
def update_budget(bid):
    d = request.get_json() or {}
    mutate(
        "UPDATE budgets SET category=%s,planned_amount=%s,notes=%s WHERE id=%s",
        (d["category"], d["planned_amount"], d.get("notes"), bid)
    )
    return jsonify(row_to_dict(query("SELECT * FROM budgets WHERE id=%s", (bid,), one=True)))


@app.route("/api/erp/budgets/<int:bid>", methods=["DELETE"])
@require_role("owner", "manager", "finance")
def delete_budget(bid):
    mutate("DELETE FROM budgets WHERE id=%s", (bid,))
    return jsonify({"deleted": bid})


# ── REVENUE PROJECTIONS ──────────────────────────────────────────────────────

@app.route("/api/erp/revenue-projections", methods=["GET"])
@require_auth
def get_revenue_projections():
    season_id = request.args.get("season_id")
    if season_id:
        rows = query(
            "SELECT rp.*, s.name as season_name FROM revenue_projections rp JOIN seasons s ON rp.season_id=s.id WHERE rp.season_id=%s ORDER BY rp.created_at",
            (season_id,)
        )
    else:
        rows = query("SELECT rp.*, s.name as season_name FROM revenue_projections rp JOIN seasons s ON rp.season_id=s.id ORDER BY s.start_date DESC")
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/revenue-projections", methods=["POST"])
@require_role("owner", "manager", "finance")
def create_revenue_projection():
    d = request.get_json() or {}
    rid = mutate(
        "INSERT INTO revenue_projections (season_id,unit_id,description,projected_amount,actual_amount,notes) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["season_id"], d.get("unit_id"), d["description"], d["projected_amount"], d.get("actual_amount", 0), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM revenue_projections WHERE id=%s", (rid,), one=True))), 201


@app.route("/api/erp/revenue-projections/<int:rid>", methods=["PUT"])
@require_role("owner", "manager", "finance")
def update_revenue_projection(rid):
    d = request.get_json() or {}
    mutate(
        "UPDATE revenue_projections SET description=%s,projected_amount=%s,actual_amount=%s,notes=%s,updated_at=NOW() WHERE id=%s",
        (d["description"], d["projected_amount"], d.get("actual_amount", 0), d.get("notes"), rid)
    )
    return jsonify(row_to_dict(query("SELECT * FROM revenue_projections WHERE id=%s", (rid,), one=True)))


@app.route("/api/erp/revenue-projections/<int:rid>", methods=["DELETE"])
@require_role("owner", "manager", "finance")
def delete_revenue_projection(rid):
    mutate("DELETE FROM revenue_projections WHERE id=%s", (rid,))
    return jsonify({"deleted": rid})


# ── CONTINGENCY ──────────────────────────────────────────────────────────────

@app.route("/api/erp/contingency", methods=["GET"])
@require_auth
def get_contingency():
    season_id = request.args.get("season_id")
    if season_id:
        row = query("SELECT * FROM contingency_settings WHERE season_id=%s ORDER BY id DESC LIMIT 1", (season_id,), one=True)
    else:
        row = query("SELECT * FROM contingency_settings ORDER BY id DESC LIMIT 1", one=True)
    return jsonify(row_to_dict(row) if row else {})


@app.route("/api/erp/contingency", methods=["POST"])
@require_role("owner", "manager", "finance")
def upsert_contingency():
    d = request.get_json() or {}
    season_id = d.get("season_id")
    # Delete existing for this season and replace
    if season_id:
        mutate("DELETE FROM contingency_settings WHERE season_id=%s", (season_id,))
    cid = mutate(
        "INSERT INTO contingency_settings (season_id,contingency_type,contingency_pct,contingency_fixed,notes) VALUES (%s,%s,%s,%s,%s) RETURNING id",
        (season_id, d.get("contingency_type", "percentage"), d.get("contingency_pct", 0), d.get("contingency_fixed", 0), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM contingency_settings WHERE id=%s", (cid,), one=True))), 201


# ── PROFITABILITY ENGINE ──────────────────────────────────────────────────────

@app.route("/api/erp/profitability", methods=["GET"])
@require_auth
def get_profitability():
    """
    Core profitability calculation engine.
    Returns original profit, contingency value, adjusted expenses, adjusted profit.
    """
    season_id = request.args.get("season_id")

    # Total actual revenue (finance table income)
    actual_rev = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='income'", one=True)
    # Total actual expenses (finance table + operational activities)
    actual_exp = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='expense'", one=True)
    op_costs = query("SELECT COALESCE(SUM(total_cost),0) as total FROM operational_activities WHERE status='Completed'", one=True)
    labor_costs = query("SELECT COALESCE(SUM(hours * hourly_rate),0) as total FROM labor_allocations", one=True)

    total_revenue = float(actual_rev["total"])
    base_expenses = float(actual_exp["total"]) + float(op_costs["total"]) + float(labor_costs["total"])
    original_profit = total_revenue - base_expenses

    # Projected revenue
    proj_filter = "WHERE season_id=%s" if season_id else ""
    proj_args = (season_id,) if season_id else ()
    proj_rev = query(f"SELECT COALESCE(SUM(projected_amount),0) as total FROM revenue_projections {proj_filter}", proj_args, one=True)
    projected_revenue = float(proj_rev["total"])

    # Budget total
    budget_total = query(f"SELECT COALESCE(SUM(planned_amount),0) as total FROM budgets {proj_filter}", proj_args, one=True)

    # Contingency
    contingency_row = query(
        "SELECT * FROM contingency_settings" + (" WHERE season_id=%s" if season_id else "") + " ORDER BY id DESC LIMIT 1",
        (season_id,) if season_id else (), one=True
    )
    contingency_value = 0.0
    if contingency_row:
        if contingency_row["contingency_type"] == "percentage":
            contingency_value = base_expenses * float(contingency_row["contingency_pct"]) / 100
        else:
            contingency_value = float(contingency_row["contingency_fixed"])

    adjusted_expenses = base_expenses + contingency_value
    adjusted_profit = total_revenue - adjusted_expenses
    margin_pct = round(original_profit / total_revenue * 100, 1) if total_revenue else 0
    adjusted_margin_pct = round(adjusted_profit / total_revenue * 100, 1) if total_revenue else 0

    # Inventory valuation
    inv_value = query(
        "SELECT COALESCE(SUM(on_hand * unit_cost),0) as total FROM inventory", one=True
    )

    return jsonify({
        "total_revenue": total_revenue,
        "projected_revenue": projected_revenue,
        "base_expenses": base_expenses,
        "original_profit": original_profit,
        "margin_pct": margin_pct,
        "contingency_value": contingency_value,
        "adjusted_expenses": adjusted_expenses,
        "adjusted_profit": adjusted_profit,
        "adjusted_margin_pct": adjusted_margin_pct,
        "budget_total": float(budget_total["total"]),
        "inventory_value": float(inv_value["total"]),
        "revenue_vs_projected_pct": round(total_revenue / projected_revenue * 100, 1) if projected_revenue else 0,
    })


# ── COST CENTERS ─────────────────────────────────────────────────────────────

@app.route("/api/erp/cost-centers", methods=["GET"])
@require_auth
def get_cost_centers():
    rows = query("SELECT cc.*, f.name as farm_name FROM cost_centers cc LEFT JOIN farms f ON cc.farm_id=f.id WHERE cc.active=TRUE ORDER BY cc.name")
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/cost-centers", methods=["POST"])
@require_role("owner", "manager")
def create_cost_center():
    d = request.get_json() or {}
    cid = mutate(
        "INSERT INTO cost_centers (farm_id,name,code,description) VALUES (%s,%s,%s,%s) RETURNING id",
        (d.get("farm_id"), d["name"], d.get("code"), d.get("description"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM cost_centers WHERE id=%s", (cid,), one=True))), 201


# ── OPERATIONAL ACTIVITIES ───────────────────────────────────────────────────

@app.route("/api/erp/activities", methods=["GET"])
@require_auth
def get_activities():
    unit_id = request.args.get("unit_id")
    season_id = request.args.get("season_id")
    activity_type = request.args.get("type")
    limit = int(request.args.get("limit", 50))

    conditions = []
    args = []
    if unit_id:
        conditions.append("a.unit_id=%s")
        args.append(unit_id)
    if season_id:
        conditions.append("a.season_id=%s")
        args.append(season_id)
    if activity_type:
        conditions.append("a.activity_type=%s")
        args.append(activity_type)

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    rows = query(
        f"""SELECT a.*, u.name as unit_name, u.unit_type,
                   cc.name as cost_center_name,
                   us.name as performed_by_name
            FROM operational_activities a
            LEFT JOIN operational_units u ON a.unit_id=u.id
            LEFT JOIN cost_centers cc ON a.cost_center_id=cc.id
            LEFT JOIN users us ON a.performed_by=us.id
            {where}
            ORDER BY a.activity_date DESC, a.created_at DESC
            LIMIT %s""",
        tuple(args) + (limit,)
    )
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/activities", methods=["POST"])
@require_auth
def create_activity():
    """
    Core ERP operation: creates an activity with optional inventory consumption.

    TRANSACTION SAFETY (all-or-nothing):
    - Activity row created
    - Inventory lots decremented with row-level locks (SELECT FOR UPDATE)
    - Consumption records inserted
    - Main inventory on_hand decremented (guarded: cannot go below zero)
    - Finance expense entry created
    - Audit entry written
    All steps share one transaction — any failure rolls everything back.

    IDEMPOTENCY: pass an Idempotency-Key header to make retries safe.
    CONCURRENCY: inventory rows are locked with SELECT FOR UPDATE before read.
    """
    # ── Idempotency check ─────────────────────────────────────────────────────
    idem_key = request.headers.get("Idempotency-Key", "")
    if idem_key and check_idempotency(idem_key):
        return jsonify({"error": "Duplicate request — this operation has already been processed"}), 409

    d = request.get_json() or {}
    if not d.get("activity_type") or not d.get("description"):
        return jsonify({"error": "activity_type and description are required"}), 400

    user = g.user
    act_date = d.get("activity_date", datetime.utcnow().date().isoformat())
    low_stock_notifications = []  # collect outside tx to avoid nested commits

    try:
        with db_transaction() as (db, cur):
            # ── 1. Insert the activity ────────────────────────────────────────
            act_id = tx_mutate(cur,
                """INSERT INTO operational_activities
                   (activity_type,unit_id,season_id,cost_center_id,description,
                    activity_date,status,notes,performed_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (
                    d["activity_type"], d.get("unit_id"), d.get("season_id"),
                    d.get("cost_center_id"), d["description"],
                    act_date, d.get("status", "Completed"),
                    d.get("notes"), user["id"]
                )
            )

            total_inv_cost = 0.0

            # ── 2. Process inventory consumption with row-level locking ───────
            for item in d.get("inventory_items", []):
                inv_id = int(item["inventory_id"])
                qty_needed = float(item["quantity"])
                if qty_needed <= 0:
                    continue

                # Lock the inventory row for the duration of this transaction
                inv = tx_query(cur,
                    "SELECT * FROM inventory WHERE id=%s FOR UPDATE",
                    (inv_id,), one=True
                )
                if not inv:
                    raise ValueError(f"Inventory item {inv_id} not found")

                current_on_hand = float(inv["on_hand"])
                if current_on_hand < qty_needed:
                    raise ValueError(
                        f"Insufficient stock for '{inv['name']}': "
                        f"need {qty_needed}, have {current_on_hand}"
                    )

                # Lock lots LIFO (most recent first)
                lots = tx_query(cur,
                    """SELECT * FROM inventory_lots
                       WHERE inventory_id=%s AND quantity_remaining > 0
                       ORDER BY received_date DESC
                       FOR UPDATE""",
                    (inv_id,)
                )

                qty_remaining = qty_needed
                item_cost = 0.0

                if lots:
                    for lot in lots:
                        if qty_remaining <= 0:
                            break
                        lot_available = float(lot["quantity_remaining"])
                        qty_from_lot = min(qty_remaining, lot_available)
                        lot_unit_cost = float(lot["unit_cost"])
                        item_cost += qty_from_lot * lot_unit_cost

                        cur.execute(
                            "UPDATE inventory_lots SET quantity_remaining=quantity_remaining-%s WHERE id=%s",
                            (qty_from_lot, lot["id"])
                        )
                        cur.execute(
                            """INSERT INTO inventory_consumption
                               (activity_id,inventory_id,lot_id,quantity_used,unit_cost)
                               VALUES (%s,%s,%s,%s,%s)""",
                            (act_id, inv_id, lot["id"], qty_from_lot, lot_unit_cost)
                        )
                        qty_remaining -= qty_from_lot
                else:
                    unit_cost = float(inv["unit_cost"])
                    item_cost = qty_needed * unit_cost
                    cur.execute(
                        """INSERT INTO inventory_consumption
                           (activity_id,inventory_id,quantity_used,unit_cost)
                           VALUES (%s,%s,%s,%s)""",
                        (act_id, inv_id, qty_needed, unit_cost)
                    )

                # Deduct from main inventory — constraint prevents going below 0
                cur.execute(
                    """UPDATE inventory
                       SET on_hand = on_hand - %s, last_updated = NOW()
                       WHERE id = %s AND on_hand >= %s""",
                    (qty_needed, inv_id, qty_needed)
                )
                if cur.rowcount == 0:
                    raise ValueError(
                        f"Concurrent modification detected for inventory item {inv_id}; "
                        f"transaction aborted"
                    )

                total_inv_cost += item_cost

                # Capture low-stock state after deduction (read inside tx for accuracy)
                updated_inv = tx_query(cur,
                    "SELECT name, on_hand, par_level, unit FROM inventory WHERE id=%s",
                    (inv_id,), one=True
                )
                if updated_inv and float(updated_inv["on_hand"]) <= float(updated_inv["par_level"]):
                    low_stock_notifications.append((inv_id, dict(updated_inv)))

            # ── 3. Calculate total cost (inventory + labor already in DB) ─────
            cur.execute(
                "SELECT COALESCE(SUM(quantity_used * unit_cost),0) AS total FROM inventory_consumption WHERE activity_id=%s",
                (act_id,)
            )
            inv_cost_row = cur.fetchone()
            cur.execute(
                "SELECT COALESCE(SUM(hours * hourly_rate),0) AS total FROM labor_allocations WHERE activity_id=%s",
                (act_id,)
            )
            lab_cost_row = cur.fetchone()
            total_cost = float(inv_cost_row["total"]) + float(lab_cost_row["total"])
            cur.execute(
                "UPDATE operational_activities SET total_cost=%s WHERE id=%s",
                (total_cost, act_id)
            )

            # ── 4. Auto-create finance expense entry ──────────────────────────
            fin_id = None
            if total_cost > 0:
                fin_id = tx_mutate(cur,
                    """INSERT INTO finance
                           (type,category,description,amount,date,reference)
                       VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (
                        "expense",
                        d.get("finance_category", d["activity_type"].replace("_", " ").title()),
                        d["description"],
                        total_cost,
                        act_date,
                        f"ACT-{act_id}"
                    )
                )

            # ── 5. Audit trail ────────────────────────────────────────────────
            write_audit(cur,
                action="CREATE",
                record_type="operational_activity",
                record_id=act_id,
                record_label=d["description"],
                after={
                    "activity_type": d["activity_type"],
                    "total_cost": total_cost,
                    "finance_entry_id": fin_id,
                    "inventory_items_count": len(d.get("inventory_items", [])),
                },
                user_id=user["id"]
            )
            # Transaction commits here ─────────────────────────────────────────

    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        log_security("ACTIVITY_CREATE_ERROR", str(e), user_id=user.get("id"))
        return jsonify({"error": "Activity could not be saved — transaction rolled back"}), 500

    # ── 6. Fire low-stock notifications (outside tx — these are best-effort) ──
    for inv_id, inv_data in low_stock_notifications:
        create_notification(
            user["id"],
            f"Low Stock: {inv_data['name']}",
            f"{inv_data['name']} is at {inv_data['on_hand']} {inv_data['unit']} "
            f"(par level: {inv_data['par_level']})",
            "warning", "inventory", inv_id
        )

    row = query("""
        SELECT a.*, u.name as unit_name
        FROM operational_activities a
        LEFT JOIN operational_units u ON a.unit_id=u.id
        WHERE a.id=%s
    """, (act_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/erp/activities/<int:aid>", methods=["GET"])
@require_auth
def get_activity(aid):
    row = query("""
        SELECT a.*, u.name as unit_name, us.name as performed_by_name
        FROM operational_activities a
        LEFT JOIN operational_units u ON a.unit_id=u.id
        LEFT JOIN users us ON a.performed_by=us.id
        WHERE a.id=%s
    """, (aid,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    result = row_to_dict(row)
    # Add consumption detail
    consumption = query("""
        SELECT ic.*, i.name as item_name, i.unit
        FROM inventory_consumption ic
        JOIN inventory i ON ic.inventory_id=i.id
        WHERE ic.activity_id=%s
    """, (aid,))
    result["inventory_consumed"] = rows_to_list(consumption)
    # Add labor
    labor = query("""
        SELECT la.*, w.name as worker_name
        FROM labor_allocations la
        LEFT JOIN workers w ON la.worker_id=w.id
        WHERE la.activity_id=%s
    """, (aid,))
    result["labor"] = rows_to_list(labor)
    return jsonify(result)


@app.route("/api/erp/activities/<int:aid>", methods=["DELETE"])
@require_role("owner", "manager")
def delete_activity(aid):
    """
    Soft-delete an activity and atomically restore all consumed inventory.
    All inventory restores and the activity deletion share one transaction —
    either all complete or none do.
    Finance entries linked via ACT-{id} reference are soft-deleted (voided),
    not permanently removed, to preserve ledger traceability.
    """
    user = g.user
    try:
        with db_transaction() as (db, cur):
            # Lock the activity row
            activity = tx_query(cur,
                "SELECT * FROM operational_activities WHERE id=%s FOR UPDATE",
                (aid,), one=True
            )
            if not activity:
                raise ValueError("Activity not found")

            # Read consumption records (lock inventory rows they touch)
            consumptions = tx_query(cur,
                "SELECT * FROM inventory_consumption WHERE activity_id=%s",
                (aid,)
            )

            for c in consumptions:
                # Lock inventory row before restoring
                cur.execute(
                    "SELECT id FROM inventory WHERE id=%s FOR UPDATE",
                    (c["inventory_id"],)
                )
                cur.execute(
                    "UPDATE inventory SET on_hand=on_hand+%s, last_updated=NOW() WHERE id=%s",
                    (c["quantity_used"], c["inventory_id"])
                )
                if c["lot_id"]:
                    cur.execute(
                        "UPDATE inventory_lots SET quantity_remaining=quantity_remaining+%s WHERE id=%s",
                        (c["quantity_used"], c["lot_id"])
                    )

            # Void (soft-delete) the linked finance entry rather than hard-delete
            cur.execute(
                """UPDATE finance SET notes = COALESCE(notes,'') || ' [VOIDED: activity deleted]',
                          category = 'VOIDED-' || category
                   WHERE reference=%s AND category NOT LIKE 'VOIDED-%%'""",
                (f"ACT-{aid}",)
            )

            # Hard delete the activity (cascades to inventory_consumption via FK)
            cur.execute("DELETE FROM operational_activities WHERE id=%s", (aid,))

            write_audit(cur,
                action="DELETE",
                record_type="operational_activity",
                record_id=aid,
                record_label=activity.get("description", ""),
                before={
                    "activity_type": activity.get("activity_type"),
                    "total_cost": float(activity.get("total_cost") or 0),
                    "status": activity.get("status"),
                },
                user_id=user["id"]
            )

    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        log_security("ACTIVITY_DELETE_ERROR", str(e), user_id=user.get("id"))
        return jsonify({"error": "Delete failed — transaction rolled back"}), 500

    return jsonify({"deleted": aid})


# ── LABOR ALLOCATIONS ────────────────────────────────────────────────────────

@app.route("/api/erp/labor", methods=["GET"])
@require_auth
def get_labor_allocations():
    worker_id = request.args.get("worker_id")
    unit_id = request.args.get("unit_id")
    rows = query(
        """SELECT la.*, w.name as worker_name, w.role as worker_role,
                  u.name as unit_name, a.description as activity_desc
           FROM labor_allocations la
           LEFT JOIN workers w ON la.worker_id=w.id
           LEFT JOIN operational_units u ON la.unit_id=u.id
           LEFT JOIN operational_activities a ON la.activity_id=a.id
           ORDER BY la.allocation_date DESC
           LIMIT 100"""
    )
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/labor", methods=["POST"])
@require_auth
def create_labor_allocation():
    d = request.get_json() or {}
    lid = mutate(
        """INSERT INTO labor_allocations (activity_id,worker_id,unit_id,hours,hourly_rate,allocation_date,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d.get("activity_id"), d["worker_id"], d.get("unit_id"), d.get("hours", 0),
         d.get("hourly_rate", 0), d.get("allocation_date", datetime.utcnow().date().isoformat()), d.get("notes"))
    )
    # Update activity total cost if linked
    if d.get("activity_id"):
        recalculate_activity_cost(d["activity_id"])
    return jsonify(row_to_dict(query("SELECT * FROM labor_allocations WHERE id=%s", (lid,), one=True))), 201


# ── PRODUCTION BATCHES ───────────────────────────────────────────────────────

@app.route("/api/erp/production", methods=["GET"])
@require_auth
def get_production():
    rows = query("""
        SELECT pb.*, u.name as unit_name, s.name as season_name
        FROM production_batches pb
        LEFT JOIN operational_units u ON pb.unit_id=u.id
        LEFT JOIN seasons s ON pb.season_id=s.id
        ORDER BY pb.batch_date DESC
    """)
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/production", methods=["POST"])
@require_auth
def create_production_batch():
    """
    Record a production batch. If actual_revenue > 0, a matching finance
    income entry is created in the same transaction.
    """
    idem_key = request.headers.get("Idempotency-Key", "")
    if idem_key and check_idempotency(idem_key):
        return jsonify({"error": "Duplicate request — this production batch has already been recorded"}), 409

    d = request.get_json() or {}
    if not d.get("product_type") or not d.get("quantity"):
        return jsonify({"error": "product_type and quantity are required"}), 400

    user = g.user
    batch_date = d.get("batch_date", datetime.utcnow().date().isoformat())
    revenue = float(d.get("actual_revenue", 0))
    bid = None

    try:
        with db_transaction() as (db, cur):
            bid = tx_mutate(cur,
                """INSERT INTO production_batches
                       (unit_id,season_id,product_type,quantity,unit_of_measure,
                        actual_revenue,batch_date,notes)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (d.get("unit_id"), d.get("season_id"), d["product_type"], d["quantity"],
                 d.get("unit_of_measure", "kg"), revenue, batch_date, d.get("notes"))
            )
            fin_id = None
            if revenue > 0:
                fin_id = tx_mutate(cur,
                    """INSERT INTO finance (type,category,description,amount,date,reference)
                       VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                    ("income", "Production Sale",
                     f"{d['product_type']} — {d['quantity']} {d.get('unit_of_measure','kg')}",
                     revenue, batch_date, f"PROD-{bid}")
                )
            write_audit(cur,
                action="CREATE",
                record_type="production_batch",
                record_id=bid,
                record_label=d["product_type"],
                after={"quantity": d["quantity"], "revenue": revenue, "finance_entry_id": fin_id},
                user_id=user["id"]
            )
    except Exception as e:
        log_security("PRODUCTION_BATCH_ERROR", str(e), user_id=user.get("id"))
        return jsonify({"error": "Production batch could not be saved — transaction rolled back"}), 500

    return jsonify(row_to_dict(query("SELECT * FROM production_batches WHERE id=%s", (bid,), one=True))), 201


# ── INVENTORY LOTS ───────────────────────────────────────────────────────────

@app.route("/api/erp/inventory-lots", methods=["GET"])
@require_auth
def get_inventory_lots():
    inv_id = request.args.get("inventory_id")
    if inv_id:
        rows = query(
            "SELECT il.*, i.name as item_name, i.unit FROM inventory_lots il JOIN inventory i ON il.inventory_id=i.id WHERE il.inventory_id=%s ORDER BY il.received_date DESC",
            (inv_id,)
        )
    else:
        rows = query(
            "SELECT il.*, i.name as item_name, i.unit FROM inventory_lots il JOIN inventory i ON il.inventory_id=i.id ORDER BY il.received_date DESC LIMIT 100"
        )
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/inventory-lots", methods=["POST"])
@require_auth
def create_inventory_lot():
    """
    Receive inventory: creates lot + increases on_hand + records purchase expense.

    TRANSACTION SAFETY: lot insert, on_hand increment, and finance entry all
    commit together or not at all. The inventory row is locked before update
    to prevent concurrent receipt races.
    """
    idem_key = request.headers.get("Idempotency-Key", "")
    if idem_key and check_idempotency(idem_key):
        return jsonify({"error": "Duplicate request — this receipt has already been processed"}), 409

    d = request.get_json() or {}
    if not d.get("inventory_id") or not d.get("quantity_received") or not d.get("unit_cost"):
        return jsonify({"error": "inventory_id, quantity_received, and unit_cost are required"}), 400

    qty = float(d["quantity_received"])
    unit_cost = float(d["unit_cost"])
    if qty <= 0 or unit_cost < 0:
        return jsonify({"error": "quantity_received must be > 0 and unit_cost must be >= 0"}), 422

    recv_date = d.get("received_date", datetime.utcnow().date().isoformat())
    user = g.user
    lot_id = None

    try:
        with db_transaction() as (db, cur):
            # Lock inventory row before modifying on_hand
            inv = tx_query(cur,
                "SELECT * FROM inventory WHERE id=%s FOR UPDATE",
                (d["inventory_id"],), one=True
            )
            if not inv:
                raise ValueError(f"Inventory item {d['inventory_id']} not found")

            # Create lot
            lot_id = tx_mutate(cur,
                """INSERT INTO inventory_lots
                       (inventory_id,lot_number,quantity_received,quantity_remaining,
                        unit_cost,received_date,expiry_date,supplier,notes)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (d["inventory_id"], d.get("lot_number"), qty, qty, unit_cost,
                 recv_date, d.get("expiry_date"), d.get("supplier"), d.get("notes"))
            )

            # Increase on_hand and update rolling unit cost
            cur.execute(
                "UPDATE inventory SET on_hand=on_hand+%s, unit_cost=%s, last_updated=NOW() WHERE id=%s",
                (qty, unit_cost, d["inventory_id"])
            )

            # Record purchase as finance expense
            fin_id = tx_mutate(cur,
                """INSERT INTO finance (type,category,description,amount,date,reference)
                   VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
                ("expense", "Inventory Purchase",
                 f"Purchased {qty} {inv['unit']} of {inv['name']}",
                 qty * unit_cost, recv_date, f"LOT-{lot_id}")
            )

            write_audit(cur,
                action="CREATE",
                record_type="inventory_lot",
                record_id=lot_id,
                record_label=inv["name"],
                after={
                    "inventory_id": d["inventory_id"],
                    "qty": qty, "unit_cost": unit_cost,
                    "finance_entry_id": fin_id,
                },
                user_id=user["id"]
            )

    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        log_security("INV_LOT_CREATE_ERROR", str(e), user_id=user.get("id"))
        return jsonify({"error": "Lot could not be saved — transaction rolled back"}), 500

    return jsonify(row_to_dict(query("SELECT * FROM inventory_lots WHERE id=%s", (lot_id,), one=True))), 201


# ── ASSET DEPRECIATION ───────────────────────────────────────────────────────

@app.route("/api/erp/depreciation", methods=["GET"])
@require_auth
def get_depreciation():
    rows = query("""
        SELECT ad.*, a.asset_id as asset_code, a.description as asset_desc, a.value as asset_value
        FROM asset_depreciation ad
        JOIN assets a ON ad.asset_id=a.id
        ORDER BY a.asset_id
    """)
    result = []
    for row in rows_to_list(rows):
        # Calculate current book value
        asset_val = float(row.get("asset_value") or 0)
        accum = float(row.get("accumulated_depreciation") or 0)
        row["book_value"] = max(float(row.get("residual_value") or 0), asset_val - accum)
        result.append(row)
    return jsonify(result)


@app.route("/api/erp/depreciation", methods=["POST"])
@require_role("owner", "manager", "finance")
def create_depreciation():
    d = request.get_json() or {}
    # Calculate annual depreciation (straight line)
    asset = query("SELECT * FROM assets WHERE id=%s", (d["asset_id"],), one=True)
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
    asset_value = float(asset["value"] or 0)
    residual = float(d.get("residual_value", 0))
    life = float(d.get("useful_life_years", 5))
    annual_dep = (asset_value - residual) / life if life > 0 else 0

    did = mutate(
        """INSERT INTO asset_depreciation (asset_id,method,useful_life_years,residual_value,depreciation_start,annual_depreciation,accumulated_depreciation,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["asset_id"], d.get("method", "straight_line"), life, residual,
         d.get("depreciation_start", datetime.utcnow().date().isoformat()),
         annual_dep, d.get("accumulated_depreciation", 0), d.get("notes"))
    )
    return jsonify(row_to_dict(query("SELECT * FROM asset_depreciation WHERE id=%s", (did,), one=True))), 201


@app.route("/api/erp/depreciation/<int:did>/run", methods=["POST"])
@require_role("owner", "manager", "finance")
def run_depreciation(did):
    """
    Run a depreciation period — adds annual amount to accumulated and
    creates a matching finance expense entry. Atomic: either both write
    or neither does.
    """
    user = g.user
    try:
        with db_transaction() as (db, cur):
            row = tx_query(cur,
                "SELECT * FROM asset_depreciation WHERE id=%s FOR UPDATE",
                (did,), one=True
            )
            if not row:
                raise ValueError("Depreciation schedule not found")
            annual = float(row["annual_depreciation"])

            cur.execute(
                "UPDATE asset_depreciation SET accumulated_depreciation=accumulated_depreciation+%s WHERE id=%s",
                (annual, did)
            )
            fin_id = tx_mutate(cur,
                "INSERT INTO finance (type,category,description,amount,date) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                ("expense", "Depreciation",
                 f"Asset depreciation — period entry (schedule {did})",
                 annual, datetime.utcnow().date().isoformat())
            )
            write_audit(cur,
                action="DEPRECIATION_RUN",
                record_type="asset_depreciation",
                record_id=did,
                after={"period_amount": annual, "finance_entry_id": fin_id},
                user_id=user["id"]
            )
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        log_security("DEPRECIATION_RUN_ERROR", str(e), user_id=user.get("id"))
        return jsonify({"error": "Depreciation run failed — transaction rolled back"}), 500

    return jsonify(row_to_dict(query("SELECT * FROM asset_depreciation WHERE id=%s", (did,), one=True)))


# ── NOTIFICATIONS ────────────────────────────────────────────────────────────

@app.route("/api/erp/notifications", methods=["GET"])
@require_auth
def get_notifications():
    user = g.user
    unread_only = request.args.get("unread") == "1"
    if unread_only:
        rows = query(
            "SELECT * FROM notifications WHERE user_id=%s AND read_at IS NULL ORDER BY created_at DESC LIMIT 50",
            (user["id"],)
        )
    else:
        rows = query(
            "SELECT * FROM notifications WHERE user_id=%s ORDER BY created_at DESC LIMIT 100",
            (user["id"],)
        )
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/notifications/read-all", methods=["POST"])
@require_auth
def mark_all_notifications_read():
    mutate(
        "UPDATE notifications SET read_at=NOW() WHERE user_id=%s AND read_at IS NULL",
        (g.user["id"],)
    )
    return jsonify({"ok": True})


@app.route("/api/erp/notifications/<int:nid>/read", methods=["POST"])
@require_auth
def mark_notification_read(nid):
    mutate("UPDATE notifications SET read_at=NOW() WHERE id=%s AND user_id=%s", (nid, g.user["id"]))
    return jsonify({"ok": True})


# ── ANALYTICS & REPORTING ────────────────────────────────────────────────────

@app.route("/api/erp/analytics/unit-costs", methods=["GET"])
@require_auth
def get_unit_costs():
    """Per-unit cost and production summary."""
    rows = query("""
        SELECT u.id, u.name, u.unit_type, u.area_ha,
               COALESCE(SUM(a.total_cost),0) as total_activity_cost,
               COALESCE(SUM(pb.actual_revenue),0) as total_production_revenue,
               COALESCE(SUM(pb.quantity),0) as total_quantity_produced
        FROM operational_units u
        LEFT JOIN operational_activities a ON a.unit_id=u.id AND a.status='Completed'
        LEFT JOIN production_batches pb ON pb.unit_id=u.id
        GROUP BY u.id, u.name, u.unit_type, u.area_ha
        ORDER BY total_activity_cost DESC
    """)
    result = []
    for row in rows_to_list(rows):
        cost = float(row["total_activity_cost"])
        rev = float(row["total_production_revenue"])
        row["unit_profit"] = rev - cost
        row["cost_per_ha"] = round(cost / float(row["area_ha"]), 2) if row["area_ha"] else 0
        result.append(row)
    return jsonify(result)


@app.route("/api/erp/analytics/labor-costs", methods=["GET"])
@require_auth
def get_labor_cost_analysis():
    rows = query("""
        SELECT w.id, w.name, w.role, w.department,
               COALESCE(SUM(la.hours),0) as total_hours,
               COALESCE(SUM(la.hours * la.hourly_rate),0) as total_allocated_cost,
               w.salary as monthly_salary
        FROM workers w
        LEFT JOIN labor_allocations la ON la.worker_id=w.id
        GROUP BY w.id, w.name, w.role, w.department, w.salary
        ORDER BY total_allocated_cost DESC
    """)
    return jsonify(rows_to_list(rows))


@app.route("/api/erp/analytics/inventory-valuation", methods=["GET"])
@require_auth
def get_inventory_valuation():
    rows = query("""
        SELECT i.id, i.name, i.category, i.unit, i.on_hand, i.unit_cost,
               (i.on_hand * i.unit_cost) as current_value,
               COALESCE(SUM(ic.quantity_used * ic.unit_cost),0) as total_consumed_value,
               i.par_level,
               CASE WHEN i.on_hand <= i.par_level THEN true ELSE false END as below_par
        FROM inventory i
        LEFT JOIN inventory_consumption ic ON ic.inventory_id=i.id
        GROUP BY i.id, i.name, i.category, i.unit, i.on_hand, i.unit_cost, i.par_level
        ORDER BY current_value DESC
    """)
    total_value = sum(float(r["current_value"] or 0) for r in rows)
    return jsonify({
        "items": rows_to_list(rows),
        "total_value": total_value
    })


@app.route("/api/erp/analytics/budget-variance", methods=["GET"])
@require_auth
def get_budget_variance():
    season_id = request.args.get("season_id")
    budgets_q = query(
        "SELECT * FROM budgets" + (" WHERE season_id=%s" if season_id else "") + " ORDER BY category",
        (season_id,) if season_id else ()
    )
    result = []
    for b in rows_to_list(budgets_q):
        actual = query(
            "SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='expense' AND category ILIKE %s",
            (f"%{b['category']}%",), one=True
        )
        planned = float(b["planned_amount"])
        actual_val = float(actual["total"])
        result.append({
            "category": b["category"],
            "planned": planned,
            "actual": actual_val,
            "variance": planned - actual_val,
            "variance_pct": round((planned - actual_val) / planned * 100, 1) if planned else 0,
            "status": "Under Budget" if actual_val <= planned else "Over Budget"
        })
    return jsonify(result)


@app.route("/api/erp/analytics/cash-flow", methods=["GET"])
@require_auth
def get_cash_flow():
    """Monthly cash flow for last 18 months."""
    rows = query("""
        SELECT
            to_char(TO_DATE(date, 'YYYY-MM-DD'), 'YYYY-MM') as month,
            SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as inflows,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as outflows
        FROM finance
        WHERE TO_DATE(date, 'YYYY-MM-DD') >= CURRENT_DATE - INTERVAL '18 months'
        GROUP BY to_char(TO_DATE(date, 'YYYY-MM-DD'), 'YYYY-MM')
        ORDER BY month ASC
    """)
    data = rows_to_list(rows)
    # Add cumulative cash position
    running = 0.0
    for row in data:
        running += float(row["inflows"]) - float(row["outflows"])
        row["net"] = float(row["inflows"]) - float(row["outflows"])
        row["cumulative"] = round(running, 2)
    return jsonify(data)


@app.route("/api/erp/analytics/pl-summary", methods=["GET"])
@require_auth
def get_pl_summary():
    """Full P&L summary grouped by category."""
    income_cats = query("""
        SELECT category, COALESCE(SUM(amount),0) as total
        FROM finance WHERE type='income'
        GROUP BY category ORDER BY total DESC
    """)
    expense_cats = query("""
        SELECT category, COALESCE(SUM(amount),0) as total
        FROM finance WHERE type='expense'
        GROUP BY category ORDER BY total DESC
    """)
    total_income = sum(float(r["total"]) for r in income_cats)
    total_expense = sum(float(r["total"]) for r in expense_cats)

    # Activity costs by type
    activity_costs = query("""
        SELECT activity_type, COALESCE(SUM(total_cost),0) as total
        FROM operational_activities WHERE status='Completed'
        GROUP BY activity_type ORDER BY total DESC
    """)

    return jsonify({
        "income": rows_to_list(income_cats),
        "expenses": rows_to_list(expense_cats),
        "activity_costs": rows_to_list(activity_costs),
        "total_income": total_income,
        "total_expense": total_expense,
        "gross_profit": total_income - total_expense,
        "gross_margin_pct": round((total_income - total_expense) / total_income * 100, 1) if total_income else 0,
    })


@app.route("/api/erp/analytics/yield-analysis", methods=["GET"])
@require_auth
def get_yield_analysis():
    """Yield per unit with cost analysis."""
    rows = query("""
        SELECT u.name as unit_name, u.unit_type, u.area_ha,
               pb.product_type,
               SUM(pb.quantity) as total_yield,
               pb.unit_of_measure,
               SUM(pb.actual_revenue) as total_revenue,
               COUNT(pb.id) as batch_count
        FROM production_batches pb
        JOIN operational_units u ON pb.unit_id=u.id
        GROUP BY u.name, u.unit_type, u.area_ha, pb.product_type, pb.unit_of_measure
        ORDER BY total_yield DESC
    """)
    result = []
    for row in rows_to_list(rows):
        area = float(row["area_ha"] or 1)
        row["yield_per_ha"] = round(float(row["total_yield"] or 0) / area, 2)
        result.append(row)
    return jsonify(result)


# ── ENHANCED DASHBOARD ────────────────────────────────────────────────────────

@app.route("/api/erp/dashboard", methods=["GET"])
@require_auth
def get_erp_dashboard():
    """Full ERP executive dashboard payload."""
    # Base financials
    income = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='income'", one=True)
    expense = query("SELECT COALESCE(SUM(amount),0) as total FROM finance WHERE type='expense'", one=True)
    total_income = float(income["total"])
    total_expense = float(expense["total"])

    # Activity operational costs
    op_costs = query("SELECT COALESCE(SUM(total_cost),0) as total FROM operational_activities WHERE status='Completed'", one=True)

    # Projected revenue
    proj = query("SELECT COALESCE(SUM(projected_amount),0) as total FROM revenue_projections", one=True)
    proj_total = float(proj["total"])

    # Budget total
    budget = query("SELECT COALESCE(SUM(planned_amount),0) as total FROM budgets", one=True)
    budget_total = float(budget["total"])

    # Contingency
    cont = query("SELECT * FROM contingency_settings ORDER BY id DESC LIMIT 1", one=True)
    contingency_value = 0.0
    if cont:
        if cont["contingency_type"] == "percentage":
            contingency_value = total_expense * float(cont["contingency_pct"]) / 100
        else:
            contingency_value = float(cont["contingency_fixed"])

    # Inventory metrics
    inv_value = query("SELECT COALESCE(SUM(on_hand * unit_cost),0) as total FROM inventory", one=True)
    low_stock = query("SELECT COUNT(*) as total FROM inventory WHERE on_hand <= par_level", one=True)

    # Livestock
    livestock = query("SELECT COALESCE(SUM(count),0) as total FROM livestock", one=True)
    # Crops
    crops = query("SELECT COALESCE(SUM(area_ha),0) as total FROM crops", one=True)
    # Workers
    workers_present = query("SELECT COUNT(*) as total FROM workers WHERE status='Present'", one=True)
    workers_total = query("SELECT COUNT(*) as total FROM workers", one=True)
    # Compliance
    overdue = query("SELECT COUNT(*) as total FROM compliance WHERE status='Overdue'", one=True)
    due_soon = query("SELECT COUNT(*) as total FROM compliance WHERE status='Due Soon'", one=True)
    # Activities this month
    recent_activities = query("""
        SELECT a.activity_type, a.description, a.activity_date, a.total_cost, u.name as unit_name
        FROM operational_activities a
        LEFT JOIN operational_units u ON a.unit_id=u.id
        ORDER BY a.created_at DESC LIMIT 8
    """)
    # Monthly trend (last 6 months)
    monthly = query("""
        SELECT
            to_char(TO_DATE(date, 'YYYY-MM-DD'), 'Mon YY') as month,
            SUM(CASE WHEN type='income' THEN amount ELSE 0 END) as income,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expense
        FROM finance
        WHERE TO_DATE(date, 'YYYY-MM-DD') >= CURRENT_DATE - INTERVAL '6 months'
        GROUP BY to_char(TO_DATE(date, 'YYYY-MM-DD'), 'Mon YY'),
                 to_char(TO_DATE(date, 'YYYY-MM-DD'), 'YYYY-MM')
        ORDER BY to_char(TO_DATE(date, 'YYYY-MM-DD'), 'YYYY-MM') ASC
    """)
    # Unread notifications
    notif_count = query(
        "SELECT COUNT(*) as total FROM notifications WHERE user_id=%s AND read_at IS NULL",
        (g.user["id"],), one=True
    )

    original_profit = total_income - total_expense
    adjusted_profit = total_income - (total_expense + contingency_value)

    return jsonify({
        # Revenue
        "revenue_ytd": total_income,
        "projected_revenue": proj_total,
        "revenue_vs_projection_pct": round(total_income / proj_total * 100, 1) if proj_total else 0,
        # Expenses & Profit
        "expenditure_ytd": total_expense,
        "operational_costs": float(op_costs["total"]),
        "budget_total": budget_total,
        "budget_utilization_pct": round(total_expense / budget_total * 100, 1) if budget_total else 0,
        "original_profit": original_profit,
        "contingency_value": contingency_value,
        "adjusted_expenses": total_expense + contingency_value,
        "adjusted_profit": adjusted_profit,
        "margin_pct": round(original_profit / total_income * 100, 1) if total_income else 0,
        "adjusted_margin_pct": round(adjusted_profit / total_income * 100, 1) if total_income else 0,
        # Operations
        "livestock_count": int(livestock["total"]),
        "crop_hectares": float(crops["total"]),
        "workers_present": int(workers_present["total"]),
        "workers_total": int(workers_total["total"]),
        # Inventory
        "inventory_value": float(inv_value["total"]),
        "low_stock_items": int(low_stock["total"]),
        # Compliance
        "compliance_overdue": int(overdue["total"]),
        "compliance_due_soon": int(due_soon["total"]),
        # Notifications
        "unread_notifications": int(notif_count["total"]),
        # Charts
        "monthly_trend": rows_to_list(monthly),
        "recent_activities": rows_to_list(recent_activities),
    })


# ─── MAIN ──────────────────────────────────────────────────────────────────────

import os
import traceback

# Startup — don't log DATABASE_URL as it contains credentials
print("[startup] Initialising Thornfield ERP...")

try:
    print("[startup] Running init_db()...")
    init_db()
    print("[startup] init_db() OK")
except Exception:
    print("[startup] init_db() FAILED:")
    traceback.print_exc()

try:
    print("[startup] Running init_erp_db()...")
    init_erp_db()
    print("[startup] init_erp_db() OK")
except Exception:
    print("[startup] init_erp_db() FAILED:")
    traceback.print_exc()

# seed_owner() removed — no hardcoded credentials at startup

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Thornfield ERP running at http://localhost:{port}\n")
    app.run(debug=False, host="0.0.0.0", port=port)
