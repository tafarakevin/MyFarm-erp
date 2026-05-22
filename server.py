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
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory

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

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(password, stored):
    try:
        salt, hashed = stored.split(":")
        return hashlib.sha256((salt + password).encode()).hexdigest() == hashed
    except:
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
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    return query(
        "SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=%s AND s.expires_at > NOW() AND u.active=1",
        (token,), one=True
    )


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
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
            user = get_current_user()
            if not user:
                return jsonify({"error": "Unauthorized"}), 401
            if user["role"] not in roles:
                return jsonify({"error": "Forbidden"}), 403
            g.user = user
            return f(*args, **kwargs)
        return decorated
    return decorator




def query(sql, args=(), one=False):
    db = get_db()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def mutate(sql, args=()):
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


def row_to_dict(row):
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows):
    return [dict(r) for r in rows]


# ─── CORS (manual, no dependency needed) ───────────────────────────────────────

@app.after_request
def cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-CSRF-Token"
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
            expires_at  TIMESTAMPTZ NOT NULL,
            created_at  TIMESTAMPTZ DEFAULT NOW()
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
            performed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at   TIMESTAMPTZ DEFAULT NOW()
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
    db.commit()
    db.close()
def seed_db():
    """Seed with Thornfield data if tables are empty. Safe to call multiple times."""
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()

    def empty(table):
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return cur.fetchone()[0] == 0

    if empty("assets"):
        assets = [
            ("AST-001", "John Deere 6130R Tractor",    "Vehicle",        "North Barn",  "Operational", "2025-08-12", 85000),
            ("AST-002", "Irrigation Pump Station B",   "Infrastructure", "West Field",  "Maintenance", "2025-09-01", 22000),
            ("AST-003", "Combine Harvester NH CR8090", "Vehicle",        "South Yard",  "Operational", "2025-07-20", 210000),
            ("AST-004", "Grain Silo — Block C",        "Infrastructure", "Processing",  "Operational", "2025-06-15", 38000),
            ("AST-005", "Sprayer Boom 24m",            "Equipment",      "East Shed",   "Repair",      "2025-10-03", 12000),
            ("AST-006", "Livestock Scale — Digital",   "Equipment",      "Cattle Pen",  "Operational", "2025-09-28", 3500),
            ("AST-007", "Feed Mixer Wagon",            "Equipment",      "Feedlot",     "Operational", "2025-09-10", 18000),
            ("AST-008", "Borehole Pump — North",       "Infrastructure", "North Field", "Maintenance", "2025-09-29", 9500),
            ("AST-009", "Isuzu NQR Truck",             "Vehicle",        "Main Yard",   "Operational", "2025-09-05", 45000),
            ("AST-010", "Solar Panel Array — Barn",    "Infrastructure", "North Barn",  "Operational", "2025-08-01", 28000),
        ]
        cur.executemany(
            "INSERT INTO assets (asset_id,description,category,location,status,last_service,value) VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            assets
        )

    if empty("livestock"):
        herds = [
            ("Herd A — Angus",    "Angus",    428, 524, "Good",    "Grazing", "North Paddock"),
            ("Herd B — Brahman",  "Brahman",  676, 489, "Good",    "Grazing", "East Paddock"),
            ("Flock C — Merino",  "Merino",   612,  68, "Monitor", "Paddock", "West Paddock"),
            ("Herd D — Boer Goat","Boer Goat",126,  52, "Good",    "Browse",  "South Browse"),
        ]
        cur.executemany(
            "INSERT INTO livestock (herd_name,breed,count,avg_weight,health,status,location) VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            herds
        )
        cur.execute("SELECT id FROM livestock ORDER BY id")
        ids = [r[0] for r in cur.fetchall()]
        events = [
            (ids[2], "Health",      "3 animals lame — vet called",         "2025-09-28", "Pending"),
            (ids[0], "Vaccination", "FMD vaccination complete — 428 head", "2025-09-15", "Done"),
            (ids[1], "Weigh-in",    "Next scheduled weigh-in",             "2025-10-10", "Upcoming"),
            (ids[0], "Birth",       "12 calves born — Herd A",             "2025-09-20", "Logged"),
        ]
        cur.executemany(
            "INSERT INTO livestock_events (livestock_id,event_type,description,event_date,status) VALUES (%s,%s,%s,%s,%s)",
            events
        )

    if empty("crops"):
        crops = [
            ("Block N1", "Maize",    48,  "2024-11-01", "2025-04-01", "Harvested", "—",    0,  68400),
            ("Block N2", "Soya Bean",60,  "2024-12-01", "2025-05-01", "Growing",   "Drip", 80, 0),
            ("Block S1", "Tobacco",  90,  "2025-09-01", "2026-03-01", "Seedling",  "Pivot",60, 0),
            ("Block E1", "Wheat",    100, "2025-06-01", "2025-11-01", "Ripening",  "Flood",30, 0),
            ("Block W1", None,       42,  None,         None,         "Fallow",    "—",    0,  0),
        ]
        cur.executemany(
            "INSERT INTO crops (block,crop,area_ha,planted,est_harvest,status,irrigation,irrigation_pct,est_yield_value) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            crops
        )

    if empty("workers"):
        workers = [
            ("Moses Ncube",    "MN", "Field Supervisor",  "Operations", "Present", 520,  "+263 77 100 0001", "2020-03-01"),
            ("Tendai Moyo",    "TM", "Livestock Hand",    "Livestock",  "Present", 380,  "+263 77 100 0002", "2021-06-01"),
            ("Rudo Chiweshe",  "RC", "Crop Technician",   "Crops",      "Present", 420,  "+263 77 100 0003", "2019-11-01"),
            ("Brian Mutasa",   "BM", "Equipment Operator","Maintenance","Leave",   450,  "+263 77 100 0004", "2022-01-15"),
            ("Agnes Gumbo",    "AG", "Accounts Clerk",    "Finance",    "Present", 490,  "+263 77 100 0005", "2018-07-01"),
            ("Peter Zimuto",   "PZ", "Security",          "Operations", "Present", 340,  "+263 77 100 0006", "2023-02-01"),
            ("Farai Mhike",    "FM", "Irrigation Tech",   "Crops",      "Present", 410,  "+263 77 100 0007", "2021-09-01"),
            ("Sarah Mwangi",   "SM", "Estate Manager",    "Management", "Present", 1200, "+263 77 100 0008", "2017-05-01"),
            ("John Dlamini",   "JD", "Driver",            "Operations", "Leave",   360,  "+263 77 100 0009", "2022-08-01"),
        ]
        cur.executemany(
            "INSERT INTO workers (name,initials,role,department,status,salary,phone,start_date) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            workers
        )

    if empty("inventory"):
        items = [
            ("Diesel Fuel",        "Fuel",       "L",    8400, 3000, 12000, 1.20,  "Puma Energy"),
            ("Maize Seed",         "Crop Input", "kg",   2100, 1000, 4000,  3.50,  "Seedco"),
            ("Fertiliser (NPK)",   "Crop Input", "kg",   640,  2000, 5000,  0.85,  "Omnia"),
            ("Cattle Feed Pellets","Feed",        "kg",   3200, 1500, 6000,  0.60,  "Agrifoods"),
            ("Herbicide",          "Chemical",   "L",    180,  400,  800,   12.00, "Syngenta"),
            ("Engine Oil",         "Maintenance","L",    42,   100,  200,   8.50,  "Total"),
            ("Lime",               "Crop Input", "kg",   5000, 1000, 10000, 0.20,  "Local supplier"),
            ("Vaccine — FMD",      "Veterinary", "dose", 240,  500,  1000,  2.20,  "Afrivet"),
            ("Baling Wire",        "Sundry",     "kg",   85,   50,   200,   4.00,  "Hardware store"),
            ("Glyphosate",         "Chemical",   "L",    95,   150,  400,   9.50,  "Agrochem"),
        ]
        cur.executemany(
            "INSERT INTO inventory (name,category,unit,on_hand,par_level,max_level,unit_cost,supplier) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            items
        )

    if empty("finance"):
        records = [
            ("income",  "Crop Sales",      "Maize sales — Block N1",         68400,  "2025-04-30"),
            ("income",  "Livestock Sales", "Cattle sales — 48 head",         112000, "2025-07-15"),
            ("income",  "Tobacco",         "Advance payment — Block S1",     48000,  "2025-09-01"),
            ("income",  "Dairy",           "Milk sales YTD",                 14200,  "2025-09-30"),
            ("income",  "Grants",          "Government agricultural grant",   5800,   "2025-05-01"),
            ("expense", "Labour",          "Payroll Jan–Sep",                88200,  "2025-09-30"),
            ("expense", "Crop Inputs",     "Seed, fertiliser, chemicals YTD",42400,  "2025-09-30"),
            ("expense", "Equipment",       "Maintenance & repairs YTD",      18600,  "2025-09-30"),
            ("expense", "Livestock",       "Feed and veterinary costs YTD",  22400,  "2025-09-30"),
            ("expense", "Fuel & Energy",   "Diesel, electricity YTD",        12600,  "2025-09-30"),
        ]
        cur.executemany(
            "INSERT INTO finance (type,category,description,amount,date) VALUES (%s,%s,%s,%s,%s)",
            records
        )

    if empty("compliance"):
        items = [
            ("Environmental Impact Assessment","Environmental","Compliant","2025-08-01","2026-08-01","EMA Zimbabwe"),
            ("Water Use Permit — Borehole",    "Water",        "Compliant","2023-01-01","2026-12-31","ZINWA"),
            ("ZIMRA Tax Clearance",            "Tax",          "Compliant","2025-01-01","2025-12-31","ZIMRA"),
            ("Livestock Movement Permit",      "Livestock",    "Due Soon", "2025-04-28","2025-10-28","DVS"),
            ("Pesticide Applicator License",   "Chemical",     "Due Soon", "2024-10-15","2025-10-15","MCAZ"),
            ("Annual Fire Safety Inspection",  "Safety",       "Overdue",  "2024-09-01","2025-09-01","Civil Protection"),
            ("Occupational Health & Safety Audit","Safety",    "Overdue",  "2024-08-15","2025-08-15","NSSA"),
        ]
        cur.executemany(
            "INSERT INTO compliance (title,category,status,issued_date,expiry_date,issuing_body) VALUES (%s,%s,%s,%s,%s,%s)",
            items
        )

    if empty("settings"):
        defaults = [
            ("estate_name",         "Thornfield Estate"),
            ("location",            "Harare, Zimbabwe"),
            ("location_lat",        "-17.8292"),
            ("location_lon",        "31.0522"),
            ("total_area",          "340 ha"),
            ("currency",            "USD ($)"),
            ("current_season",      "Autumn 2025"),
            ("notif_alert_emails",  "true"),
            ("notif_stock_warnings","true"),
            ("notif_compliance",    "true"),
            ("notif_daily_summary", "false"),
            ("notif_sms",           "false"),
            ("pref_dark_mode",      "true"),
            ("pref_auto_backup",    "true"),
            ("pref_2fa",            "true"),
            ("pref_audit_logging",  "false"),
        ]
        cur.executemany(
            "INSERT INTO settings (key,value) VALUES (%s,%s) ON CONFLICT DO NOTHING",
            defaults
        )

    db.commit()
    db.close()
def seed_owner():
    """Create a default owner account if no users exist."""
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        pw = hash_password("thornfield2025")
        cur.execute(
            "INSERT INTO users (name,email,password,role) VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING",
            ("James Thornfield", "admin@thornfield.com", pw, "owner")
        )
        db.commit()
        print("  Default owner: admin@thornfield.com / thornfield2025")
    db.close()

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
        d = request.get_json()
        print(f"[login] email={d.get('email')}", flush=True)
        if not d.get("email") or not d.get("password"):
            return jsonify({"error": "Email and password required"}), 400
        user = query("SELECT * FROM users WHERE email=%s AND active=1", (d["email"],), one=True)
        print(f"[login] user found: {bool(user)}", flush=True)
        if not user:
            return jsonify({"error": "Invalid email or password"}), 401
        pw_ok = verify_password(d["password"], user["password"])
        print(f"[login] password ok: {pw_ok}", flush=True)
        if not pw_ok:
            return jsonify({"error": "Invalid email or password"}), 401
        token = secrets.token_hex(32)
        expires = (datetime.utcnow() + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[login] inserting session, expires={expires}", flush=True)
        mutate("INSERT INTO sessions (token,user_id,expires_at) VALUES (%s,%s,%s)", (token, user["id"], expires))
        mutate("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))
        print("[login] success", flush=True)
        return jsonify({
            "token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "pages": ROLE_PAGES.get(user["role"], [])
            }
        })
    except Exception as e:
        print(f"[login] EXCEPTION: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": "Server error", "detail": str(e)}), 500


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    auth = request.headers.get("Authorization", "")[7:]
    mutate("DELETE FROM sessions WHERE token=%s", (auth,))
    return jsonify({"message": "Logged out"})


@app.route("/api/auth/me", methods=["GET", "HEAD"])
@require_auth
def me():
    if request.method == "HEAD":
        return "", 200
    u = g.user
    return jsonify({
        "id": u["id"], "name": u["name"], "email": u["email"],
        "role": u["role"], "pages": ROLE_PAGES.get(u["role"], [])
    })


@app.route("/api/health", methods=["GET", "HEAD"])
def health():
    """Lightweight liveness probe — no auth required."""
    if request.method == "HEAD":
        return "", 200
    return jsonify({"status": "ok", "service": "thornfield-estate"}), 200


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
def update_herd(lid):
    d = request.get_json()
    mutate(
        "UPDATE livestock SET herd_name=%s,breed=%s,count=%s,avg_weight=%s,health=%s,status=%s,location=%s,notes=%s WHERE id=%s",
        (d["herd_name"], d["breed"], d.get("count",0), d.get("avg_weight",0),
         d.get("health","Good"), d.get("status","Grazing"), d.get("location"), d.get("notes"), lid)
    )
    row = query("SELECT * FROM livestock WHERE id=%s", (lid,), one=True)
    return jsonify(row_to_dict(row))


@app.route("/api/livestock/<int:lid>", methods=["DELETE"])
@require_auth
def delete_herd(lid):
    mutate("DELETE FROM livestock WHERE id=%s", (lid,))
    return jsonify({"deleted": lid})


@app.route("/api/livestock/<int:lid>/events", methods=["POST"])
@require_auth
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
def delete_inventory_item(iid):
    mutate("DELETE FROM inventory WHERE id=%s", (iid,))
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
def create_finance_record():
    d = request.get_json()
    new_id = mutate(
        "INSERT INTO finance (type,category,description,amount,date,reference,notes) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
        (d["type"], d["category"], d["description"], d["amount"],
         d["date"], d.get("reference"), d.get("notes"))
    )
    row = query("SELECT * FROM finance WHERE id=%s", (new_id,), one=True)
    return jsonify(row_to_dict(row)), 201


@app.route("/api/finance/<int:fid>", methods=["DELETE"])
@require_auth
def delete_finance_record(fid):
    mutate("DELETE FROM finance WHERE id=%s", (fid,))
    return jsonify({"deleted": fid})


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
    rows = query("""
        SELECT a.*, u.name as user_name
        FROM audit_log a
        LEFT JOIN users u ON a.performed_by = u.id
        ORDER BY a.created_at DESC
        LIMIT 200
    """)
    return jsonify(rows_to_list(rows))


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


def seed_erp_db():
    """Seed ERP tables with Thornfield demo data."""
    db = psycopg2.connect(DATABASE_URL)
    cur = db.cursor()

    def empty(table):
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        return cur.fetchone()[0] == 0

    if empty("farms"):
        cur.execute(
            "INSERT INTO farms (name,location,total_ha,currency) VALUES (%s,%s,%s,%s) RETURNING id",
            ("Thornfield Estate", "Harare, Zimbabwe", 340, "USD")
        )
        farm_id = cur.fetchone()[0]
        # Operational Units
        units = [
            (farm_id, "Block N1 — Maize", "field", 48),
            (farm_id, "Block N2 — Soya Bean", "field", 60),
            (farm_id, "Block S1 — Tobacco", "field", 90),
            (farm_id, "Block E1 — Wheat", "field", 100),
            (farm_id, "Block W1 — Fallow", "field", 42),
            (farm_id, "Herd A — Angus", "herd", 0),
            (farm_id, "Herd B — Brahman", "herd", 0),
            (farm_id, "Flock C — Merino", "herd", 0),
            (farm_id, "North Barn Warehouse", "warehouse", 0),
            (farm_id, "Processing Silo C", "silo", 0),
        ]
        cur.executemany(
            "INSERT INTO operational_units (farm_id,name,unit_type,area_ha) VALUES (%s,%s,%s,%s)",
            units
        )
        # Cost Centers
        centers = [
            (farm_id, "Crop Operations", "CC-CROP"),
            (farm_id, "Livestock Operations", "CC-LIVE"),
            (farm_id, "Machinery & Equipment", "CC-MACH"),
            (farm_id, "Labour", "CC-LAB"),
            (farm_id, "Irrigation", "CC-IRRIG"),
        ]
        cur.executemany(
            "INSERT INTO cost_centers (farm_id,name,code) VALUES (%s,%s,%s)",
            centers
        )
        # Season
        cur.execute(
            "INSERT INTO seasons (farm_id,name,start_date,end_date,status) VALUES (%s,%s,%s,%s,%s) RETURNING id",
            (farm_id, "Season 2025/2026", "2025-09-01", "2026-04-30", "Active")
        )
        season_id = cur.fetchone()[0]
        # Budgets
        budgets = [
            (season_id, "Labour", 96000),
            (season_id, "Crop Inputs", 48000),
            (season_id, "Fuel & Energy", 18000),
            (season_id, "Equipment Maintenance", 22000),
            (season_id, "Livestock Feed & Vet", 28000),
            (season_id, "Irrigation", 12000),
            (season_id, "Administration", 8000),
        ]
        cur.executemany(
            "INSERT INTO budgets (season_id,category,planned_amount) VALUES (%s,%s,%s)",
            budgets
        )
        # Revenue Projections
        projections = [
            (season_id, "Maize — Block N1 (60t @ $220/t)", 13200),
            (season_id, "Tobacco — Block S1 (45t @ $2100/t)", 94500),
            (season_id, "Wheat — Block E1 (380t @ $280/t)", 106400),
            (season_id, "Soya Bean — Block N2 (120t @ $480/t)", 57600),
            (season_id, "Cattle Sales — 80 head", 144000),
            (season_id, "Milk Production — YTD", 18000),
        ]
        cur.executemany(
            "INSERT INTO revenue_projections (season_id,description,projected_amount) VALUES (%s,%s,%s)",
            projections
        )
        # Contingency
        cur.execute(
            "INSERT INTO contingency_settings (season_id,contingency_type,contingency_pct) VALUES (%s,%s,%s)",
            (season_id, "percentage", 10)
        )
        # Inventory Lots
        cur.execute("SELECT id, on_hand, unit_cost FROM inventory ORDER BY id LIMIT 10")
        inv_rows = cur.fetchall()
        for row in inv_rows:
            inv_id, qty, cost = row
            cur.execute(
                """INSERT INTO inventory_lots (inventory_id,lot_number,quantity_received,quantity_remaining,unit_cost,received_date)
                   VALUES (%s,%s,%s,%s,%s,%s)""",
                (inv_id, f"LOT-{inv_id:03d}-A", qty, qty, cost, "2025-09-01")
            )

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
    Automatically:
    - Deducts inventory stock
    - Records consumption at lot cost (LIFO)
    - Recalculates total activity cost
    - Creates finance expense entry
    - Triggers low-stock notifications
    """
    d = request.get_json() or {}
    user = g.user

    # Create the activity
    act_id = mutate(
        """INSERT INTO operational_activities
           (activity_type,unit_id,season_id,cost_center_id,description,activity_date,status,notes,performed_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (
            d["activity_type"], d.get("unit_id"), d.get("season_id"),
            d.get("cost_center_id"), d["description"],
            d.get("activity_date", datetime.utcnow().date().isoformat()),
            d.get("status", "Completed"), d.get("notes"), user["id"]
        )
    )

    total_inv_cost = 0.0

    # Process inventory consumption items
    for item in d.get("inventory_items", []):
        inv_id = item["inventory_id"]
        qty_needed = float(item["quantity"])

        # Get current inventory
        inv = query("SELECT * FROM inventory WHERE id=%s", (inv_id,), one=True)
        if not inv:
            continue

        # LIFO: get lots ordered by most recent first
        lots = query(
            "SELECT * FROM inventory_lots WHERE inventory_id=%s AND quantity_remaining > 0 ORDER BY received_date DESC",
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

                # Update lot
                mutate(
                    "UPDATE inventory_lots SET quantity_remaining=quantity_remaining-%s WHERE id=%s",
                    (qty_from_lot, lot["id"])
                )
                # Record consumption
                mutate(
                    """INSERT INTO inventory_consumption
                       (activity_id,inventory_id,lot_id,quantity_used,unit_cost)
                       VALUES (%s,%s,%s,%s,%s)""",
                    (act_id, inv_id, lot["id"], qty_from_lot, lot_unit_cost)
                )
                qty_remaining -= qty_from_lot
        else:
            # No lots, use current unit cost
            unit_cost = float(inv["unit_cost"])
            item_cost = qty_needed * unit_cost
            mutate(
                """INSERT INTO inventory_consumption
                   (activity_id,inventory_id,quantity_used,unit_cost)
                   VALUES (%s,%s,%s,%s)""",
                (act_id, inv_id, qty_needed, unit_cost)
            )

        # Deduct from main inventory
        mutate(
            "UPDATE inventory SET on_hand=GREATEST(0, on_hand-%s), last_updated=NOW() WHERE id=%s",
            (qty_needed, inv_id)
        )
        total_inv_cost += item_cost

        # Check low stock threshold and notify
        updated_inv = query("SELECT * FROM inventory WHERE id=%s", (inv_id,), one=True)
        if updated_inv and float(updated_inv["on_hand"]) <= float(updated_inv["par_level"]):
            create_notification(
                user["id"],
                f"Low Stock: {updated_inv['name']}",
                f"{updated_inv['name']} is at {updated_inv['on_hand']} {updated_inv['unit']} (par level: {updated_inv['par_level']})",
                "warning", "inventory", inv_id
            )

    # Recalculate and update total cost
    total_cost = recalculate_activity_cost(act_id)

    # Auto-create finance expense entry for significant activities
    if total_cost > 0:
        mutate(
            "INSERT INTO finance (type,category,description,amount,date,reference) VALUES (%s,%s,%s,%s,%s,%s)",
            (
                "expense",
                d.get("finance_category", d["activity_type"].replace("_", " ").title()),
                d["description"],
                total_cost,
                d.get("activity_date", datetime.utcnow().date().isoformat()),
                f"ACT-{act_id}"
            )
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
    # Restore inventory quantities before deleting
    consumptions = query("SELECT * FROM inventory_consumption WHERE activity_id=%s", (aid,))
    for c in consumptions:
        mutate(
            "UPDATE inventory SET on_hand=on_hand+%s, last_updated=NOW() WHERE id=%s",
            (c["quantity_used"], c["inventory_id"])
        )
        if c["lot_id"]:
            mutate(
                "UPDATE inventory_lots SET quantity_remaining=quantity_remaining+%s WHERE id=%s",
                (c["quantity_used"], c["lot_id"])
            )
    mutate("DELETE FROM operational_activities WHERE id=%s", (aid,))
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
    d = request.get_json() or {}
    bid = mutate(
        """INSERT INTO production_batches (unit_id,season_id,product_type,quantity,unit_of_measure,actual_revenue,batch_date,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d.get("unit_id"), d.get("season_id"), d["product_type"], d["quantity"],
         d.get("unit_of_measure", "kg"), d.get("actual_revenue", 0),
         d.get("batch_date", datetime.utcnow().date().isoformat()), d.get("notes"))
    )
    # If actual revenue > 0, record as income
    if d.get("actual_revenue", 0) > 0:
        mutate(
            "INSERT INTO finance (type,category,description,amount,date,reference) VALUES (%s,%s,%s,%s,%s,%s)",
            ("income", "Production Sale", f"{d['product_type']} — {d['quantity']} {d.get('unit_of_measure','kg')}",
             d["actual_revenue"], d.get("batch_date", datetime.utcnow().date().isoformat()), f"PROD-{bid}")
        )
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
    """Receive inventory: creates lot + increases on_hand + records expense."""
    d = request.get_json() or {}
    qty = float(d["quantity_received"])
    unit_cost = float(d["unit_cost"])

    lot_id = mutate(
        """INSERT INTO inventory_lots (inventory_id,lot_number,quantity_received,quantity_remaining,unit_cost,received_date,expiry_date,supplier,notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (d["inventory_id"], d.get("lot_number"), qty, qty, unit_cost,
         d.get("received_date", datetime.utcnow().date().isoformat()),
         d.get("expiry_date"), d.get("supplier"), d.get("notes"))
    )
    # Increase on_hand
    mutate(
        "UPDATE inventory SET on_hand=on_hand+%s, unit_cost=%s, last_updated=NOW() WHERE id=%s",
        (qty, unit_cost, d["inventory_id"])
    )
    # Record as expense
    inv = query("SELECT * FROM inventory WHERE id=%s", (d["inventory_id"],), one=True)
    if inv:
        mutate(
            "INSERT INTO finance (type,category,description,amount,date,reference) VALUES (%s,%s,%s,%s,%s,%s)",
            ("expense", "Inventory Purchase",
             f"Purchased {qty} {inv['unit']} of {inv['name']}",
             qty * unit_cost,
             d.get("received_date", datetime.utcnow().date().isoformat()),
             f"LOT-{lot_id}")
        )
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
    """Run a depreciation period — adds annual amount to accumulated."""
    row = query("SELECT * FROM asset_depreciation WHERE id=%s", (did,), one=True)
    if not row:
        return jsonify({"error": "Not found"}), 404
    annual = float(row["annual_depreciation"])
    mutate(
        "UPDATE asset_depreciation SET accumulated_depreciation=accumulated_depreciation+%s WHERE id=%s",
        (annual, did)
    )
    # Record as expense
    mutate(
        "INSERT INTO finance (type,category,description,amount,date) VALUES (%s,%s,%s,%s,%s)",
        ("expense", "Depreciation", f"Asset depreciation — period entry", annual, datetime.utcnow().date().isoformat())
    )
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

print(f"[startup] DATABASE_URL = {os.environ.get('DATABASE_URL', 'NOT SET')}")

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

try:
    print("[startup] Running seed_db()...")
    seed_db()
    print("[startup] seed_db() OK")
except Exception:
    print("[startup] seed_db() FAILED:")
    traceback.print_exc()

try:
    print("[startup] Running seed_erp_db()...")
    seed_erp_db()
    print("[startup] seed_erp_db() OK")
except Exception:
    print("[startup] seed_erp_db() FAILED:")
    traceback.print_exc()

try:
    print("[startup] Running seed_owner()...")
    seed_owner()
    print("[startup] seed_owner() OK")
except Exception:
    print("[startup] seed_owner() FAILED:")
    traceback.print_exc()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Thornfield ERP running at http://localhost:{port}\n")
    app.run(debug=False, host="0.0.0.0", port=port)
