from flask import Flask, render_template, request, redirect, session, flash, abort, g, send_from_directory, Response
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename

from config import Config
from utils.mailer import mail, send_email
from utils.logger import add_log
from utils.scanner import is_malicious_file
from utils.alerts import send_admin_alert

import os
import time
import re
import uuid
import secrets
import string
import datetime
import hashlib  # ✅ SHA-256: imported for all four SHA-256 use cases
import json     # ✅ SHA-256: used for log tamper detection serialization
import magic    # python-magic for MIME type checking
import csv
import io

# =====================================================
# APP SETUP
# =====================================================
app = Flask(__name__)
app.config.from_object(Config)

# ── Enforce strong secret key ──────────────────────
secret = app.config.get("SECRET_KEY", "")
if not secret or len(secret) < 32:
    raise RuntimeError(
        "SECRET_KEY must be set and at least 32 characters long. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = secret

# ── Session cookie hardening ───────────────────────
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"]   = True    # Must be True in production (HTTPS)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30-minute session expiry

# ── File upload config ─────────────────────────────
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB hard cap — prevents DoS

bcrypt = Bcrypt(app)
csrf   = CSRFProtect(app)
mail.init_app(app)


# =====================================================
# SHA-256 HELPERS
# =====================================================

# ── 1. FILE INTEGRITY ─────────────────────────────
def get_file_hash(filepath):
    """
    Compute SHA-256 of a file in 8 KB chunks.
    Used to verify resume files haven't been tampered
    with after upload.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_file_integrity(filepath, stored_hash):
    """
    Re-hash the file on disk and compare to the stored hash.
    Returns True if intact, False if modified or missing.
    """
    if not stored_hash:
        return True   # Legacy file uploaded before hashing was added
    try:
        return get_file_hash(filepath) == stored_hash
    except FileNotFoundError:
        return False


# ── 2. LOG TAMPER DETECTION ───────────────────────
def hash_log_entry(entry):
    """
    SHA-256 of a log entry's core fields (user, action, ip, timestamp).
    Any post-write modification to those fields will be detectable.
    """
    hashable = json.dumps({
        "user":      entry.get("user", ""),
        "action":    entry.get("action", ""),
        "ip":        entry.get("ip", ""),
        "timestamp": entry.get("timestamp", ""),
    }, sort_keys=True)
    return hashlib.sha256(hashable.encode()).hexdigest()


def verify_log_integrity(log_entry):
    """
    Re-compute expected hash for a log entry and compare.
    Returns True if untampered, False if the entry was modified.
    """
    stored_hash = log_entry.get("integrity_hash")
    if not stored_hash:
        return True   # Legacy entry before hashing was added
    return hashlib.sha256(
        json.dumps({
            "user":      log_entry.get("user", ""),
            "action":    log_entry.get("action", ""),
            "ip":        log_entry.get("ip", ""),
            "timestamp": log_entry.get("timestamp", ""),
        }, sort_keys=True).encode()
    ).hexdigest() == stored_hash


# ── 3. OTP HASHING ───────────────────────────────
def hash_otp(otp: str) -> str:
    """
    SHA-256 hash of an OTP for safe session storage.
    OTPs are short-lived (5 min) and generated via secrets,
    so SHA-256 is acceptable here — unlike long-lived passwords.
    """
    return hashlib.sha256(otp.encode()).hexdigest()


# ── 4. SESSION FINGERPRINTING ─────────────────────
def generate_session_fingerprint(req) -> str:
    """
    SHA-256 fingerprint of the client's browser environment.
    If this changes mid-session, it likely means the session
    cookie was stolen and replayed from a different machine.
    IP is intentionally excluded — mobile users roam networks.
    """
    data = "|".join([
        req.user_agent.string or "",
        str(req.accept_languages),
        str(req.accept_encodings),
    ])
    return hashlib.sha256(data.encode()).hexdigest()


# =====================================================
# CSP NONCE — generated once per request
# =====================================================
@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)


# =====================================================
# ENFORCE FIRST-LOGIN PASSWORD CHANGE
# =====================================================
@app.before_request
def enforce_password_change():
    """
    If an authenticated user has must_change_pass=True, redirect every
    request to /change_password until they comply.
    """
    if not request.endpoint:
        return
    exempt = {"change_password", "logout", "csp_report", "static"}
    if request.endpoint in exempt:
        return
    if "user" in session:
        user_doc = db.users.find_one(
            {"email": session["user"]},
            {"must_change_pass": 1}
        )
        if user_doc and user_doc.get("must_change_pass"):
            flash("You must change your password before continuing.")
            return redirect("/change_password")


# =====================================================
# ✅ SHA-256 (4): SESSION FINGERPRINT CHECK
# Detects session hijacking on every authenticated request.
# =====================================================
@app.before_request
def check_session_fingerprint():
    """
    Re-compute the browser fingerprint on every authenticated request
    and compare to what was stored at login time.
    Mismatch → kill the session immediately and alert admin.
    """
    # Guard: endpoint can be None for unmatched routes
    if not request.endpoint:
        return

    exempt = {
        "login", "logout", "register", "static",
        "forgot_password", "reset_password", "csp_report",
        "verify_otp", "index",
    }
    if request.endpoint in exempt:
        return

    # Only check authenticated sessions that have a stored fingerprint
    if "user" not in session or "fingerprint" not in session:
        return

    try:
        current_fp = generate_session_fingerprint(request)
        stored_fp  = session.get("fingerprint")

        if stored_fp and current_fp != stored_fp:
            suspected_email = session.get("user", "unknown")
            try:
                add_log(db, suspected_email, "SESSION_HIJACK_DETECTED", request.remote_addr)
                send_admin_alert(
                    f"Possible session hijack for {suspected_email} from IP "
                    f"{request.remote_addr}. Fingerprint mismatch detected."
                )
            except Exception:
                pass  # Don't let logging failure block the security response
            session.clear()
            flash("Your session was terminated for security reasons. Please log in again.")
            return redirect("/login")
    except Exception:
        # Never let fingerprint check crash a legitimate request
        pass


# =====================================================
# JINJA2 FILTER — Unix timestamp → human-readable string
# =====================================================
@app.template_filter("timestamp_to_str")
def timestamp_to_str(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


# =====================================================
# RATE LIMITER
# =====================================================
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[]
)


# =====================================================
# UPLOAD FOLDER
# =====================================================
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx"}
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


# =====================================================
# DATABASE
# =====================================================
client = MongoClient(app.config["MONGO_URI"])
db = client["recruitment_db"]


def ensure_indexes():
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.applications.create_index([("user_email", ASCENDING)])
    db.applications.create_index([("employer_email", ASCENDING)])
    db.security_logs.create_index([("ip", ASCENDING)])
    db.security_logs.create_index([("action", ASCENDING)])
    db.security_logs.create_index([("timestamp", DESCENDING)])


# =====================================================
# ADMIN SEEDING
# =====================================================
def seed_admin():
    admin_email    = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not admin_email or not admin_password:
        print("[WARN] ADMIN_EMAIL / ADMIN_PASSWORD not set — no superuser seeded.")
        return

    if db.users.find_one({"email": admin_email}):
        return

    if not strong_password(admin_password):
        raise RuntimeError(
            "ADMIN_PASSWORD does not meet strength requirements "
            "(8+ chars, upper, lower, digit, special)."
        )

    hashed = bcrypt.generate_password_hash(admin_password).decode("utf-8")
    db.users.insert_one({
        "name":             "System Administrator",
        "email":            admin_email,
        "password":         hashed,
        "role":             "admin",
        "company":          None,
        "failed_attempts":  0,
        "locked_until":     0,
        "created_by":       "seed",
        "must_change_pass": False,
    })
    print(f"[INFO] Admin account seeded for {admin_email}")


# =====================================================
# HELPERS
# =====================================================

def sanitize_string(value, max_length=200):
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_length]


def get_fresh_user(email):
    """Re-fetch full user doc from DB — never rely on stale session data for auth."""
    return db.users.find_one({"email": email})


def get_fresh_role(email):
    user = db.users.find_one({"email": email}, {"role": 1})
    return user["role"] if user else None


def require_role(*roles):
    """
    Decorator: verifies session exists AND re-validates role live from DB.
    Prevents privilege escalation even if session is somehow stale.
    """
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user" not in session:
                return redirect("/login")
            live_role = get_fresh_role(session["user"])
            if live_role not in roles:
                abort(403)
            session["role"] = live_role
            return f(*args, **kwargs)
        return wrapped
    return decorator


def validate_file(file):
    """
    Two-layer file validation:
      1. Extension whitelist
      2. Magic-byte MIME detection (prevents extension spoofing)
    """
    filename = secure_filename(file.filename)
    ext = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        return False, "File type not allowed"

    header = file.read(2048)
    file.seek(0)

    detected_mime = magic.from_buffer(header, mime=True)
    if detected_mime not in ALLOWED_MIME_TYPES:
        return False, f"File content does not match extension (detected: {detected_mime})"

    return True, None


def strong_password(password):
    """
    Enforces password policy:
    - 8+ characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+=\-]", password):
        return False
    return True


def generate_otp():
    """
    Cryptographically secure OTP via secrets module.
    Always produces exactly 6 digits.
    """
    return str(secrets.randbelow(900000) + 100000)


def regenerate_session(keep_keys=None):
    """
    Proper session fixation prevention.
    Clears the current session and re-populates only the keys we
    explicitly carry forward, forcing a new session ID.
    """
    keep_keys = keep_keys or []
    kept = {k: session[k] for k in keep_keys if k in session}
    session.clear()
    session.update(kept)


# =====================================================
# SECURITY HEADERS (CSP with per-request nonce)
# =====================================================
@app.after_request
def add_security_headers(response):
    nonce = getattr(g, "csp_nonce", secrets.token_hex(16))

    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"]             = "no-store, no-cache, must-revalidate"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; "
        f"style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        f"font-src 'self' https://fonts.gstatic.com; "
        f"img-src 'self' data:; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"report-uri /csp-report;"
    )
    return response


# =====================================================
# CSP VIOLATION REPORT ENDPOINT
# =====================================================
@app.route("/csp-report", methods=["POST"])
@csrf.exempt
def csp_report():
    try:
        raw = request.data[:1000].decode("utf-8", errors="replace")
        add_log(db, "system", f"CSP_VIOLATION:{raw}", request.remote_addr)
    except Exception:
        pass
    return "", 204


# =====================================================
# CSRF ERROR HANDLER
# =====================================================
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Session expired or invalid request. Please try again.")
    return redirect(request.referrer or "/"), 400


# =====================================================
# FILE TOO LARGE ERROR HANDLER
# =====================================================
@app.errorhandler(413)
def file_too_large(e):
    flash("File too large. Maximum allowed size is 5 MB.")
    return redirect(request.referrer or "/jobs"), 413


# =====================================================
# HOME
# =====================================================
@app.route("/")
def index():
    return render_template("index.html")


# =====================================================
# REGISTER (candidates only)
# =====================================================
@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if request.method == "POST":
        name     = sanitize_string(request.form.get("name", ""), 100)
        email    = sanitize_string(request.form.get("email", ""), 254).lower()
        password = request.form.get("password", "").strip()

        role = "candidate"

        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Invalid email address")
            return redirect("/register")

        if db.users.find_one({"email": email}):
            flash("Email already registered")
            return redirect("/register")

        if not strong_password(password):
            flash("Weak Password: needs 8+ chars, uppercase, lowercase, number, special char")
            return redirect("/register")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        db.users.insert_one({
            "name":             name,
            "email":            email,
            "password":         hashed,
            "role":             role,
            "company":          None,
            "failed_attempts":  0,
            "locked_until":     0,
            "created_by":       "self",
            "must_change_pass": False,
        })

        add_log(db, email, "REGISTER_SUCCESS", request.remote_addr)
        flash("Registration successful. Please log in.")
        return redirect("/login")

    return render_template("register.html")


# =====================================================
# LOGIN
# =====================================================
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    import random
    ip = request.remote_addr

    # IP block check
    blocked = db.blocked_ips.find_one({"ip": ip})
    if blocked:
        if blocked["until"] > time.time():
            return render_template("blocked.html")
        else:
            db.blocked_ips.delete_one({"ip": ip})

    if request.method == "GET":
        a = random.randint(1, 9)
        b = random.randint(1, 9)
        session["captcha_answer"] = str(a + b)
        return render_template("login.html", captcha_question=f"{a} + {b}")

    email        = sanitize_string(request.form.get("email", ""), 254).lower()
    password     = request.form.get("password", "").strip()
    user_captcha = sanitize_string(request.form.get("captcha", ""), 10)

    # CAPTCHA check
    if user_captcha != session.get("captcha_answer"):
        add_log(db, email, "CAPTCHA_FAILED", ip)
        flash("Wrong CAPTCHA answer")
        session.pop("captcha_answer", None)
        return redirect("/login")

    session.pop("captcha_answer", None)

    user = db.users.find_one({"email": email})

    if not user:
        # Dummy hash check — prevents user enumeration via timing difference
        bcrypt.check_password_hash(
            "$2b$12$placeholderplaceholderplaceholderplaceholderplaceholder",
            password
        )
        add_log(db, email, "LOGIN_FAILED", ip)
        flash("Invalid credentials")
        return redirect("/login")

    # Account lock check
    if user.get("locked_until", 0) > time.time():
        add_log(db, email, "ACCOUNT_LOCKED", ip)
        remaining = int((user["locked_until"] - time.time()) / 60) + 1
        flash(f"Account locked. Try again in {remaining} minute(s).")
        return redirect("/login")

    try:
        password_match = bcrypt.check_password_hash(user["password"], password)
    except ValueError as e:
        print(f"Invalid password hash for user {email}: {e}")
        add_log(db, email, "LOGIN_FAILED", ip)
        flash("Invalid credentials")
        return redirect("/login")

    if password_match:
        db.users.update_one({"email": email}, {"$set": {"failed_attempts": 0}})

        otp = generate_otp()

        # ✅ SHA-256 (3): Store OTP hash in session, never plaintext
        session["otp"]          = hash_otp(otp)
        session["otp_expiry"]   = time.time() + 300
        session["otp_attempts"] = 0
        session["temp_user"]    = user["email"]
        session["temp_name"]    = user["name"]
        session["temp_role"]    = user["role"]
        session["temp_company"] = user.get("company")

        send_email(app, email, "OTP Verification",
                   f"Your OTP is {otp}. It expires in 5 minutes. Do not share it.")
        add_log(db, email, "OTP_SENT", ip)
        return redirect("/verify_otp")

    # Wrong password
    attempts    = user.get("failed_attempts", 0) + 1
    update_data = {"failed_attempts": attempts}

    if attempts >= 5:
        update_data["locked_until"] = time.time() + 300
        add_log(db, email, "ACCOUNT_LOCKED", ip)
        send_admin_alert(
            f"Account locked for {email} after {attempts} failed attempts from IP {ip}."
        )

    db.users.update_one({"email": email}, {"$set": update_data})
    add_log(db, email, "LOGIN_FAILED", ip)

    # Auto-block IP after 10 cumulative failures
    fail_count = db.security_logs.count_documents({"ip": ip, "action": "LOGIN_FAILED"})
    if fail_count >= 10:
        db.blocked_ips.update_one(
            {"ip": ip},
            {"$set": {"ip": ip, "until": time.time() + 900}},
            upsert=True
        )
        add_log(db, email, "IP_BLOCKED", ip)
        send_admin_alert(f"IP {ip} auto-blocked after 10 failed login attempts.")
        return render_template("blocked.html")

    flash("Invalid credentials")
    return redirect("/login")


# =====================================================
# VERIFY OTP
# =====================================================
@app.route("/verify_otp", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_otp():
    if request.method == "POST":
        otp          = sanitize_string(request.form.get("otp", ""), 10)
        max_attempts = 5

        if time.time() > session.get("otp_expiry", 0):
            session.pop("otp", None)
            flash("OTP has expired. Please log in again.")
            return redirect("/login")

        attempts = session.get("otp_attempts", 0) + 1
        session["otp_attempts"] = attempts

        if attempts > max_attempts:
            add_log(db, session.get("temp_user", "unknown"), "OTP_BRUTE_FORCE", request.remote_addr)
            send_admin_alert(
                f"OTP brute force detected for {session.get('temp_user', 'unknown')} "
                f"from IP {request.remote_addr}."
            )
            session.clear()
            flash("Too many wrong OTP attempts. Please log in again.")
            return redirect("/login")

        # ✅ SHA-256 (3): Compare hash of user input against stored OTP hash
        if hash_otp(otp) == session.get("otp"):
            user_email   = session["temp_user"]
            user_name    = session["temp_name"]
            user_role    = session["temp_role"]
            user_company = session["temp_company"]

            # Full session regeneration to prevent session fixation
            regenerate_session()

            session["user"]        = user_email
            session["name"]        = user_name
            session["role"]        = user_role
            session["company"]     = user_company
            # ✅ SHA-256 (4): Store browser fingerprint after successful login
            session["fingerprint"] = generate_session_fingerprint(request)

            add_log(db, user_email, "LOGIN_SUCCESS", request.remote_addr)

            if user_role == "admin":
                return redirect("/admin")
            elif user_role == "employer":
                return redirect("/employer")
            else:
                return redirect("/dashboard")

        add_log(db, session.get("temp_user", "unknown"), "OTP_FAILED", request.remote_addr)
        flash(f"Wrong OTP. {max_attempts - attempts} attempt(s) remaining.")
        return redirect("/verify_otp")

    return render_template("verify_otp.html")


# =====================================================
# FORGOT PASSWORD
# =====================================================
@app.route("/forgot_password", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == "POST":
        email = sanitize_string(request.form.get("email", ""), 254).lower()
        user  = db.users.find_one({"email": email})

        if not user:
            time.sleep(0.5)   # Timing equalization — prevents user enumeration
            flash("If that email exists, an OTP has been sent.")
            return redirect("/forgot_password")

        otp = generate_otp()

        session["reset_email"]    = email
        # ✅ SHA-256 (3): Store reset OTP hash in session, never plaintext
        session["reset_otp"]      = hash_otp(otp)
        session["reset_expiry"]   = time.time() + 300
        session["reset_attempts"] = 0

        send_email(app, email, "Password Reset OTP",
                   f"Your OTP is {otp}. It expires in 5 minutes. Do not share it.")

        add_log(db, email, "PASSWORD_RESET_REQUESTED", request.remote_addr)
        flash("If that email exists, an OTP has been sent.")
        return redirect("/reset_password")

    return render_template("forgot_password.html")


# =====================================================
# RESET PASSWORD
# =====================================================
@app.route("/reset_password", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def reset_password():
    if request.method == "POST":
        otp      = sanitize_string(request.form.get("otp", ""), 10)
        password = request.form.get("password", "").strip()

        if time.time() > session.get("reset_expiry", 0):
            session.pop("reset_otp", None)
            flash("OTP has expired. Please request a new one.")
            return redirect("/forgot_password")

        attempts = session.get("reset_attempts", 0) + 1
        session["reset_attempts"] = attempts

        if attempts > 5:
            session.clear()
            flash("Too many wrong attempts. Please request a new OTP.")
            return redirect("/forgot_password")

        # ✅ SHA-256 (3): Compare hash of input against stored reset OTP hash
        if hash_otp(otp) != session.get("reset_otp"):
            flash("Wrong OTP")
            return redirect("/reset_password")

        if not strong_password(password):
            flash("Weak Password: needs 8+ chars, uppercase, lowercase, number, special char")
            return redirect("/reset_password")

        hashed = bcrypt.generate_password_hash(password).decode("utf-8")

        db.users.update_one(
            {"email": session["reset_email"]},
            {"$set": {"password": hashed, "failed_attempts": 0, "locked_until": 0}}
        )

        add_log(db, session["reset_email"], "PASSWORD_RESET", request.remote_addr)

        for key in ("reset_email", "reset_otp", "reset_expiry", "reset_attempts"):
            session.pop(key, None)

        flash("Password updated. Please log in.")
        return redirect("/login")

    return render_template("reset_password.html")


# =====================================================
# CHANGE PASSWORD
# =====================================================
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        current  = request.form.get("current_password", "").strip()
        new_pass = request.form.get("new_password", "").strip()

        user_doc = get_fresh_user(session["user"])

        if not bcrypt.check_password_hash(user_doc["password"], current):
            flash("Current password is incorrect.")
            return redirect("/change_password")

        if not strong_password(new_pass):
            flash("Weak Password: needs 8+ chars, uppercase, lowercase, number, special char")
            return redirect("/change_password")

        if current == new_pass:
            flash("New password must be different from your current password.")
            return redirect("/change_password")

        hashed = bcrypt.generate_password_hash(new_pass).decode("utf-8")
        db.users.update_one(
            {"email": session["user"]},
            {"$set": {"password": hashed, "must_change_pass": False}}
        )

        add_log(db, session["user"], "PASSWORD_CHANGED", request.remote_addr)
        flash("Password changed successfully.")

        role = session.get("role")
        if role == "admin":
            return redirect("/admin")
        elif role == "employer":
            return redirect("/employer")
        return redirect("/dashboard")

    return render_template("change_password.html")


# =====================================================
# SERVE RESUME — authenticated, role-gated
# ✅ SHA-256 (1): Integrity verified before serving file
# =====================================================
@app.route("/resume/<filename>")
def serve_resume(filename):
    if "user" not in session:
        abort(403)

    filename = secure_filename(filename)
    if not filename:
        abort(400)

    role = session.get("role")

    if role in ("admin", "employer"):
        if role == "employer":
            app_doc = db.applications.find_one({
                "employer_email": session["user"],
                "resume": filename
            })
            if not app_doc:
                abort(403)
        else:
            app_doc = db.applications.find_one({"resume": filename})

        # ✅ SHA-256 (1): Verify file integrity before serving
        if app_doc:
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            if not verify_file_integrity(filepath, app_doc.get("resume_sha256")):
                add_log(db, session["user"], f"FILE_INTEGRITY_FAIL:{filename}", request.remote_addr)
                send_admin_alert(
                    f"Resume integrity check FAILED for {filename}. "
                    f"File may have been tampered with."
                )
                abort(500)

        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    if role == "candidate":
        app_doc = db.applications.find_one({
            "user_email": session["user"],
            "resume": filename
        })
        if not app_doc:
            abort(403)

        # ✅ SHA-256 (1): Verify file integrity before serving
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if not verify_file_integrity(filepath, app_doc.get("resume_sha256")):
            add_log(db, session["user"], f"FILE_INTEGRITY_FAIL:{filename}", request.remote_addr)
            send_admin_alert(
                f"Resume integrity check FAILED for {filename}. "
                f"File may have been tampered with."
            )
            abort(500)

        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    abort(403)


# =====================================================
# CANDIDATE DASHBOARD
# =====================================================
@app.route("/dashboard")
@require_role("candidate")
def dashboard():
    applications = list(db.applications.find({"user_email": session["user"]}))

    for app_doc in applications:
        try:
            job = db.jobs.find_one({"_id": ObjectId(app_doc["job_id"])})
            app_doc["job_title"]   = job["title"]   if job else "Unknown"
            app_doc["job_company"] = job["company"]  if job else "Unknown"
        except Exception:
            app_doc["job_title"]   = "Unknown"
            app_doc["job_company"] = "Unknown"

    return render_template(
        "dashboard.html",
        name=session["name"],
        role=session["role"],
        applications=applications,
    )


# =====================================================
# JOBS
# =====================================================
@app.route("/jobs")
def jobs():
    if "user" not in session:
        return redirect("/login")

    role = session.get("role")

    if role == "candidate":
        jobs_list = list(db.jobs.find())
    elif role == "employer":
        jobs_list = list(db.jobs.find({"employer_email": session["user"]}))
    else:
        jobs_list = list(db.jobs.find())

    return render_template("jobs.html", jobs=jobs_list, role=role)


# =====================================================
# ADD JOB
# =====================================================
@app.route("/add_job", methods=["POST"])
@require_role("admin", "employer")
def add_job():
    title       = sanitize_string(request.form.get("title", ""), 200)
    description = sanitize_string(request.form.get("description", ""), 2000)
    salary      = sanitize_string(request.form.get("salary", ""), 50)

    if not title:
        flash("Job title is required")
        return redirect("/employer" if session.get("role") == "employer" else "/admin")

    user_doc = get_fresh_user(session["user"])
    company  = user_doc.get("company") or sanitize_string(request.form.get("company", ""), 200)

    if not company:
        flash("Company name is missing from your profile. Contact admin.")
        return redirect("/employer")

    db.jobs.insert_one({
        "title":          title,
        "company":        company,
        "salary":         salary,
        "description":    description,
        "employer_email": session["user"],
        "posted_at":      time.time(),
    })

    add_log(db, session["user"], "JOB_ADDED", request.remote_addr)
    flash("Job posted successfully.")
    return redirect("/employer" if session.get("role") == "employer" else "/admin")


# =====================================================
# APPLY FOR JOB
# ✅ SHA-256 (1): Resume hashed on upload and stored in DB
# =====================================================
@app.route("/apply/<job_id>", methods=["POST"])
@require_role("candidate")
def apply(job_id):
    try:
        job_oid = ObjectId(job_id)
    except Exception:
        abort(400)

    job = db.jobs.find_one({"_id": job_oid})
    if not job:
        abort(404)

    existing = db.applications.find_one({
        "user_email": session["user"],
        "job_id":     str(job_oid)
    })
    if existing:
        flash("You have already applied for this job.")
        return redirect("/jobs")

    file = request.files.get("resume")
    if not file or file.filename == "":
        flash("Please upload a resume")
        return redirect("/jobs")

    original_filename = secure_filename(file.filename)

    valid, reason = validate_file(file)
    if not valid:
        add_log(db, session["user"], "MALICIOUS_FILE_BLOCKED", request.remote_addr)
        send_admin_alert(
            f"Malicious file upload blocked for user {session['user']} "
            f"from IP {request.remote_addr}. Reason: {reason}"
        )
        flash(f"File rejected: {reason}")
        return redirect("/jobs")

    if is_malicious_file(original_filename):
        add_log(db, session["user"], "MALICIOUS_FILE_BLOCKED", request.remote_addr)
        send_admin_alert(
            f"Dangerous filename blocked for user {session['user']} "
            f"from IP {request.remote_addr}. Filename: {original_filename}"
        )
        flash("Dangerous file blocked.")
        return redirect("/jobs")

    unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
    file.save(filepath)

    # ✅ SHA-256 (1): Hash the saved resume for integrity verification
    file_hash = get_file_hash(filepath)

    db.applications.insert_one({
        "user_email":     session["user"],
        "user_name":      session["name"],
        "job_id":         str(job_oid),
        "job_title":      job["title"],
        "company":        job["company"],
        "employer_email": job["employer_email"],
        "resume":         unique_filename,
        "resume_sha256":  file_hash,          # ✅ stored for later integrity checks
        "status":         "Applied",
        "applied_at":     time.time(),
    })

    add_log(db, session["user"], "APPLICATION_SUBMITTED", request.remote_addr)
    flash("Application submitted successfully.")
    return redirect("/jobs")


# =====================================================
# EMPLOYER DASHBOARD
# =====================================================
@app.route("/employer")
@require_role("employer")
def employer_dashboard():
    user_doc = get_fresh_user(session["user"])
    company  = user_doc.get("company", "Unknown Company")

    my_jobs         = list(db.jobs.find({"employer_email": session["user"]}))
    my_applications = list(db.applications.find({"employer_email": session["user"]}))

    return render_template(
        "employer_dashboard.html",
        name=session["name"],
        company=company,
        jobs=my_jobs,
        applications=my_applications,
    )


# =====================================================
# EMPLOYER: SHORTLIST APPLICATION
# =====================================================
@app.route("/employer/shortlist/<app_id>")
@require_role("employer")
def employer_shortlist(app_id):
    try:
        oid = ObjectId(app_id)
    except Exception:
        abort(400)

    app_doc = db.applications.find_one({"_id": oid})
    if not app_doc or app_doc.get("employer_email") != session["user"]:
        abort(403)

    db.applications.update_one({"_id": oid}, {"$set": {"status": "Shortlisted"}})
    add_log(db, session["user"], "APPLICATION_SHORTLISTED", request.remote_addr)

    send_email(
        app,
        app_doc["user_email"],
        "Congratulations! You've Been Shortlisted",
        f"Dear {app_doc['user_name']},\n\n"
        f"Great news! You have been shortlisted for the position of "
        f"'{app_doc['job_title']}' at {app_doc['company']}.\n\n"
        f"The employer will be in touch with you shortly regarding next steps.\n\n"
        f"Best of luck!\n"
        f"Recruitment Portal Team"
    )

    flash("Application shortlisted and candidate notified by email.")
    return redirect("/employer")


# =====================================================
# EMPLOYER: REJECT APPLICATION
# =====================================================
@app.route("/employer/reject/<app_id>")
@require_role("employer")
def employer_reject(app_id):
    try:
        oid = ObjectId(app_id)
    except Exception:
        abort(400)

    app_doc = db.applications.find_one({"_id": oid})
    if not app_doc or app_doc.get("employer_email") != session["user"]:
        abort(403)

    db.applications.update_one({"_id": oid}, {"$set": {"status": "Rejected"}})
    add_log(db, session["user"], "APPLICATION_REJECTED", request.remote_addr)

    send_email(
        app,
        app_doc["user_email"],
        f"Your Application at {app_doc['company']}",
        f"Dear {app_doc['user_name']},\n\n"
        f"Thank you for applying for the position of '{app_doc['job_title']}' "
        f"at {app_doc['company']}.\n\n"
        f"After careful consideration, we regret to inform you that we will "
        f"not be moving forward with your application at this time.\n\n"
        f"We encourage you to apply for future openings that match your profile.\n\n"
        f"Best regards,\n"
        f"Recruitment Portal Team"
    )

    flash("Application rejected and candidate notified by email.")
    return redirect("/employer")


# =====================================================
# ADMIN PANEL
# =====================================================
@app.route("/admin")
@require_role("admin")
def admin():
    users        = list(db.users.find({}, {"password": 0}))
    jobs         = list(db.jobs.find())
    applications = list(db.applications.find())
    logs         = list(db.security_logs.find().sort("_id", DESCENDING).limit(50))

    total_users      = db.users.count_documents({})
    total_employers  = db.users.count_documents({"role": "employer"})
    total_candidates = db.users.count_documents({"role": "candidate"})
    failed_logins    = db.security_logs.count_documents({"action": "LOGIN_FAILED"})
    otp_failures     = db.security_logs.count_documents({"action": "OTP_FAILED"})
    blocked_files    = db.security_logs.count_documents({"action": "MALICIOUS_FILE_BLOCKED"})
    locked_accounts  = db.security_logs.count_documents({"action": "ACCOUNT_LOCKED"})
    total_apps       = db.applications.count_documents({})

    applied     = db.applications.count_documents({"status": "Applied"})
    shortlisted = db.applications.count_documents({"status": "Shortlisted"})
    rejected    = db.applications.count_documents({"status": "Rejected"})

    pipeline = [
        {"$match": {"action": "LOGIN_FAILED"}},
        {"$group": {"_id": "$ip", "count": {"$sum": 1}}},
        {"$match": {"count": {"$gte": 3}}},
        {"$sort":  {"count": -1}},
    ]
    suspicious_ips = list(db.security_logs.aggregate(pipeline))
    blocked_ips    = list(db.blocked_ips.find())

    # ✅ SHA-256 (2): Flag any tampered log entries for the admin panel
    for log in logs:
        log["integrity_ok"] = verify_log_integrity(log)

    return render_template(
        "admin.html",
        users=users,
        jobs=jobs,
        applications=applications,
        logs=logs,
        blocked_ips=blocked_ips,
        total_users=total_users,
        total_employers=total_employers,
        total_candidates=total_candidates,
        failed_logins=failed_logins,
        otp_failures=otp_failures,
        blocked_files=blocked_files,
        locked_accounts=locked_accounts,
        total_apps=total_apps,
        applied=applied,
        shortlisted=shortlisted,
        rejected=rejected,
        suspicious_ips=suspicious_ips,
    )


# =====================================================
# ADMIN: AUDIT LOG EXPORT
# ✅ SHA-256 (2): Integrity column added to CSV export
# =====================================================
@app.route("/admin/export_logs")
@require_role("admin")
def export_logs():
    logs = list(db.security_logs.find().sort("_id", DESCENDING).limit(1000))

    output = io.StringIO()
    writer = csv.writer(output)
    # ✅ SHA-256 (2): Added "integrity" column to catch tampered entries
    writer.writerow(["timestamp", "user", "action", "ip", "integrity"])

    for log in logs:
        ts = log.get("timestamp", "")
        if isinstance(ts, (int, float)):
            ts = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

        # ✅ SHA-256 (2): Verify each log entry and flag tampered ones
        integrity = "OK" if verify_log_integrity(log) else "TAMPERED"

        writer.writerow([
            ts,
            log.get("user", ""),
            log.get("action", ""),
            log.get("ip", ""),
            integrity,
        ])

    output.seek(0)
    add_log(db, session["user"], "AUDIT_LOG_EXPORTED", request.remote_addr)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_audit_log.csv"}
    )


# =====================================================
# ADMIN: CREATE EMPLOYER
# =====================================================
@app.route("/admin/create_employer", methods=["POST"])
@require_role("admin")
def create_employer():
    name    = sanitize_string(request.form.get("name", ""), 100)
    email   = sanitize_string(request.form.get("email", ""), 254).lower()
    company = sanitize_string(request.form.get("company", ""), 200)

    if not name or not email or not company:
        flash("Name, email, and company are all required.")
        return redirect("/admin")

    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        flash("Invalid email address for employer.")
        return redirect("/admin")

    if db.users.find_one({"email": email}):
        flash("An account with that email already exists.")
        return redirect("/admin")

    alphabet  = string.ascii_letters + string.digits + "!@#$%^&*"
    temp_pass = (
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.digits) +
        secrets.choice("!@#$%^&*") +
        "".join(secrets.choice(alphabet) for _ in range(12))
    )
    temp_list = list(temp_pass)
    secrets.SystemRandom().shuffle(temp_list)
    temp_pass = "".join(temp_list)

    hashed = bcrypt.generate_password_hash(temp_pass).decode("utf-8")

    db.users.insert_one({
        "name":             name,
        "email":            email,
        "password":         hashed,
        "role":             "employer",
        "company":          company,
        "failed_attempts":  0,
        "locked_until":     0,
        "created_by":       session["user"],
        "must_change_pass": True,
    })

    send_email(
        app, email,
        "Your Employer Account — Recruitment Portal",
        f"Hello {name},\n\n"
        f"An employer account has been created for you at Recruitment Portal.\n\n"
        f"Company: {company}\n"
        f"Email: {email}\n"
        f"Temporary Password: {temp_pass}\n\n"
        f"Please log in and change your password immediately. "
        f"You will not be able to access the portal until you do.\n\n"
        f"Do not share this email."
    )

    add_log(db, session["user"], f"EMPLOYER_CREATED:{email}", request.remote_addr)
    flash(f"Employer account created for {email}. Temporary password sent via email.")
    return redirect("/admin")


# =====================================================
# ADMIN: SHORTLIST APPLICATION
# =====================================================
@app.route("/admin/shortlist/<app_id>")
@require_role("admin")
def admin_shortlist(app_id):
    try:
        oid = ObjectId(app_id)
    except Exception:
        abort(400)

    app_doc = db.applications.find_one({"_id": oid})
    if not app_doc:
        abort(404)

    db.applications.update_one({"_id": oid}, {"$set": {"status": "Shortlisted"}})

    send_email(
        app,
        app_doc["user_email"],
        "Congratulations! You've Been Shortlisted",
        f"Dear {app_doc['user_name']},\n\n"
        f"You have been shortlisted for the position of "
        f"'{app_doc['job_title']}' at {app_doc['company']}.\n\n"
        f"The employer will be in touch with you shortly.\n\n"
        f"Best of luck!\n"
        f"Recruitment Portal Team"
    )

    add_log(db, session["user"], "ADMIN_APPLICATION_SHORTLISTED", request.remote_addr)
    flash("Application shortlisted and candidate notified.")
    return redirect("/admin#applications")


# =====================================================
# ADMIN: REJECT APPLICATION
# =====================================================
@app.route("/admin/reject/<app_id>")
@require_role("admin")
def admin_reject(app_id):
    try:
        oid = ObjectId(app_id)
    except Exception:
        abort(400)

    app_doc = db.applications.find_one({"_id": oid})
    if not app_doc:
        abort(404)

    db.applications.update_one({"_id": oid}, {"$set": {"status": "Rejected"}})

    send_email(
        app,
        app_doc["user_email"],
        f"Your Application at {app_doc['company']}",
        f"Dear {app_doc['user_name']},\n\n"
        f"Thank you for applying for '{app_doc['job_title']}' at {app_doc['company']}.\n\n"
        f"After careful review, we will not be moving forward with your application at this time.\n\n"
        f"We encourage you to apply for future openings.\n\n"
        f"Best regards,\n"
        f"Recruitment Portal Team"
    )

    add_log(db, session["user"], "ADMIN_APPLICATION_REJECTED", request.remote_addr)
    flash("Application rejected and candidate notified.")
    return redirect("/admin#applications")


# =====================================================
# ADMIN: UNBLOCK IP
# =====================================================
@app.route("/unblock_ip/<ip_id>")
@require_role("admin")
def unblock_ip(ip_id):
    try:
        oid = ObjectId(ip_id)
    except Exception:
        abort(400)

    ip_doc = db.blocked_ips.find_one({"_id": oid})
    if ip_doc:
        db.blocked_ips.delete_one({"_id": oid})
        add_log(db, session["user"], f"IP_UNBLOCKED:{ip_doc.get('ip', '?')}", request.remote_addr)

    return redirect("/admin")


# =====================================================
# ADMIN: DELETE USER
# =====================================================
@app.route("/admin/delete_user/<user_id>")
@require_role("admin")
def delete_user(user_id):
    try:
        oid = ObjectId(user_id)
    except Exception:
        abort(400)

    target = db.users.find_one({"_id": oid}, {"password": 0})
    if not target:
        abort(404)

    if target["email"] == session["user"]:
        flash("You cannot delete your own account.")
        return redirect("/admin")

    if target.get("role") == "admin":
        flash("Admin accounts cannot be deleted through the panel.")
        return redirect("/admin")

    db.users.delete_one({"_id": oid})
    add_log(db, session["user"], f"USER_DELETED:{target['email']}", request.remote_addr)
    flash(f"User {target['email']} deleted.")
    return redirect("/admin")


# =====================================================
# LOGOUT
# =====================================================
@app.route("/logout")
def logout():
    if "user" in session:
        add_log(db, session["user"], "LOGOUT", request.remote_addr)
    session.clear()
    return redirect("/login")


# =====================================================
# ERROR HANDLERS
# =====================================================
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("429.html"), 429

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# =====================================================
# RUN
# =====================================================
if __name__ == "__main__":
    with app.app_context():
        ensure_indexes()
        seed_admin()
    app.run(debug=False, use_reloader=False)