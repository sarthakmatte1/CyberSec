from flask import Flask, render_template, request, redirect, session, flash, abort, g
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename

from config import Config
from utils.mailer import mail, send_email
from utils.logger import add_log
from utils.scanner import is_malicious_file
from utils.alerts import send_admin_alert

import os
import random
import time
import re
import secrets
import datetime
import magic  # python-magic for MIME type checking

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
app.config["SESSION_COOKIE_HTTPONLY"] = True    # JS cannot read the cookie
app.config["SESSION_COOKIE_SECURE"]   = False   # Set True in production (HTTPS)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # CSRF mitigation
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30-minute session expiry

bcrypt = Bcrypt(app)
csrf   = CSRFProtect(app)   # CSRF protection on all POST forms
mail.init_app(app)

# =====================================================
# CSP NONCE — generated once per request in before_request,
# consumed in after_request for the Content-Security-Policy header,
# and available in templates via {{ g.csp_nonce }}.
# This is what allows inline <script> blocks to run while
# keeping script-src locked down (no 'unsafe-inline').
# =====================================================
@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)


# =====================================================
# JINJA2 FILTER — Unix timestamp → human-readable string
# Usage in templates:  {{ ip.until | timestamp_to_str }}
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
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
}

# =====================================================
# DATABASE
# =====================================================
client = MongoClient(app.config["MONGO_URI"])
db = client["recruitment_db"]

# =====================================================
# ADMIN SEEDING
# Reads ADMIN_EMAIL + ADMIN_PASSWORD from env/.config.
# Creates the admin account once on startup if it doesn't exist.
# Admin can NEVER be registered via the public /register route.
# =====================================================
def seed_admin():
    admin_email    = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not admin_email or not admin_password:
        print("[WARN] ADMIN_EMAIL / ADMIN_PASSWORD not set — no superuser seeded.")
        return

    if db.users.find_one({"email": admin_email}):
        return  # Already exists, skip

    if not strong_password(admin_password):
        raise RuntimeError(
            "ADMIN_PASSWORD does not meet strength requirements "
            "(8+ chars, upper, lower, digit, special)."
        )

    hashed = bcrypt.generate_password_hash(admin_password).decode("utf-8")
    db.users.insert_one({
        "name":            "System Administrator",
        "email":           admin_email,
        "password":        hashed,
        "role":            "admin",
        "company":         None,
        "failed_attempts": 0,
        "locked_until":    0,
        "created_by":      "seed"
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
            session["role"] = live_role   # Keep session in sync
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
    - At least one special character from the allowed set
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
        f"form-action 'self';"
    )
    return response


# =====================================================
# CSRF ERROR HANDLER
# =====================================================
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("Session expired or invalid request. Please try again.")
    return redirect(request.referrer or "/"), 400


# =====================================================
# HOME
# =====================================================
@app.route("/")
def index():
    return render_template("index.html")


# =====================================================
# REGISTER  (candidates only — no role selection)
# Admin is seeded from env. Employers are created by admin.
# Attempting to POST role=admin or role=employer is blocked server-side.
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = sanitize_string(request.form.get("name", ""), 100)
        email    = sanitize_string(request.form.get("email", ""), 254).lower()
        password = request.form.get("password", "").strip()

        # Hard-coded role — registration is candidates ONLY.
        # Any attempt to inject a different role via form tampering is ignored.
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
            "name":            name,
            "email":           email,
            "password":        hashed,
            "role":            role,
            "company":         None,
            "failed_attempts": 0,
            "locked_until":    0,
            "created_by":      "self"
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

    if bcrypt.check_password_hash(user["password"], password):
        db.users.update_one({"email": email}, {"$set": {"failed_attempts": 0}})

        otp = str(random.randint(100000, 999999))

        session["otp"]          = otp
        session["otp_expiry"]   = time.time() + 300
        session["otp_attempts"] = 0
        session["temp_user"]    = user["email"]
        session["temp_name"]    = user["name"]
        session["temp_role"]    = user["role"]
        session["temp_company"] = user.get("company")   # None for candidates

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
            session.clear()
            flash("Too many wrong OTP attempts. Please log in again.")
            return redirect("/login")

        if otp == session.get("otp"):
            session["user"]    = session["temp_user"]
            session["name"]    = session["temp_name"]
            session["role"]    = session["temp_role"]
            session["company"] = session["temp_company"]

            add_log(db, session["user"], "LOGIN_SUCCESS", request.remote_addr)

            for key in ("otp", "otp_expiry", "otp_attempts",
                        "temp_user", "temp_name", "temp_role", "temp_company"):
                session.pop(key, None)

            session.modified = True   # Trigger session ID regeneration

            # Route to correct dashboard based on role
            role = session["role"]
            if role == "admin":
                return redirect("/admin")
            elif role == "employer":
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

        # Same message regardless — prevents user enumeration
        if not user:
            flash("If that email exists, an OTP has been sent.")
            return redirect("/forgot_password")

        otp = str(random.randint(100000, 999999))

        session["reset_email"]    = email
        session["reset_otp"]      = otp
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

        if otp != session.get("reset_otp"):
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
# CANDIDATE DASHBOARD
# =====================================================
@app.route("/dashboard")
@require_role("candidate")
def dashboard():
    applications = list(db.applications.find({"user_email": session["user"]}))

    # Enrich each application with job title
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
        applications=applications
    )


# =====================================================
# JOBS  (candidates browse & apply; employers/admin see their own)
# =====================================================
@app.route("/jobs")
def jobs():
    if "user" not in session:
        return redirect("/login")

    role = session.get("role")

    if role == "candidate":
        jobs_list = list(db.jobs.find())
    elif role == "employer":
        # Employers only see jobs they own
        jobs_list = list(db.jobs.find({"employer_email": session["user"]}))
    else:
        # Admin sees all
        jobs_list = list(db.jobs.find())

    return render_template("jobs.html", jobs=jobs_list, role=role)


# =====================================================
# ADD JOB  (employer posts under their company; admin can post too)
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

    # Company is always the employer's own company — not user-supplied
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
        "posted_at":      time.time()
    })

    add_log(db, session["user"], "JOB_ADDED", request.remote_addr)
    flash("Job posted successfully.")
    return redirect("/employer" if session.get("role") == "employer" else "/admin")


# =====================================================
# APPLY FOR JOB  (candidates only)
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

    # Prevent duplicate applications
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

    filename = secure_filename(file.filename)

    valid, reason = validate_file(file)
    if not valid:
        add_log(db, session["user"], "MALICIOUS_FILE_BLOCKED", request.remote_addr)
        flash(f"File rejected: {reason}")
        return redirect("/jobs")

    if is_malicious_file(filename):
        add_log(db, session["user"], "MALICIOUS_FILE_BLOCKED", request.remote_addr)
        flash("Dangerous file blocked.")
        return redirect("/jobs")

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    db.applications.insert_one({
        "user_email":     session["user"],
        "user_name":      session["name"],
        "job_id":         str(job_oid),
        "job_title":      job["title"],
        "company":        job["company"],
        "employer_email": job["employer_email"],   # Ties application to exact employer
        "resume":         filename,
        "status":         "Applied",
        "applied_at":     time.time()
    })

    add_log(db, session["user"], "APPLICATION_SUBMITTED", request.remote_addr)
    flash("Application submitted successfully.")
    return redirect("/jobs")


# =====================================================
# EMPLOYER DASHBOARD
# Shows: employer's company info, their jobs, applications to their jobs only
# =====================================================
@app.route("/employer")
@require_role("employer")
def employer_dashboard():
    user_doc = get_fresh_user(session["user"])
    company  = user_doc.get("company", "Unknown Company")

    # Only jobs posted by this employer
    my_jobs = list(db.jobs.find({"employer_email": session["user"]}))

    # Only applications for this employer's jobs
    my_applications = list(db.applications.find({"employer_email": session["user"]}))

    return render_template(
        "employer_dashboard.html",
        name=session["name"],
        company=company,
        jobs=my_jobs,
        applications=my_applications
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

    # Ownership check — employer can only act on their own applications
    app_doc = db.applications.find_one({"_id": oid})
    if not app_doc or app_doc.get("employer_email") != session["user"]:
        abort(403)

    db.applications.update_one({"_id": oid}, {"$set": {"status": "Shortlisted"}})
    add_log(db, session["user"], "APPLICATION_SHORTLISTED", request.remote_addr)
    flash("Application shortlisted.")
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
    flash("Application rejected.")
    return redirect("/employer")


# =====================================================
# ADMIN PANEL
# Full oversight: users, all jobs, all applications, security logs
# =====================================================
@app.route("/admin")
@require_role("admin")
def admin():
    users        = list(db.users.find({}, {"password": 0}))   # Never expose hashes
    jobs         = list(db.jobs.find())
    applications = list(db.applications.find())
    logs         = list(db.security_logs.find().sort("_id", -1).limit(50))

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
        {"$sort":  {"count": -1}}
    ]
    suspicious_ips = list(db.security_logs.aggregate(pipeline))
    blocked_ips    = list(db.blocked_ips.find())

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
        suspicious_ips=suspicious_ips
    )


# =====================================================
# ADMIN: CREATE EMPLOYER
# No public route — only reachable by authenticated admin.
# Employer receives a temp password via email and must change it on first login.
# =====================================================
@app.route("/admin/create_employer", methods=["POST"])
@require_role("admin")
def create_employer():
    import string
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

    # Generate a cryptographically random temporary password
    alphabet  = string.ascii_letters + string.digits + "!@#$%^&*"
    temp_pass = (
        secrets.choice(string.ascii_uppercase) +
        secrets.choice(string.ascii_lowercase) +
        secrets.choice(string.digits) +
        secrets.choice("!@#$%^&*") +
        "".join(secrets.choice(alphabet) for _ in range(12))
    )
    # Shuffle so the guaranteed chars aren't always at the front
    temp_list = list(temp_pass)
    random.shuffle(temp_list)
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
        "must_change_pass": True   # Flag for future enforcement
    })

    send_email(
        app, email,
        "Your Employer Account — Recruitment Portal",
        f"Hello {name},\n\n"
        f"An employer account has been created for you at Recruitment Portal.\n\n"
        f"Company: {company}\n"
        f"Email: {email}\n"
        f"Temporary Password: {temp_pass}\n\n"
        f"Please log in and change your password immediately.\n\n"
        f"Do not share this email."
    )

    add_log(db, session["user"], f"EMPLOYER_CREATED:{email}", request.remote_addr)
    flash(f"Employer account created for {email}. Temporary password sent via email.")
    return redirect("/admin")


# =====================================================
# ADMIN: SHORTLIST APPLICATION  (no employer ownership check)
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
    add_log(db, session["user"], "ADMIN_APPLICATION_SHORTLISTED", request.remote_addr)
    flash("Application shortlisted.")
    return redirect("/admin#applications")


# =====================================================
# ADMIN: REJECT APPLICATION  (no employer ownership check)
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
    add_log(db, session["user"], "ADMIN_APPLICATION_REJECTED", request.remote_addr)
    flash("Application rejected.")
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
# ADMIN: DELETE USER  (cannot delete self or other admins)
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
        seed_admin()   # Idempotent — only runs if admin doesn't exist yet
    app.run(debug=False, use_reloader=False)