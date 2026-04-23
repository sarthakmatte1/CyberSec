````md id="u6w4rx"
# Secure Recruitment Portal

A Flask-based secure recruitment portal with advanced cybersecurity features, role-based access control, job posting, candidate applications, admin monitoring, and threat protection.

---

# Features

## Authentication & Access Control

- User Registration
- Secure Login
- OTP Email Verification
- Forgot Password via OTP
- Role-Based Access Control
  - Admin
  - Employer
  - Candidate

## Security Features

- Strong Password Enforcement
- CAPTCHA Protection
- Rate Limiting
- Auto IP Blacklisting
- Account Lockout after failed attempts
- CSRF Protection
- Secure Sessions
- Security Headers
- Content Security Policy (CSP)
- HTTPOnly Cookies
- Secure Cookies
- SameSite Cookies

## File Upload Security

- Resume Upload
- Allowed Extensions Validation
- MIME Type Verification
- Malicious File Detection

## Admin Dashboard

- Total Users
- Total Applications
- Failed Logins
- OTP Failures
- Locked Accounts
- Blocked Files
- Suspicious IP Detection
- Blocked IP Management
- Shortlist / Reject Candidates

## Error Handling

- Custom 403 Page
- Custom 404 Page
- Custom 429 Page
- Blocked Access Page

---

# Tech Stack

- Python
- Flask
- MongoDB
- Flask-Mail
- Flask-Bcrypt
- Flask-Limiter
- Flask-WTF
- HTML / CSS / JavaScript

---

# Project Structure

```text
secure-recruitment-portal/
│── app.py
│── config.py
│── .env
│── requirements.txt
│── templates/
│── static/
│── uploads/
│── utils/
````

---

# Installation

## 1. Clone Repository

```bash
git clone <your-repo-url>
cd secure-recruitment-portal
```

## 2. Create Virtual Environment

```bash
python -m venv venv
```

## 3. Activate Environment

### Windows

```bash
venv\Scripts\activate
```

### Linux / Mac

```bash
source venv/bin/activate
```

## 4. Install Dependencies

```bash
pip install -r requirements.txt
```

## 5. Create `.env`

Copy:

```bash
.envexample
```

to:

```bash
.env
```

Fill your real credentials.

## 6. Run App

```bash
python app.py
```

---

# Default Roles

## Candidate

* Register
* Login
* Apply for Jobs
* Upload Resume

## Employer

* Add Jobs
* Manage Jobs

## Admin

* Monitor Users
* Security Dashboard
* View Threat Logs
* Unblock IPs
* Shortlist / Reject Applications

---

# Security Highlights

* Prevents brute-force login attacks
* Detects suspicious IP activity
* Blocks repeated attackers
* Protects forms with CSRF token
* Uses OTP verification for login
* Validates uploaded resumes

---

# Environment Variables

See:

```text
.envexample
```

---

# Screenshots

Add your screenshots here.

---

# Future Improvements

* Two-Factor Authenticator App
* SIEM Dashboard
* PDF Security Reports
* Device Login History
* JWT API Version
* Docker Deployment

---

# Author

Nirmal Chaturvedi

---

# License

For academic and educational use.

```
```
