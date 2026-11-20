# Secure Login System

A learning-focused authentication application built with Flask and SQLite. It
supports account registration, password-based sign-in, and a protected
dashboard, with server-side validation and security controls.

This project is intended for learning and local development. It has not been
independently audited and should not be deployed publicly without the production
configuration described below.

## Features

- User registration with server-side username, email, and password validation.
- Passwords hashed with bcrypt; plaintext passwords are not stored.
- CSRF protection for form submissions.
- Session-based authentication with a 30-minute session lifetime.
- Protected dashboard that displays the signed-in user's username and email.
- POST-only, CSRF-protected logout.
- Login rate limiting of five POST attempts per minute per IP address.
- Fixed dummy bcrypt verification for unknown email addresses to reduce
  account-enumeration timing differences.
- SQLite persistence with case-insensitive unique email addresses and
  parameterized database queries.

Two-factor authentication, email verification, password reset, and profile
management are not implemented.

## Technologies

- Python 3.14
- Flask
- SQLite
- bcrypt
- Flask-WTF
- Flask-Limiter
- HTML, CSS, and JavaScript

## Project structure

```text
.
├── app.py
├── config.py
├── database.py
├── security.py
├── requirements.txt
├── .env.example
├── .gitignore
├── database/
│   ├── schema.sql
│   └── secure_login.db       # Local database; ignored by Git
├── static/
│   ├── css/style.css
│   └── js/validation.js
├── templates/
│   ├── base.html
│   ├── csrf_error.html
│   ├── dashboard.html
│   ├── index.html
│   ├── login.html
│   └── register.html
├── tests/
│   ├── test_database.py
│   ├── test_login.py
│   └── test_registration.py
└── screenshots/               # Currently empty
```

The local virtual environment and Python cache directories are not part of the
shareable project.

## Windows setup

### Prerequisites

- Python 3.14 installed and available through the Windows Python launcher; this
  is the verified setup. Other Python versions should only be used if they are
  compatible with the pinned dependencies.
- PowerShell.

Open PowerShell and change to the project directory:

```powershell
cd "path\to\Secure Login web app"
```

Create and activate a virtual environment:

```powershell
py -3.14 -m venv venv
.\venv\Scripts\Activate.ps1
```

Install the pinned dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Environment configuration

The application reads these environment variables:

| Variable | Purpose | Local development |
| --- | --- | --- |
| `SECRET_KEY` | Signs Flask sessions and CSRF tokens; required at startup. | Set a randomly generated, private value. |
| `SESSION_COOKIE_SECURE` | Adds the Secure attribute to session cookies. | `false` for local HTTP; set `true` when served over HTTPS. |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter storage backend. | `memory://` for local development and tests only. |

For a local PowerShell session, generate a key and set the development values
before starting the application:

```powershell
$env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:SESSION_COOKIE_SECURE = "false"
$env:RATELIMIT_STORAGE_URI = "memory://"
```

The key is generated locally by the command; do not commit it or share it.
These environment-variable assignments apply to the current PowerShell
session. The application does **not** automatically load `.env` files.
`.env.example` is a reference template, not an automatically loaded
configuration file.

## Run locally

With the virtual environment active and environment variables set:

```powershell
python app.py
```

Open <http://127.0.0.1:5000/> in your browser. Running `app.py` directly
initializes the SQLite schema and starts Flask's development server with debug
mode enabled; use this only for local development.

## Run tests

```powershell
python -m unittest discover -s tests -v
```

The tests use temporary databases and cover database operations, registration,
login, sessions, CSRF, and login rate limiting. The current suite has 44
passing tests.

## Security notes and limitations

- Bcrypt hashes are used for stored passwords. Passwords longer than bcrypt's
  72-byte input limit are rejected during registration rather than truncated.
- Login failures use a generic message. A fixed dummy bcrypt hash is checked
  for unknown email addresses; this reduces the large timing difference from
  skipping bcrypt, but does not guarantee identical response times.
- Registration currently reports when an email address is already registered,
  which can reveal account existence.
- The default in-memory rate-limit store is not shared across worker processes
  and does not persist across restarts.
- The development server runs with debug mode enabled when started with
  `python app.py`.
- Session cookies are not marked Secure by default because local development
  uses HTTP.
- This project does not include 2FA, email verification, password reset, or
  profile management.

## Production deployment requirements

Before any production deployment:

1. Disable Flask debug mode and use a production-grade WSGI server.
2. Serve the application over HTTPS and set
   `SESSION_COOKIE_SECURE=true`.
3. Supply a strong, stable `SECRET_KEY` through the deployment environment or a
   secret manager. Do not commit it.
4. Configure shared rate-limit storage, such as Redis, and install the
   compatible Redis client required by that storage backend. Do not use
   `memory://` for a multi-worker production deployment.
5. Configure trusted proxy handling carefully if the application runs behind a
   reverse proxy, since login limits are keyed by IP address.

## Possible future improvements

- Add email verification and a secure password-reset flow.
- Add profile management and account settings.
- Add broader production deployment configuration and security-header tests.
- Expand abuse-prevention and deployment testing.

These are future ideas, not implemented features.