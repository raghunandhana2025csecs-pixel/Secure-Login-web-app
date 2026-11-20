import bcrypt
from functools import wraps

from flask import (
    Flask,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect

from config import Config
from database import (
    DATABASE_PATH,
    DatabaseError,
    DuplicateEmailError,
    create_user,
    get_user_by_email,
    get_user_by_id,
    initialize_database,
)
from security import normalize_email, validate_registration


# A fixed bcrypt hash keeps unknown-account logins on a comparable verification path.
DUMMY_PASSWORD_HASH = (
    b"$2b$12$6G1.gbTYfK4T73/QY8Z7ce8rNB7Y3M3t4LZfEWLpuOcwLBdB00lkW"
)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")
        if not isinstance(user_id, int) or isinstance(user_id, bool):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError(
            "Set the SECRET_KEY environment variable before starting the application."
        )

    app.config.setdefault("DATABASE_PATH", DATABASE_PATH)
    CSRFProtect(app)
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[],
        storage_uri=app.config["RATELIMIT_STORAGE_URI"],
    )
    limiter.init_app(app)

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "GET":
            return render_template("register.html", errors={}, form_data={})

        username = request.form.get("username", "").strip()
        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        form_data = {"username": username, "email": email}
        errors = validate_registration(
            username,
            email,
            password,
            confirm_password,
        )

        if errors:
            return render_template(
                "register.html",
                errors=errors,
                form_data=form_data,
            ), 400

        try:
            if get_user_by_email(email, db_path=app.config["DATABASE_PATH"]):
                errors["email"] = "An account with this email already exists."
            else:
                password_hash = bcrypt.hashpw(
                    password.encode("utf-8"),
                    bcrypt.gensalt(),
                ).decode("ascii")
                create_user(
                    username,
                    email,
                    password_hash,
                    db_path=app.config["DATABASE_PATH"],
                )
        except DuplicateEmailError:
            errors["email"] = "An account with this email already exists."
        except DatabaseError:
            current_app.logger.error(
                "A database operation failed during account registration."
            )
            flash(
                "Registration is temporarily unavailable. Please try again later.",
                "error",
            )
            return render_template(
                "register.html",
                errors={},
                form_data=form_data,
            ), 503

        if errors:
            return render_template(
                "register.html",
                errors=errors,
                form_data=form_data,
            ), 400

        flash("Your account was created successfully.", "success")
        return redirect(url_for("register"))

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "GET":
            return render_template("login.html", email="")

        email = normalize_email(request.form.get("email", ""))
        password = request.form.get("password", "")

        try:
            password_bytes = password.encode("utf-8")
        except UnicodeEncodeError:
            password_bytes = b""

        user = None
        valid_password = False
        password_input_is_valid = bool(password_bytes) and len(password_bytes) <= 72
        if email:
            try:
                user = get_user_by_email(
                    email,
                    db_path=app.config["DATABASE_PATH"],
                )
            except DatabaseError:
                current_app.logger.error(
                    "A database operation failed during login."
                )
                flash(
                    "Login is temporarily unavailable. Please try again later.",
                    "error",
                )
                return render_template("login.html", email=email), 503

            try:
                password_hash = (
                    user["password_hash"].encode("ascii")
                    if user is not None
                    else DUMMY_PASSWORD_HASH
                )
                password_for_check = (
                    password_bytes if password_input_is_valid else b""
                )
                password_matches = bcrypt.checkpw(
                    password_for_check,
                    password_hash,
                )
                valid_password = (
                    user is not None
                    and password_input_is_valid
                    and password_matches
                )
            except (AttributeError, TypeError, UnicodeEncodeError, ValueError):
                valid_password = False

        if not valid_password:
            flash("Invalid email or password", "error")
            return render_template("login.html", email=email), 401

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        flash("You are now signed in.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        try:
            user = get_user_by_id(
                session["user_id"],
                db_path=app.config["DATABASE_PATH"],
            )
        except DatabaseError:
            current_app.logger.error(
                "A database operation failed while loading the dashboard."
            )
            return "Dashboard is temporarily unavailable.", 503

        if user is None:
            session.clear()
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))

        return render_template("dashboard.html", user=user)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):
        message = "The form could not be verified. Please reload it and try again."
        if request.endpoint == "register":
            flash(message, "error")
            return render_template("register.html", errors={}, form_data={}), 400
        if request.endpoint == "login":
            flash(message, "error")
            return render_template(
                "login.html",
                email=request.form.get("email", ""),
            ), 400
        return render_template("csrf_error.html"), 400

    @app.errorhandler(429)
    def handle_rate_limit(error):
        if request.endpoint == "login":
            flash(
                "Too many login attempts. Please wait a minute and try again.",
                "error",
            )
            return render_template(
                "login.html",
                email=request.form.get("email", ""),
            ), 429
        return "Too many requests. Please try again later.", 429

    return app


app = create_app()


if __name__ == "__main__":
    initialize_database(app.config["DATABASE_PATH"])
    app.run(debug=True)