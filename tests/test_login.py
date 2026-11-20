import os
import re
import secrets
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import bcrypt

os.environ.setdefault("SECRET_KEY", secrets.token_hex(32))

from app import create_app
from database import (
    create_user,
    get_db_connection,
    get_user_by_email,
    initialize_database,
)


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "login.db"
        initialize_database(self.database_path)

        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": secrets.token_hex(32),
                "DATABASE_PATH": self.database_path,
                "SESSION_COOKIE_SECURE": False,
                "WTF_CSRF_ENABLED": True,
                "RATELIMIT_STORAGE_URI": "memory://",
            }
        )
        self.client = self.app.test_client()

        unique_id = secrets.token_hex(8)
        self.email = f"member-{unique_id}@example.test"
        self.username = f"member{unique_id}"
        self.password = f"Aa1!{secrets.token_urlsafe(16)}"
        self.password_hash = bcrypt.hashpw(
            self.password.encode("utf-8"),
            bcrypt.gensalt(),
        ).decode("ascii")
        self.user_id = create_user(
            username=self.username,
            email=self.email,
            password_hash=self.password_hash,
            db_path=self.database_path,
        )

    def csrf_token(self, path="/login"):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            response.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def login_form(self, email=None, password=None):
        return {
            "csrf_token": self.csrf_token(),
            "email": self.email if email is None else email,
            "password": self.password if password is None else password,
        }

    def login(self):
        response = self.client.post("/login", data=self.login_form())
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")
        return response

    def test_login_page_loads_successfully(self):
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log in", response.data)
        self.assertIn(b'name="email"', response.data)
        self.assertIn(b'name="password"', response.data)

    def test_login_form_contains_csrf_token(self):
        response = self.client.get("/login")

        self.assertEqual(response.status_code, 200)
        self.assertRegex(
            response.get_data(as_text=True),
            r'name="csrf_token" value="[^"]+"',
        )

    def test_valid_login_succeeds(self):
        response = self.client.post(
            "/login",
            data=self.login_form(email=self.email.upper()),
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")
        with self.client.session_transaction() as stored_session:
            self.assertEqual(stored_session["user_id"], self.user_id)

    def test_incorrect_password_is_rejected(self):
        wrong_password = "WrongPassword9!"
        with patch("app.bcrypt.checkpw", wraps=bcrypt.checkpw) as check_password:
            response = self.client.post(
                "/login",
                data=self.login_form(password=wrong_password),
            )

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid email or password", response.data)
        check_password.assert_called_once_with(
            wrong_password.encode("utf-8"),
            self.password_hash.encode("ascii"),
        )
        with self.client.session_transaction() as stored_session:
            self.assertNotIn("user_id", stored_session)

    def test_unknown_email_is_rejected(self):
        with patch("app.bcrypt.checkpw", wraps=bcrypt.checkpw) as check_password:
            response = self.client.post(
                "/login",
                data=self.login_form(email="unknown@example.test"),
            )

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid email or password", response.data)
        check_password.assert_called_once()
        submitted_password, dummy_hash = check_password.call_args.args
        self.assertEqual(submitted_password, self.password.encode("utf-8"))
        self.assertNotEqual(dummy_hash, self.password_hash.encode("ascii"))
        self.assertFalse(bcrypt.checkpw(submitted_password, dummy_hash))
        dummy_rounds = int(dummy_hash.split(b"$")[2])
        account_rounds = int(self.password_hash.split("$")[2])
        self.assertEqual(dummy_rounds, account_rounds)
        with self.client.session_transaction() as stored_session:
            self.assertNotIn("user_id", stored_session)

    def test_unknown_email_and_wrong_password_use_the_same_error(self):
        wrong_password = self.client.post(
            "/login",
            data=self.login_form(password="WrongPassword9!"),
        )
        unknown_email = self.client.post(
            "/login",
            data=self.login_form(email="unknown@example.test"),
        )

        generic_message = b"Invalid email or password"
        self.assertEqual(wrong_password.status_code, unknown_email.status_code)
        self.assertIn(generic_message, wrong_password.data)
        self.assertIn(generic_message, unknown_email.data)
        self.assertNotIn(b"No account exists", unknown_email.data)
        with self.client.session_transaction() as stored_session:
            for key in ("user_id", "password", "password_hash"):
                self.assertNotIn(key, stored_session)

        user = get_user_by_email(self.email, db_path=self.database_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["password_hash"], self.password_hash)
        connection = get_db_connection(self.database_path)
        try:
            user_count = connection.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(user_count, 1)

    def test_sql_injection_shaped_login_inputs_do_not_authenticate_or_modify_users(self):
        injection_inputs = (
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin'--",
            "anything' OR 'x'='x",
        )

        for injection_input in injection_inputs:
            with self.subTest(email=injection_input):
                response = self.client.post(
                    "/login",
                    data=self.login_form(
                        email=injection_input,
                        password=self.password,
                    ),
                )

                self.assertEqual(response.status_code, 401)
                self.assertIn(b"Invalid email or password", response.data)
                with self.client.session_transaction() as stored_session:
                    self.assertNotIn("user_id", stored_session)

        user = get_user_by_email(self.email, db_path=self.database_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["id"], self.user_id)
        self.assertEqual(user["password_hash"], self.password_hash)
        connection = get_db_connection(self.database_path)
        try:
            user_count = connection.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(user_count, 1)

    def test_password_hash_is_not_exposed_in_any_html_response(self):
        self.login()
        pages = (
            ("/", 200),
            ("/register", 200),
            ("/login", 200),
            ("/dashboard", 200),
            ("/profile", 404),
        )

        for path, expected_status in pages:
            with self.subTest(path=path):
                response = self.client.get(path)

                self.assertEqual(response.status_code, expected_status)
                self.assertNotIn(self.password_hash.encode("ascii"), response.data)

    def test_login_rate_limit_returns_friendly_429_after_five_attempts(self):
        remote_address = "192.0.2.10"
        for _ in range(5):
            response = self.client.post(
                "/login",
                data=self.login_form(password="WrongPassword9!"),
                environ_overrides={"REMOTE_ADDR": remote_address},
            )
            self.assertEqual(response.status_code, 401)

        limited_response = self.client.post(
            "/login",
            data=self.login_form(password="WrongPassword9!"),
            environ_overrides={"REMOTE_ADDR": remote_address},
        )

        self.assertEqual(limited_response.status_code, 429)
        self.assertIn(
            b"Too many login attempts. Please wait a minute and try again.",
            limited_response.data,
        )
        self.assertEqual(self.client.get("/login").status_code, 200)

    def test_login_rate_limit_is_per_ip_not_per_account(self):
        limited_address = "192.0.2.20"
        for _ in range(5):
            response = self.client.post(
                "/login",
                data=self.login_form(password="WrongPassword9!"),
                environ_overrides={"REMOTE_ADDR": limited_address},
            )
            self.assertEqual(response.status_code, 401)

        response = self.client.post(
            "/login",
            data=self.login_form(),
            environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")

    def test_login_rate_limit_state_is_isolated_between_app_instances(self):
        for _ in range(5):
            response = self.client.post(
                "/login",
                data=self.login_form(password="WrongPassword9!"),
            )
            self.assertEqual(response.status_code, 401)

        second_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": secrets.token_hex(32),
                "DATABASE_PATH": self.database_path,
                "SESSION_COOKIE_SECURE": False,
                "WTF_CSRF_ENABLED": True,
                "RATELIMIT_STORAGE_URI": "memory://",
            }
        )
        second_client = second_app.test_client()
        token_response = second_client.get("/login")
        token = re.search(
            r'name="csrf_token" value="([^"]+)"',
            token_response.get_data(as_text=True),
        ).group(1)
        response = second_client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": self.email,
                "password": "WrongPassword9!",
            },
        )

        self.assertEqual(response.status_code, 401)

    def test_empty_credentials_are_rejected(self):
        response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "email": "",
                "password": "",
            },
        )

        self.assertEqual(response.status_code, 401)
        self.assertIn(b"Invalid email or password", response.data)

    def test_unauthenticated_dashboard_redirects_to_login(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_dashboard_clears_session_for_a_missing_user_record(self):
        with self.client.session_transaction() as stored_session:
            stored_session["user_id"] = 999999

        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")
        with self.client.session_transaction() as stored_session:
            self.assertNotIn("user_id", stored_session)

    def test_authenticated_dashboard_displays_user_information(self):
        self.login()
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(self.username.encode("ascii"), response.data)
        self.assertIn(self.email.encode("ascii"), response.data)

    def test_dashboard_never_displays_password_hash(self):
        self.login()
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.password_hash.encode("ascii"), response.data)
        self.assertNotIn(b"password_hash", response.data)

    def test_session_contains_only_user_id_as_authentication_data(self):
        with self.client.session_transaction() as stored_session:
            stored_session["stale_value"] = "remove me"

        self.login()
        with self.client.session_transaction() as stored_session:
            self.assertEqual(stored_session["user_id"], self.user_id)
            self.assertTrue(stored_session.permanent)
            for key in ("password", "password_hash", "email", "username", "stale_value"):
                self.assertNotIn(key, stored_session)

    def test_session_cookie_security_settings(self):
        response = self.client.post("/login", data=self.login_form())
        cookie = response.headers.get("Set-Cookie", "")

        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)
        self.assertIn("Expires=", cookie)
        self.assertEqual(
            self.app.config["PERMANENT_SESSION_LIFETIME"],
            timedelta(minutes=30),
        )

    def test_secure_cookie_can_be_enabled_for_https(self):
        secure_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": secrets.token_hex(32),
                "DATABASE_PATH": self.database_path,
                "SESSION_COOKIE_SECURE": True,
                "WTF_CSRF_ENABLED": True,
                "RATELIMIT_STORAGE_URI": "memory://",
            }
        )
        secure_client = secure_app.test_client()
        token_response = secure_client.get("/login")
        token = re.search(
            r'name="csrf_token" value="([^"]+)"',
            token_response.get_data(as_text=True),
        ).group(1)
        response = secure_client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": self.email,
                "password": self.password,
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertIn("Secure", response.headers.get("Set-Cookie", ""))

    def test_logout_works_with_post_and_clears_session(self):
        self.login()
        logout_token = self.csrf_token("/dashboard")

        response = self.client.post(
            "/logout",
            data={"csrf_token": logout_token},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        with self.client.session_transaction() as stored_session:
            self.assertEqual(dict(stored_session), {})

    def test_dashboard_is_unavailable_after_logout(self):
        self.login()
        logout_token = self.csrf_token("/dashboard")
        self.client.post("/logout", data={"csrf_token": logout_token})

        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_logout_rejects_get(self):
        response = self.client.get("/logout")

        self.assertEqual(response.status_code, 405)

    def test_login_rejects_missing_and_invalid_csrf_tokens(self):
        self.client.get("/login")
        missing_token = self.client.post(
            "/login",
            data={"email": self.email, "password": self.password},
        )
        invalid_token = self.client.post(
            "/login",
            data={
                "csrf_token": "invalid-token",
                "email": self.email,
                "password": self.password,
            },
        )

        self.assertEqual(missing_token.status_code, 400)
        self.assertEqual(invalid_token.status_code, 400)

    def test_logout_rejects_missing_and_invalid_csrf_tokens(self):
        self.login()
        missing_token = self.client.post("/logout", data={})
        invalid_token = self.client.post(
            "/logout",
            data={"csrf_token": "invalid-token"},
        )

        self.assertEqual(missing_token.status_code, 400)
        self.assertEqual(invalid_token.status_code, 400)


if __name__ == "__main__":
    unittest.main()
