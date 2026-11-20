import os
import re
import secrets
import tempfile
import unittest
from pathlib import Path

import bcrypt

os.environ.setdefault("SECRET_KEY", secrets.token_hex(32))

from app import create_app
from database import create_user, get_user_by_email, initialize_database


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "registration.db"
        initialize_database(self.database_path)

        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": secrets.token_hex(32),
                "DATABASE_PATH": self.database_path,
                "WTF_CSRF_ENABLED": True,
            }
        )
        self.client = self.app.test_client()

    def csrf_token(self, client=None):
        client = client or self.client
        response = client.get("/register")
        self.assertEqual(response.status_code, 200)
        match = re.search(
            r'name="csrf_token" value="([^"]+)"',
            response.get_data(as_text=True),
        )
        self.assertIsNotNone(match)
        return match.group(1)

    def valid_form(self, client=None):
        unique_id = secrets.token_hex(8)
        return {
            "csrf_token": self.csrf_token(client),
            "username": f"user{unique_id}",
            "email": f"test-{unique_id}@example.test",
            "password": f"Aa1!{secrets.token_urlsafe(16)}",
            "confirm_password": "",
        }

    def add_password_confirmation(self, form):
        form["confirm_password"] = form["password"]
        return form

    def insert_existing_user(self, email):
        password = secrets.token_urlsafe(24).encode("utf-8")
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode("ascii")
        create_user(
            username=f"user{secrets.token_hex(5)}",
            email=email,
            password_hash=password_hash,
            db_path=self.database_path,
        )

    def test_registration_page_loads_with_csrf_token(self):
        response = self.client.get("/register")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('name="csrf_token"', page)
        self.assertIn('name="username"', page)
        self.assertIn('name="email"', page)
        self.assertIn('name="password"', page)
        self.assertIn('name="confirm_password"', page)
        self.assertIn("Register", page)
        self.assertIn('href="/"', page)

    def test_successful_registration(self):
        form = self.add_password_confirmation(self.valid_form())
        response = self.client.post(
            "/register",
            data=form,
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Your account was created successfully.",
            response.data,
        )
        self.assertIsNotNone(
            get_user_by_email(form["email"], db_path=self.database_path)
        )

    def test_empty_fields_are_rejected(self):
        response = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token(),
                "username": "",
                "email": "",
                "password": "",
                "confirm_password": "",
            },
        )

        self.assertEqual(response.status_code, 400)
        for message in (
            b"Username is required.",
            b"Email is required.",
            b"Password is required.",
            b"Please confirm your password.",
        ):
            self.assertIn(message, response.data)

    def test_invalid_username_is_rejected(self):
        form = self.add_password_confirmation(self.valid_form())
        form["username"] = "not valid!"

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Use 3", response.data)

    def test_invalid_email_is_rejected(self):
        form = self.add_password_confirmation(self.valid_form())
        form["email"] = "not-an-email"

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Enter a valid email address.", response.data)

    def test_weak_password_is_rejected(self):
        form = self.valid_form()
        form["password"] = "weakpass"
        form["confirm_password"] = form["password"]

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Use at least 8 characters", response.data)

    def test_password_mismatch_is_rejected(self):
        form = self.valid_form()
        form["confirm_password"] = "DifferentPassword9!"

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Passwords do not match.", response.data)

    def test_duplicate_email_is_rejected(self):
        form = self.add_password_confirmation(self.valid_form())
        self.insert_existing_user(form["email"])

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"An account with this email already exists.", response.data)

    def test_case_insensitive_duplicate_email_is_rejected(self):
        form = self.add_password_confirmation(self.valid_form())
        self.insert_existing_user(form["email"])
        form["email"] = form["email"].upper()

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"An account with this email already exists.", response.data)

    def test_password_is_stored_as_a_bcrypt_hash(self):
        form = self.add_password_confirmation(self.valid_form())
        password = form["password"]

        response = self.client.post(
            "/register",
            data=form,
            follow_redirects=True,
        )
        user = get_user_by_email(form["email"], db_path=self.database_path)

        self.assertIsNotNone(user)
        self.assertNotEqual(user["password_hash"], password)
        self.assertNotIn(user["password_hash"].encode("ascii"), response.data)
        self.assertTrue(
            bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("ascii"),
            )
        )

    def test_password_over_72_utf8_bytes_is_rejected(self):
        form = self.valid_form()
        form["password"] = f"Aa1!{'é' * 35}"
        form["confirm_password"] = form["password"]

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"must not exceed 72 UTF-8 bytes", response.data)

    def test_password_at_72_utf8_bytes_is_accepted(self):
        form = self.valid_form()
        form["password"] = f"Aa1!{'é' * 34}"
        form["confirm_password"] = form["password"]

        response = self.client.post(
            "/register",
            data=form,
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your account was created successfully.", response.data)

    def test_missing_csrf_token_is_rejected(self):
        response = self.client.post(
            "/register",
            data={
                "username": "temporaryuser",
                "email": "temporary@example.test",
                "password": "Aa1!temporary",
                "confirm_password": "Aa1!temporary",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"form could not be verified", response.data)

    def test_invalid_csrf_token_does_not_register_user(self):
        form = self.add_password_confirmation(self.valid_form())
        form["csrf_token"] = "invalid-token"

        response = self.client.post("/register", data=form)

        self.assertEqual(response.status_code, 400)
        self.assertIsNone(
            get_user_by_email(form["email"], db_path=self.database_path)
        )

    def test_database_errors_show_a_generic_message(self):
        broken_app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": secrets.token_hex(32),
                "DATABASE_PATH": Path(self.temporary_directory.name)
                / "missing"
                / "registration.db",
                "WTF_CSRF_ENABLED": True,
            }
        )
        broken_client = broken_app.test_client()
        form = self.add_password_confirmation(self.valid_form(broken_client))
        response = broken_client.post("/register", data=form)

        self.assertEqual(response.status_code, 503)
        self.assertIn(
            b"Registration is temporarily unavailable.",
            response.data,
        )
        self.assertNotIn(b"registration.db", response.data)

    def test_homepage_still_works(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Secure Login System | Home", response.data)


if __name__ == "__main__":
    unittest.main()
