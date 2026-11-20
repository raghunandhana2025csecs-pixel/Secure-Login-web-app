import secrets
import tempfile
import unittest
from pathlib import Path

import bcrypt

from database import (
    DatabaseError,
    DuplicateEmailError,
    create_user,
    get_db_connection,
    get_user_by_email,
    initialize_database,
)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.database_path = Path(self.temporary_directory.name) / "test_secure_login.db"
        initialize_database(self.database_path)

    def test_initialization_creates_users_table(self):
        self.assertTrue(self.database_path.is_file())

        connection = get_db_connection(self.database_path)
        try:
            columns = connection.execute("PRAGMA table_info(users)").fetchall()
        finally:
            connection.close()

        self.assertEqual(
            [column["name"] for column in columns],
            ["id", "username", "email", "password_hash", "created_at"],
        )

    def test_insert_retrieve_and_case_insensitive_duplicate_rejection(self):
        password = secrets.token_urlsafe(32).encode("utf-8")
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode("utf-8")
        email = f"test-{secrets.token_hex(8)}@example.test"

        user_id = create_user(
            username="temporary-test-user",
            email=email,
            password_hash=password_hash,
            db_path=self.database_path,
        )
        user = get_user_by_email(email.upper(), db_path=self.database_path)

        self.assertIsNotNone(user)
        self.assertEqual(user["id"], user_id)
        self.assertEqual(user["password_hash"], password_hash)
        self.assertTrue(
            bcrypt.checkpw(password, user["password_hash"].encode("utf-8"))
        )
        self.assertIsNone(
            get_user_by_email("missing@example.test", db_path=self.database_path)
        )

        with self.assertRaises(DuplicateEmailError):
            create_user(
                username="another-temporary-user",
                email=email.upper(),
                password_hash=password_hash,
                db_path=self.database_path,
            )

    def test_connection_errors_are_reported(self):
        invalid_path = Path(self.temporary_directory.name) / "missing" / "database.db"

        with self.assertRaises(DatabaseError):
            get_db_connection(invalid_path)

    def test_injection_shaped_username_is_stored_as_data(self):
        password = secrets.token_urlsafe(32).encode("utf-8")
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode("ascii")
        username = "admin'--"
        email = f"test-{secrets.token_hex(8)}@example.test"

        create_user(
            username=username,
            email=email,
            password_hash=password_hash,
            db_path=self.database_path,
        )

        user = get_user_by_email(email, db_path=self.database_path)
        connection = get_db_connection(self.database_path)
        try:
            user_count = connection.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertIsNotNone(user)
        self.assertEqual(user["username"], username)
        self.assertEqual(user_count, 1)


if __name__ == "__main__":
    unittest.main()
