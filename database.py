import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent / "database" / "secure_login.db"
SCHEMA_PATH = Path(__file__).resolve().parent / "database" / "schema.sql"


class DatabaseError(RuntimeError):
    """Raised when a database operation cannot be completed."""


class DuplicateEmailError(DatabaseError):
    """Raised when an email address is already present in the users table."""


def get_db_connection(db_path: str | Path = DATABASE_PATH) -> sqlite3.Connection:
    """Open a SQLite connection and return rows that support named access."""
    try:
        connection = sqlite3.connect(str(db_path), timeout=5)
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error as exc:
        raise DatabaseError(f"Could not connect to SQLite database: {db_path}") from exc


def initialize_database(db_path: str | Path = DATABASE_PATH) -> None:
    """Create the database folder and apply the SQL schema."""
    path = Path(db_path)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        schema = SCHEMA_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise DatabaseError(f"Could not prepare the database at {path}.") from exc

    connection = get_db_connection(path)
    try:
        connection.executescript(schema)
        connection.commit()
    except sqlite3.Error as exc:
        connection.rollback()
        raise DatabaseError(f"Could not initialize the database at {path}.") from exc
    finally:
        connection.close()


def create_user(
    username: str,
    email: str,
    password_hash: str,
    db_path: str | Path = DATABASE_PATH,
) -> int:
    """Insert a user record and return its generated ID."""
    connection = get_db_connection(db_path)
    try:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash),
            )
            return cursor.lastrowid
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed: users.email" in str(exc):
            raise DuplicateEmailError("A user with this email already exists.") from exc
        raise DatabaseError("Could not insert the user record.") from exc
    except sqlite3.Error as exc:
        raise DatabaseError("Could not insert the user record.") from exc
    finally:
        connection.close()


def get_user_by_email(
    email: str,
    db_path: str | Path = DATABASE_PATH,
) -> dict[str, object] | None:
    """Return one user record by email, or None when no record matches."""
    connection = get_db_connection(db_path)
    try:
        row = connection.execute(
            """
            SELECT id, username, email, password_hash, created_at
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
        return dict(row) if row is not None else None
    except sqlite3.Error as exc:
        raise DatabaseError("Could not retrieve the user record.") from exc
    finally:
        connection.close()


def get_user_by_id(
    user_id: int,
    db_path: str | Path = DATABASE_PATH,
) -> dict[str, object] | None:
    """Return public account details by ID without selecting the password hash."""
    connection = get_db_connection(db_path)
    try:
        row = connection.execute(
            """
            SELECT id, username, email, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        return dict(row) if row is not None else None
    except sqlite3.Error as exc:
        raise DatabaseError("Could not retrieve the user record.") from exc
    finally:
        connection.close()