"""Users, sessions and favorites in SQLite (standard library only)."""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PBKDF2_ITERATIONS = 600_000        # OWASP guidance for PBKDF2-HMAC-SHA256
MIN_PASSWORD = 10
MAX_PASSWORD = 256
MAX_FAVORITES = 5000               # per user
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pw TEXT NOT NULL,
    created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    added TEXT NOT NULL,
    PRIMARY KEY (user_id, url)
);
CREATE TABLE IF NOT EXISTS state (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    last_read TEXT
);
"""


class UserExists(ValueError):
    pass


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(calc, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def valid_username(name: str) -> bool:
    return bool(USERNAME_RE.match(name or ""))


def password_problem(password: str) -> Optional[str]:
    if len(password) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(password) > MAX_PASSWORD:
        return f"Password must be at most {MAX_PASSWORD} characters."
    return None


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Equalises login timing for unknown usernames.
        self._dummy = hash_password("not-a-real-password")
        with self._conn() as c:
            c.executescript(SCHEMA)
            c.execute("PRAGMA journal_mode=WAL")

    @contextlib.contextmanager
    def _conn(self):
        c = sqlite3.connect(self.path, timeout=10)
        c.execute("PRAGMA foreign_keys=ON")
        try:
            with c:                      # commit or roll back
                yield c
        finally:
            c.close()

    # ---- users
    def add_user(self, name: str, password: str) -> None:
        if not valid_username(name):
            raise ValueError("Username must be 3-32 characters: letters, digits, '.', '_' or '-'.")
        problem = password_problem(password)
        if problem:
            raise ValueError(problem)
        try:
            with self._conn() as c:
                c.execute("INSERT INTO users (name, pw, created) VALUES (?,?,?)",
                          (name, hash_password(password), datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            raise UserExists(f"User '{name}' already exists.") from None

    def set_password(self, name: str, password: str) -> None:
        problem = password_problem(password)
        if problem:
            raise ValueError(problem)
        with self._conn() as c:
            row = c.execute("SELECT id FROM users WHERE name=?", (name,)).fetchone()
            if not row:
                raise ValueError(f"No such user '{name}'.")
            c.execute("UPDATE users SET pw=? WHERE id=?", (hash_password(password), row[0]))
            c.execute("DELETE FROM sessions WHERE user_id=?", (row[0],))     # sign the user out everywhere

    def delete_user(self, name: str) -> None:
        with self._conn() as c:
            if c.execute("DELETE FROM users WHERE name=?", (name,)).rowcount == 0:
                raise ValueError(f"No such user '{name}'.")

    def list_users(self) -> list:
        with self._conn() as c:
            return c.execute("SELECT name, created, (SELECT COUNT(*) FROM favorites f WHERE f.user_id=u.id) "
                             "FROM users u ORDER BY name").fetchall()

    def user_count(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def verify(self, name: str, password: str) -> Optional[tuple]:
        """Return (id, name) for valid credentials, else None. Takes the same time either way."""
        with self._conn() as c:
            row = c.execute("SELECT id, name, pw FROM users WHERE name=?", (name,)).fetchone()
        ok = check_password(password, row[2] if row else self._dummy)
        return (row[0], row[1]) if row and ok else None

    # ---- sessions (only a hash of the token is stored)
    def create_session(self, user_id: int, seconds: int) -> str:
        token = secrets.token_urlsafe(32)
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))
            c.execute("INSERT INTO sessions (token_hash, user_id, expires) VALUES (?,?,?)",
                      (token_hash(token), user_id, int(time.time()) + seconds))
        return token

    def session_user(self, token: str) -> Optional[tuple]:
        if not token:
            return None
        with self._conn() as c:
            return c.execute("SELECT u.id, u.name FROM sessions s JOIN users u ON u.id = s.user_id "
                             "WHERE s.token_hash=? AND s.expires > ?", (token_hash(token), int(time.time()))).fetchone()

    def delete_session(self, token: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(token),))

    # ---- favorites and read marker
    def favorites(self, user_id: int) -> list:
        with self._conn() as c:
            return [r[0] for r in c.execute("SELECT url FROM favorites WHERE user_id=? ORDER BY added DESC", (user_id,))]

    def set_favorite(self, user_id: int, url: str, on: bool) -> bool:
        """Returns False if adding would exceed the per-user limit."""
        with self._conn() as c:
            if not on:
                c.execute("DELETE FROM favorites WHERE user_id=? AND url=?", (user_id, url))
                return True
            n = c.execute("SELECT COUNT(*) FROM favorites WHERE user_id=?", (user_id,)).fetchone()[0]
            if n >= MAX_FAVORITES:
                return False
            c.execute("INSERT OR IGNORE INTO favorites (user_id, url, added) VALUES (?,?,?)",
                      (user_id, url, datetime.now(timezone.utc).isoformat()))
            return True

    def last_read(self, user_id: int) -> Optional[str]:
        with self._conn() as c:
            row = c.execute("SELECT last_read FROM state WHERE user_id=?", (user_id,)).fetchone()
        return row[0] if row else None

    def set_last_read(self, user_id: int, value: str) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO state (user_id, last_read) VALUES (?,?) "
                      "ON CONFLICT(user_id) DO UPDATE SET last_read=excluded.last_read", (user_id, value))
