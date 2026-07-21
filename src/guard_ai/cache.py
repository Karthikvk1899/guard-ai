import sqlite3
import time
from pathlib import Path
from typing import Optional

class PackageCache:
    """SQLite cache engine for package availability lookups (PyPI & NPM)."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            cache_dir = Path.home() / ".guard_ai"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = cache_dir / "cache.db"

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the cache database schema."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS package_cache (
                    registry TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    is_exists INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    PRIMARY KEY (registry, package_name)
                )
            """)
            conn.commit()

    def get(self, registry: str, package_name: str, max_age_seconds: float = 86400) -> Optional[bool]:
        """
        Check if package status is cached and not expired (default TTL: 24 hrs).
        """
        pkg_key = package_name.lower()
        reg_key = registry.lower()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT is_exists, timestamp FROM package_cache WHERE registry = ? AND package_name = ?",
                (reg_key, pkg_key)
            )
            row = cursor.fetchone()
            if not row:
                return None

            is_exists, timestamp = row
            if time.time() - timestamp > max_age_seconds:
                return None

            return bool(is_exists)

    def set(self, registry: str, package_name: str, exists: bool):
        """Save or update package lookup result in SQLite."""
        pkg_key = package_name.lower()
        reg_key = registry.lower()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO package_cache (registry, package_name, is_exists, timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (reg_key, pkg_key, int(exists), time.time())
            )
            conn.commit()
