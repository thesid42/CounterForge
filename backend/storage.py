import json
import os
import sqlite3
import threading
from pathlib import Path


class Store:
    """Small single-user local store. All writes are serialized."""
    def __init__(self, path=None):
        path = path or str(Path(os.getenv("COUNTERFORGE_STATE_DIR", "data")) / "counterforge.sqlite")
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, value TEXT, PRIMARY KEY(kind,id))")
        self.db.commit()

    def put(self, kind, key, value):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO records VALUES (?,?,?)", (kind, key, json.dumps(value)))

    def get(self, kind, key):
        with self.lock:
            row = self.db.execute("SELECT value FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, kind):
        with self.lock:
            rows = self.db.execute("SELECT value FROM records WHERE kind=? ORDER BY rowid DESC", (kind,)).fetchall()
        return [json.loads(row[0]) for row in rows]
