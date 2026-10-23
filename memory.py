"""
NERO Memory — memory.py
SQLite-backed persistent storage for devices, threats, DNA,
evolution history, audit log, and code versions.
"""
import sqlite3, json, time, os, threading

DB_PATH = os.path.join(os.path.dirname(__file__), "nero.db")
_lock   = threading.Lock()

def _conn():
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

def init():
    with _lock:
        c = _conn()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            ip          TEXT PRIMARY KEY,
            mac         TEXT,
            name        TEXT,
            vendor      TEXT,
            os          TEXT,
            device_type TEXT,
            first_seen  REAL,
            last_seen   REAL,
            packets     INTEGER DEFAULT 0,
            trust_score INTEGER DEFAULT 50,
            blocked     INTEGER DEFAULT 0,
            notes       TEXT
        );
        CREATE TABLE IF NOT EXISTS dna_vectors (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ip      TEXT,
            ts      REAL,
            vector  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_dna_ip ON dna_vectors(ip);
        CREATE TABLE IF NOT EXISTS threat_patterns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE,
            description TEXT,
            indicators  TEXT,
            seen_count  INTEGER DEFAULT 1,
            created_at  REAL,
            updated_at  REAL
        );
        CREATE TABLE IF NOT EXISTS alert_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        REAL,
            ip        TEXT,
            type      TEXT,
            severity  TEXT,
            message   TEXT,
            outcome   TEXT DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS evolution_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL,
            module      TEXT,
            change_type TEXT,
            description TEXT,
            diff        TEXT,
            applied     INTEGER DEFAULT 0,
            approved    INTEGER DEFAULT 0,
            rolled_back INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS code_versions (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        REAL,
            filename  TEXT,
            content   TEXT,
            reason    TEXT
        );
        CREATE TABLE IF NOT EXISTS config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        c.commit()
        c.close()
    print("[MEMORY] Database initialized")

# ── DEVICES ──────────────────────────────────────────────────────
def upsert_device(ip, **kwargs):
    with _lock:
        c = _conn()
        existing = c.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if existing:
            sets  = ", ".join(f"{k}=?" for k in kwargs)
            vals  = list(kwargs.values()) + [ip]
            c.execute(f"UPDATE devices SET {sets} WHERE ip=?", vals)
        else:
            kwargs["ip"] = ip
            cols = ", ".join(kwargs.keys())
            qs   = ", ".join("?" * len(kwargs))
            c.execute(f"INSERT INTO devices ({cols}) VALUES ({qs})", list(kwargs.values()))
        c.commit()
        c.close()

def get_device(ip):
    with _lock:
        c = _conn()
        row = c.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        c.close()
        return dict(row) if row else None

def get_all_devices():
    with _lock:
        c = _conn()
        rows = c.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
        c.close()
        return [dict(r) for r in rows]

# ── DNA ───────────────────────────────────────────────────────────
def save_dna(ip, vector):
    with _lock:
        c = _conn()
        c.execute("INSERT INTO dna_vectors (ip, ts, vector) VALUES (?,?,?)",
                  (ip, time.time(), json.dumps(vector)))
        # keep last 1000 per device
        c.execute("""DELETE FROM dna_vectors WHERE ip=? AND id NOT IN
                     (SELECT id FROM dna_vectors WHERE ip=? ORDER BY id DESC LIMIT 1000)""",
                  (ip, ip))
        c.commit()
        c.close()

def get_dna(ip, limit=500):
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT vector FROM dna_vectors WHERE ip=? ORDER BY id DESC LIMIT ?",
            (ip, limit)).fetchall()
        c.close()
        return [json.loads(r["vector"]) for r in rows]

# ── THREATS ───────────────────────────────────────────────────────
def save_threat(name, description, indicators):
    with _lock:
        c = _conn()
        now = time.time()
        c.execute("""INSERT INTO threat_patterns (name, description, indicators, created_at, updated_at)
                     VALUES (?,?,?,?,?)
                     ON CONFLICT(name) DO UPDATE SET
                     seen_count=seen_count+1, updated_at=?, indicators=?""",
                  (name, description, json.dumps(indicators), now, now, json.dumps(indicators)))
        c.commit()
        c.close()

def get_threats():
    with _lock:
        c = _conn()
        rows = c.execute("SELECT * FROM threat_patterns ORDER BY seen_count DESC").fetchall()
        c.close()
        return [dict(r) for r in rows]

# ── ALERTS ────────────────────────────────────────────────────────
def save_alert(ip, alert_type, severity, message):
    with _lock:
        c = _conn()
        c.execute("INSERT INTO alert_log (ts, ip, type, severity, message) VALUES (?,?,?,?,?)",
                  (time.time(), ip, alert_type, severity, message))
        c.commit()
        c.close()

def update_alert_outcome(alert_id, outcome):
    with _lock:
        c = _conn()
        c.execute("UPDATE alert_log SET outcome=? WHERE id=?", (outcome, alert_id))
        c.commit()
        c.close()

def get_alerts(limit=200):
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM alert_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        c.close()
        return [dict(r) for r in rows]

# ── EVOLUTION ─────────────────────────────────────────────────────
def save_evolution(module, change_type, description, diff=""):
    with _lock:
        c = _conn()
        c.execute("""INSERT INTO evolution_log (ts, module, change_type, description, diff)
                     VALUES (?,?,?,?,?)""",
                  (time.time(), module, change_type, description, diff))
        c.commit()
        c.close()

def approve_evolution(evo_id):
    with _lock:
        c = _conn()
        c.execute("UPDATE evolution_log SET approved=1 WHERE id=?", (evo_id,))
        c.commit()
        c.close()

def get_evolution_log(limit=50):
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM evolution_log ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
        c.close()
        return [dict(r) for r in rows]

# ── CODE VERSIONS ─────────────────────────────────────────────────
def save_code_version(filename, content, reason=""):
    with _lock:
        c = _conn()
        c.execute("INSERT INTO code_versions (ts, filename, content, reason) VALUES (?,?,?,?)",
                  (time.time(), filename, content, reason))
        c.commit()
        c.close()

def get_code_versions(filename, limit=10):
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM code_versions WHERE filename=? ORDER BY ts DESC LIMIT ?",
            (filename, limit)).fetchall()
        c.close()
        return [dict(r) for r in rows]

# ── CONFIG ────────────────────────────────────────────────────────
def set_config(key, value):
    with _lock:
        c = _conn()
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?,?)",
                  (key, json.dumps(value)))
        c.commit()
        c.close()

def get_config(key, default=None):
    with _lock:
        c = _conn()
        row = c.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        c.close()
        return json.loads(row["value"]) if row else default
