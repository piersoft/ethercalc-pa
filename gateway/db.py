"""Accesso SQLite, schema, audit e primitive di sicurezza condivise."""
import hashlib, hmac, os, secrets, sqlite3, string, time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

DB_PATH = os.environ.get("GW_DB", "/data/gateway.sqlite")
ETHERCALC_KEY = os.environ.get("ETHERCALC_KEY", "")
MIN_PW = 12
ph = PasswordHasher()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL DEFAULT '',
  pw_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1,
  must_change INTEGER NOT NULL DEFAULT 1, failed INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT);
CREATE TABLE IF NOT EXISTS sheets(
  id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL, public_export INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, username TEXT, ip TEXT,
  action TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS sheets_owner ON sheets(owner_id);
"""


def connect():
    con = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init():
    con = connect()
    con.executescript(SCHEMA)
    con.close()


def audit(con, username, ip, action, detail=""):
    con.execute("INSERT INTO audit(ts,username,ip,action,detail) VALUES(?,?,?,?,?)",
                (int(time.time()), username, ip, action, detail))


def hash_pw(pw):
    return ph.hash(pw)


def verify_pw(pw_hash, pw):
    try:
        return ph.verify(pw_hash, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def room_hmac(room):
    """Stesso calcolo di EtherCalc: HMAC-SHA256(key, room) in esadecimale."""
    return hmac.new(ETHERCALC_KEY.encode(), room.encode(), hashlib.sha256).hexdigest()


def new_sheet_id():
    alphabet = string.ascii_lowercase + string.digits
    return secrets.choice(string.ascii_lowercase) + "".join(secrets.choice(alphabet) for _ in range(15))
