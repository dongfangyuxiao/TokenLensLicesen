import hashlib
import json
import os
import binascii
import sqlite3
from datetime import datetime

DB_PATH = os.getenv('DB_PATH', 'license_admin.db')


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_password(password: str, salt: str = None):
    if salt is None:
        salt = binascii.hexlify(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return binascii.hexlify(dk).decode(), salt


def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS admin_users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS license_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer TEXT NOT NULL,
            product TEXT NOT NULL DEFAULT '',
            machine_code TEXT NOT NULL DEFAULT '',
            expires_at TEXT DEFAULT '',
            features TEXT NOT NULL DEFAULT '[]',
            metadata TEXT NOT NULL DEFAULT '{}',
            license_token TEXT NOT NULL DEFAULT '',
            record_status TEXT NOT NULL DEFAULT 'active',
            remark TEXT DEFAULT '',
            created_by TEXT DEFAULT '',
            created_at TEXT,
            updated_at TEXT,
            download_count INTEGER NOT NULL DEFAULT 0,
            last_downloaded_at TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_license_records_status ON license_records(record_status);
        CREATE INDEX IF NOT EXISTS idx_license_records_customer ON license_records(customer);
        CREATE INDEX IF NOT EXISTS idx_license_records_machine_code ON license_records(machine_code);
        """)
        row = conn.execute("SELECT username FROM admin_users WHERE username='admin'").fetchone()
        if not row:
            pwd_hash, salt = _hash_password('admin123')
            conn.execute("INSERT INTO admin_users VALUES ('admin',?,?)", (pwd_hash, salt))
        conn.commit()


def verify_admin(username: str, password: str) -> bool:
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash,salt FROM admin_users WHERE username=?", (username,)).fetchone()
        if not row:
            return False
        password_hash, _ = _hash_password(password, row['salt'])
        return password_hash == row['password_hash']


def _decode_json_field(raw: str, default):
    try:
        return json.loads(raw or '')
    except Exception:
        return default


def _normalize_license_record(row):
    if not row:
        return None
    item = dict(row)
    item['features'] = _decode_json_field(item.get('features', '[]'), [])
    item['metadata'] = _decode_json_field(item.get('metadata', '{}'), {})
    effective_status = item.get('record_status') or 'active'
    expires_at = item.get('expires_at') or ''
    if effective_status == 'active' and expires_at:
        try:
            expires_dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if expires_dt <= datetime.now(expires_dt.tzinfo):
                effective_status = 'expired'
        except Exception:
            pass
    item['effective_status'] = effective_status
    return item


def create_license_record(customer: str, product: str, machine_code: str, expires_at: str,
                          features: list, metadata: dict, license_token: str, created_by: str = '', remark: str = ''):
    now = datetime.now().isoformat()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO license_records "
            "(customer,product,machine_code,expires_at,features,metadata,license_token,record_status,remark,created_by,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (customer, product, machine_code, expires_at, json.dumps(features or [], ensure_ascii=False), json.dumps(metadata or {}, ensure_ascii=False), license_token, 'active', remark, created_by, now, now)
        )
        conn.commit()
        return cur.lastrowid


def list_license_records(status: str = '', keyword: str = '', limit: int = 200):
    sql = "SELECT * FROM license_records WHERE 1=1"
    params = []
    if status in ('active', 'revoked'):
        sql += " AND record_status=?"
        params.append(status)
    if keyword:
        kw = f'%{keyword.strip()}%'
        sql += " AND (customer LIKE ? OR machine_code LIKE ? OR remark LIKE ?)"
        params.extend([kw, kw, kw])
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [_normalize_license_record(r) for r in rows]


def get_license_record(record_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM license_records WHERE id=?", (record_id,)).fetchone()
        return _normalize_license_record(row)


def update_license_record(record_id: int, record_status: str = '', remark: str = None):
    sets = []
    params = []
    if record_status in ('active', 'revoked'):
        sets.append("record_status=?")
        params.append(record_status)
    if remark is not None:
        sets.append("remark=?")
        params.append(remark)
    if not sets:
        return False
    sets.append("updated_at=?")
    params.append(datetime.now().isoformat())
    params.append(record_id)
    with get_conn() as conn:
        cur = conn.execute(f"UPDATE license_records SET {', '.join(sets)} WHERE id=?", params)
        conn.commit()
        return cur.rowcount > 0


def delete_license_record(record_id: int):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM license_records WHERE id=?", (record_id,))
        conn.commit()
        return cur.rowcount > 0


def mark_license_record_downloaded(record_id: int):
    now = datetime.now().isoformat()
    with get_conn() as conn:
        conn.execute("UPDATE license_records SET download_count=COALESCE(download_count,0)+1, last_downloaded_at=?, updated_at=? WHERE id=?", (now, now, record_id))
        conn.commit()


def get_license_record_summary():
    rows = list_license_records(limit=1000)
    return {
        'total_count': len(rows),
        'active_count': sum(1 for r in rows if r.get('effective_status') == 'active'),
        'revoked_count': sum(1 for r in rows if r.get('record_status') == 'revoked'),
        'expired_count': sum(1 for r in rows if r.get('effective_status') == 'expired'),
    }
