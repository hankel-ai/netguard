import aiosqlite
from app.config import settings

_db: aiosqlite.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL UNIQUE COLLATE NOCASE,
    ip TEXT,
    hostname TEXT,
    description TEXT,
    is_blocking INTEGER NOT NULL DEFAULT 0,
    override TEXT NOT NULL DEFAULT 'none',
    last_seen TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS schedule_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    day_of_week TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    action TEXT NOT NULL,
    source TEXT NOT NULL,
    target_id INTEGER
);

CREATE TABLE IF NOT EXISTS lan_devices (
    mac TEXT PRIMARY KEY COLLATE NOCASE,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    last_seen TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

MIGRATIONS = [
    "ALTER TABLE targets ADD COLUMN description TEXT",
    "ALTER TABLE lan_devices ADD COLUMN vendor TEXT",
    "ALTER TABLE lan_devices ADD COLUMN device_type TEXT",
    "ALTER TABLE targets ADD COLUMN is_monitoring INTEGER NOT NULL DEFAULT 0",
]


async def get_db() -> aiosqlite.Connection:
    global _db
    if _db is None:
        _db = await aiosqlite.connect(settings.db_path)
        _db.row_factory = aiosqlite.Row
        await _db.execute("PRAGMA foreign_keys = ON")
        await _db.executescript(SCHEMA)
        # Run migrations (ignore errors for already-applied)
        for sql in MIGRATIONS:
            try:
                await _db.execute(sql)
            except Exception:
                pass
        await _db.commit()
    return _db


async def close_db():
    global _db
    if _db is not None:
        await _db.close()
        _db = None


# --- Targets ---

async def get_all_targets() -> list[dict]:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM targets ORDER BY id")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_target(target_id: int) -> dict | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM targets WHERE id = ?", (target_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def get_target_by_mac(mac: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM targets WHERE mac = ? COLLATE NOCASE", (mac,))
    row = await cursor.fetchone()
    return dict(row) if row else None


async def add_target(mac: str, ip: str | None = None, hostname: str | None = None) -> int:
    db = await get_db()
    cursor = await db.execute(
        "INSERT INTO targets (mac, ip, hostname) VALUES (?, ?, ?)",
        (mac.lower(), ip, hostname),
    )
    await db.commit()
    return cursor.lastrowid


async def remove_target(target_id: int):
    db = await get_db()
    await db.execute("DELETE FROM targets WHERE id = ?", (target_id,))
    await db.commit()


async def update_target(target_id: int, **fields):
    db = await get_db()
    if not fields:
        return
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [target_id]
    await db.execute(f"UPDATE targets SET {set_clause} WHERE id = ?", values)
    await db.commit()


# --- Schedules ---

async def get_schedules_for_target(target_id: int) -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM schedule_rules WHERE target_id = ? ORDER BY id",
        (target_id,),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_schedule(rule_id: int) -> dict | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM schedule_rules WHERE id = ?", (rule_id,))
    row = await cursor.fetchone()
    return dict(row) if row else None


# --- Audit Log ---

async def add_log(action: str, source: str, target_id: int | None = None):
    db = await get_db()
    await db.execute(
        "INSERT INTO audit_log (action, source, target_id) VALUES (?, ?, ?)",
        (action, source, target_id),
    )
    await db.commit()


# --- LAN Device Cache ---

async def upsert_lan_device(mac: str, ip: str | None, hostname: str | None,
                            vendor: str | None = None, device_type: str | None = None):
    db = await get_db()
    await db.execute(
        "INSERT INTO lan_devices (mac, ip, hostname, vendor, device_type, last_seen) "
        "VALUES (?, ?, ?, ?, ?, datetime('now')) "
        "ON CONFLICT(mac) DO UPDATE SET "
        "ip = COALESCE(excluded.ip, lan_devices.ip), "
        "hostname = COALESCE(excluded.hostname, lan_devices.hostname), "
        "vendor = COALESCE(excluded.vendor, lan_devices.vendor), "
        "device_type = COALESCE(excluded.device_type, lan_devices.device_type), "
        "last_seen = datetime('now')",
        (mac.lower(), ip, hostname, vendor, device_type),
    )
    await db.commit()


async def get_all_lan_devices() -> list[dict]:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM lan_devices ORDER BY hostname IS NULL, ip")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def get_lan_device_by_mac(mac: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute("SELECT * FROM lan_devices WHERE mac = ? COLLATE NOCASE", (mac,))
    row = await cursor.fetchone()
    return dict(row) if row else None
