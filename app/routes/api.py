from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from app.auth import require_auth, check_password, create_session_cookie, COOKIE_NAME
from app.database import get_db, get_state, set_state, add_log
from app.scheduler import evaluate_schedule

router = APIRouter(prefix="/api")


# --- Models ---

class LoginRequest(BaseModel):
    password: str


class ScheduleCreate(BaseModel):
    day_of_week: str
    start_time: str
    end_time: str


class ScheduleUpdate(BaseModel):
    day_of_week: str | None = None
    start_time: str | None = None
    end_time: str | None = None


# --- Dependency to get the blocker instance ---

_blocker = None


def set_blocker(blocker):
    global _blocker
    _blocker = blocker


def get_blocker():
    return _blocker


# --- Auth ---

@router.post("/login")
async def login(body: LoginRequest, response: Response):
    if not check_password(body.password):
        return {"ok": False, "error": "Wrong password"}
    cookie = create_session_cookie()
    response.set_cookie(
        COOKIE_NAME,
        cookie,
        max_age=86400,
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}


# --- Status ---

@router.get("/status")
async def status(request: Request):
    require_auth(request)
    blocker = get_blocker()
    override = await get_state("override", "none")
    return {
        "is_blocking": blocker.is_blocking,
        "override": override,
        "target_mac": blocker.target_mac,
        "target_ip": blocker.target_ip,
        "gateway_ip": blocker.gateway_ip,
        "gateway_mac": blocker.gateway_mac,
    }


# --- Manual Override ---

@router.post("/block")
async def block(request: Request):
    require_auth(request)
    blocker = get_blocker()
    await blocker.block()
    await set_state("is_blocking", "1")
    await set_state("override", "block")
    await add_log("blocked", "manual")
    return {"ok": True, "is_blocking": True}


@router.post("/unblock")
async def unblock(request: Request):
    require_auth(request)
    blocker = get_blocker()
    await blocker.unblock()
    await set_state("is_blocking", "0")
    await set_state("override", "unblock")
    await add_log("unblocked", "manual")
    return {"ok": True, "is_blocking": False}


@router.post("/clear-override")
async def clear_override(request: Request):
    require_auth(request)
    blocker = get_blocker()
    await set_state("override", "none")
    await add_log("override cleared", "manual")
    # Re-evaluate schedule immediately
    should_block = await evaluate_schedule()
    if should_block and not blocker.is_blocking:
        await blocker.block()
        await set_state("is_blocking", "1")
        await add_log("blocked", "schedule")
    elif not should_block and blocker.is_blocking:
        await blocker.unblock()
        await set_state("is_blocking", "0")
        await add_log("unblocked", "schedule")
    return {"ok": True, "is_blocking": blocker.is_blocking}


# --- Schedules ---

@router.get("/schedules")
async def list_schedules(request: Request):
    require_auth(request)
    db = await get_db()
    cursor = await db.execute("SELECT * FROM schedule_rules ORDER BY id")
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


@router.post("/schedules")
async def create_schedule(body: ScheduleCreate, request: Request):
    require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        "INSERT INTO schedule_rules (day_of_week, start_time, end_time) VALUES (?, ?, ?)",
        (body.day_of_week.lower(), body.start_time, body.end_time),
    )
    await db.commit()
    await add_log(f"schedule added: {body.day_of_week} {body.start_time}-{body.end_time}", "manual")
    return {"ok": True, "id": cursor.lastrowid}


@router.put("/schedules/{rule_id}")
async def update_schedule(rule_id: int, body: ScheduleUpdate, request: Request):
    require_auth(request)
    db = await get_db()
    # Build dynamic update
    fields = []
    values = []
    if body.day_of_week is not None:
        fields.append("day_of_week = ?")
        values.append(body.day_of_week.lower())
    if body.start_time is not None:
        fields.append("start_time = ?")
        values.append(body.start_time)
    if body.end_time is not None:
        fields.append("end_time = ?")
        values.append(body.end_time)
    if not fields:
        return {"ok": False, "error": "No fields to update"}
    values.append(rule_id)
    await db.execute(f"UPDATE schedule_rules SET {', '.join(fields)} WHERE id = ?", values)
    await db.commit()
    return {"ok": True}


@router.delete("/schedules/{rule_id}")
async def delete_schedule(rule_id: int, request: Request):
    require_auth(request)
    db = await get_db()
    await db.execute("DELETE FROM schedule_rules WHERE id = ?", (rule_id,))
    await db.commit()
    await add_log(f"schedule {rule_id} deleted", "manual")
    return {"ok": True}


@router.patch("/schedules/{rule_id}/toggle")
async def toggle_schedule(rule_id: int, request: Request):
    require_auth(request)
    db = await get_db()
    await db.execute(
        "UPDATE schedule_rules SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?",
        (rule_id,),
    )
    await db.commit()
    return {"ok": True}


# --- Audit Log ---

@router.get("/log")
async def get_log(request: Request):
    require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 50"
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]
