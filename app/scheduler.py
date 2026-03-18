import asyncio
import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from zoneinfo import ZoneInfo

from app.config import settings
from app.database import get_db, get_state, set_state, add_log

logger = logging.getLogger("netguard.scheduler")

_scheduler: AsyncIOScheduler | None = None
_blocker = None  # set by init_scheduler


DAY_MAP = {
    "mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6,
}
WEEKDAY_DAYS = {0, 1, 2, 3, 4}
WEEKEND_DAYS = {5, 6}


def _matches_day(rule_day: str, current_weekday: int) -> bool:
    rule_day = rule_day.lower()
    if rule_day == "weekday":
        return current_weekday in WEEKDAY_DAYS
    if rule_day == "weekend":
        return current_weekday in WEEKEND_DAYS
    return DAY_MAP.get(rule_day) == current_weekday


def _time_in_range(start_str: str, end_str: str, now_str: str) -> bool:
    """Check if now_str (HH:MM) is within [start, end). Handles overnight spans."""
    if start_str <= end_str:
        return start_str <= now_str < end_str
    else:
        # Overnight: e.g. 22:00-07:00 matches 22:00-23:59 and 00:00-06:59
        return now_str >= start_str or now_str < end_str


async def evaluate_schedule() -> bool:
    """Return True if current time falls within any enabled schedule rule."""
    tz = ZoneInfo(settings.tz)
    now = datetime.now(tz)
    current_weekday = now.weekday()
    now_str = now.strftime("%H:%M")

    db = await get_db()
    cursor = await db.execute(
        "SELECT day_of_week, start_time, end_time FROM schedule_rules WHERE enabled = 1"
    )
    rules = await cursor.fetchall()

    for rule in rules:
        if _matches_day(rule["day_of_week"], current_weekday):
            if _time_in_range(rule["start_time"], rule["end_time"], now_str):
                return True
    return False


async def tick():
    """Called every 60s. Evaluate schedule and apply block/unblock."""
    try:
        override = await get_state("override", "none")
        if override != "none":
            return  # manual override active, skip schedule

        should_block = await evaluate_schedule()
        currently_blocking = _blocker.is_blocking

        if should_block and not currently_blocking:
            await _blocker.block()
            await set_state("is_blocking", "1")
            await add_log("blocked", "schedule")
            logger.info("Schedule triggered: BLOCK")
        elif not should_block and currently_blocking:
            await _blocker.unblock()
            await set_state("is_blocking", "0")
            await add_log("unblocked", "schedule")
            logger.info("Schedule triggered: UNBLOCK")
    except Exception:
        logger.exception("Error in schedule tick")


def init_scheduler(blocker):
    global _scheduler, _blocker
    _blocker = blocker
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(tick, "interval", seconds=60, id="schedule_tick")
    _scheduler.start()
    logger.info("Scheduler started (60s interval)")


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
