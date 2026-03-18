import asyncio
import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from zoneinfo import ZoneInfo

from app.config import settings
from app.database import get_db, get_all_targets, get_schedules_for_target, update_target, add_log

logger = logging.getLogger("netguard.scheduler")

_scheduler: AsyncIOScheduler | None = None
_manager = None  # BlockerManager, set by init_scheduler

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
    if start_str <= end_str:
        return start_str <= now_str < end_str
    else:
        return now_str >= start_str or now_str < end_str


async def evaluate_schedule_for_target(target_id: int) -> bool:
    """Return True if current time falls within any enabled schedule rule for target."""
    tz = ZoneInfo(settings.tz)
    now = datetime.now(tz)
    current_weekday = now.weekday()
    now_str = now.strftime("%H:%M")

    rules = await get_schedules_for_target(target_id)
    for rule in rules:
        if not rule["enabled"]:
            continue
        if _matches_day(rule["day_of_week"], current_weekday):
            if _time_in_range(rule["start_time"], rule["end_time"], now_str):
                return True
    return False


async def tick():
    """Called every 60s. Evaluate schedule for each target and apply block/unblock."""
    try:
        targets = await get_all_targets()
        for target in targets:
            tid = target["id"]
            override = target["override"]
            if override != "none":
                continue

            blocker = _manager.get_blocker(tid)
            if blocker is None:
                continue

            should_block = await evaluate_schedule_for_target(tid)
            currently_blocking = blocker.is_blocking

            if should_block and not currently_blocking:
                await blocker.block()
                await update_target(tid, is_blocking=1)
                await add_log("blocked", "schedule", target_id=tid)
                logger.info("Schedule triggered BLOCK for target %d", tid)
            elif not should_block and currently_blocking:
                await blocker.unblock()
                await update_target(tid, is_blocking=0)
                await add_log("unblocked", "schedule", target_id=tid)
                logger.info("Schedule triggered UNBLOCK for target %d", tid)
    except Exception:
        logger.exception("Error in schedule tick")


def init_scheduler(manager):
    global _scheduler, _manager
    _manager = manager
    _scheduler = AsyncIOScheduler()
    _scheduler.add_job(tick, "interval", seconds=60, id="schedule_tick")
    _scheduler.start()
    logger.info("Scheduler started (60s interval)")


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
