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
WEEKDAY_DAYS = {0, 1, 2, 3, 6}  # Mon-Thu + Sun (school nights)
WEEKEND_DAYS = {4, 5}            # Fri-Sat (weekend nights)


def _day_matches(rule_day: str, weekday: int) -> bool:
    rule_day = rule_day.lower()
    if rule_day == "weekday":
        return weekday in WEEKDAY_DAYS
    if rule_day == "weekend":
        return weekday in WEEKEND_DAYS
    return DAY_MAP.get(rule_day) == weekday


def _is_overnight(start_str: str, end_str: str) -> bool:
    """True when end time is earlier than start time (crosses midnight)."""
    return start_str > end_str


async def evaluate_schedule_for_target(target_id: int) -> bool:
    """Return True if current time falls within any enabled schedule rule for target.

    For overnight rules (e.g. 23:30–06:00), the day type applies to the
    start time only.  So a "weekday" rule 23:30–06:00 that begins Friday
    night stays active through Saturday 06:00, even though Saturday is a
    weekend day.
    """
    tz = ZoneInfo(settings.tz)
    now = datetime.now(tz)
    current_weekday = now.weekday()
    yesterday_weekday = (current_weekday - 1) % 7
    now_str = now.strftime("%H:%M")

    rules = await get_schedules_for_target(target_id)
    for rule in rules:
        if not rule["enabled"]:
            continue

        start = rule["start_time"]
        end = rule["end_time"]
        overnight = _is_overnight(start, end)

        if overnight:
            # Before-midnight portion: day must match today, time >= start
            if now_str >= start and _day_matches(rule["day_of_week"], current_weekday):
                return True
            # After-midnight portion: day must match *yesterday*, time < end
            if now_str < end and _day_matches(rule["day_of_week"], yesterday_weekday):
                return True
        else:
            # Same-day rule: simple range check
            if _day_matches(rule["day_of_week"], current_weekday):
                if start <= now_str < end:
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
