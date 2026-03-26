import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.arp import BlockerManager
from app.database import get_all_targets, update_target, close_db, add_log
from app.pihole import get_pihole_client
from app.routes.api import router as api_router, set_manager, set_traffic_monitor
from app.routes.pages import router as pages_router
from app.scheduler import init_scheduler, stop_scheduler
from app.traffic import TrafficMonitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("netguard")

manager = BlockerManager()
traffic_monitor = TrafficMonitor()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("NetGuard starting up...")
    await asyncio.to_thread(manager.init)
    await asyncio.to_thread(traffic_monitor.init)
    set_manager(manager)
    set_traffic_monitor(traffic_monitor)

    # Restore all targets from DB
    targets = await get_all_targets()
    for t in targets:
        blocker = await asyncio.to_thread(manager.add_target, t["id"], t["mac"])
        if t["is_blocking"] == 1 or t["override"] == "block":
            logger.info("Restoring BLOCK for target %d (%s)", t["id"], t["mac"])
            await blocker.block()
            await update_target(t["id"], is_blocking=1)
            await add_log("block restored on startup", "system", target_id=t["id"])
        if t.get("is_monitoring"):
            logger.info("Restoring MONITOR for target %d (%s)", t["id"], t["mac"])
            await blocker.start_monitor()
            await asyncio.to_thread(
                traffic_monitor.add_target, t["id"], t["mac"], blocker.target_ip
            )

    traffic_monitor.start()
    init_scheduler(manager)

    # Pi-hole integration (optional)
    pihole = get_pihole_client()
    if pihole:
        try:
            if await pihole.test_connection():
                await pihole.ensure_blocking_group()
                # Restore DNS blocks
                for t in targets:
                    if t.get("dns_blocked"):
                        blocker = manager.get_blocker(t["id"])
                        ip = blocker.target_ip if blocker else t.get("ip")
                        if ip:
                            await pihole.dns_block_device(ip)
                            logger.info("Restored DNS block for target %d (%s)", t["id"], ip)
                logger.info("Pi-hole integration active")
            else:
                logger.warning("Pi-hole configured but connection failed")
        except Exception:
            logger.warning("Pi-hole setup failed", exc_info=True)
    else:
        logger.info("Pi-hole not configured — skipping")

    logger.info("NetGuard ready (%d targets loaded)", len(targets))

    yield

    # Shutdown: always unblock all
    logger.info("NetGuard shutting down — unblocking all...")
    stop_scheduler()
    await asyncio.to_thread(traffic_monitor.cleanup)
    await manager.shutdown()

    # DNS unblock all
    pihole = get_pihole_client()
    if pihole:
        try:
            for t in await get_all_targets():
                if t.get("dns_blocked"):
                    blocker = manager.get_blocker(t["id"])
                    ip = blocker.target_ip if blocker else t.get("ip")
                    if ip:
                        await pihole.dns_unblock_device(ip)
            await pihole.close()
        except Exception:
            logger.warning("Pi-hole shutdown cleanup failed", exc_info=True)

    for t in await get_all_targets():
        # Only reset runtime state; preserve override & dns_blocked so they
        # survive restarts and get restored on next startup.
        await update_target(t["id"], is_blocking=0)
    await add_log("all unblocked on shutdown", "system")
    await close_db()
    logger.info("NetGuard stopped cleanly")


app = FastAPI(title="NetGuard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(api_router)
app.include_router(pages_router)
