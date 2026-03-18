import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.arp import BlockerManager
from app.database import get_all_targets, update_target, close_db, add_log
from app.routes.api import router as api_router, set_manager
from app.routes.pages import router as pages_router
from app.scheduler import init_scheduler, stop_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("netguard")

manager = BlockerManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("NetGuard starting up...")
    await asyncio.to_thread(manager.init)
    set_manager(manager)

    # Restore all targets from DB
    targets = await get_all_targets()
    for t in targets:
        blocker = await asyncio.to_thread(manager.add_target, t["id"], t["mac"])
        if t["is_blocking"] == 1 or t["override"] == "block":
            logger.info("Restoring BLOCK for target %d (%s)", t["id"], t["mac"])
            await blocker.block()
            await update_target(t["id"], is_blocking=1)
            await add_log("block restored on startup", "system", target_id=t["id"])

    init_scheduler(manager)
    logger.info("NetGuard ready (%d targets loaded)", len(targets))

    yield

    # Shutdown: always unblock all
    logger.info("NetGuard shutting down — unblocking all...")
    stop_scheduler()
    await manager.shutdown()
    for t in await get_all_targets():
        await update_target(t["id"], is_blocking=0, override="none")
    await add_log("all unblocked on shutdown", "system")
    await close_db()
    logger.info("NetGuard stopped cleanly")


app = FastAPI(title="NetGuard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(api_router)
app.include_router(pages_router)
