import asyncio
import logging
import signal
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.arp import ArpBlocker
from app.database import get_state, set_state, close_db, add_log
from app.routes.api import router as api_router, set_blocker
from app.routes.pages import router as pages_router
from app.scheduler import init_scheduler, stop_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("netguard")

blocker = ArpBlocker()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("NetGuard starting up...")
    await asyncio.to_thread(blocker.init)
    set_blocker(blocker)

    # Restore previous state
    was_blocking = await get_state("is_blocking", "0")
    override = await get_state("override", "none")
    if was_blocking == "1" or override == "block":
        logger.info("Restoring previous BLOCK state")
        await blocker.block()
        await set_state("is_blocking", "1")
        await add_log("block restored on startup", "system")

    init_scheduler(blocker)
    logger.info("NetGuard ready")

    yield

    # Shutdown: always unblock
    logger.info("NetGuard shutting down — unblocking...")
    stop_scheduler()
    await blocker.unblock()
    await set_state("is_blocking", "0")
    await set_state("override", "none")
    await add_log("unblocked on shutdown", "system")
    await close_db()
    logger.info("NetGuard stopped cleanly")


app = FastAPI(title="NetGuard", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
app.include_router(api_router)
app.include_router(pages_router)
