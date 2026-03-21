import asyncio

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from app.auth import require_auth, check_password, create_session_cookie, COOKIE_NAME
from app.database import (
    get_all_targets, get_target, get_target_by_mac, add_target as db_add_target,
    remove_target as db_remove_target, update_target,
    get_schedules_for_target, get_schedule, add_log, get_db,
    upsert_lan_device, get_all_lan_devices, get_lan_device_by_mac,
)
from app.scheduler import evaluate_schedule_for_target
from app.scanner import full_scan, fetch_pihole_devices, resolve_mac, resolve_hostname
from app.oui import lookup_vendor
from app.pihole import get_pihole_client

router = APIRouter(prefix="/api")

_manager = None  # BlockerManager
_traffic = None   # TrafficMonitor


def set_manager(manager):
    global _manager
    _manager = manager


def set_traffic_monitor(monitor):
    global _traffic
    _traffic = monitor


# --- Models ---

class LoginRequest(BaseModel):
    password: str


class AddTargetRequest(BaseModel):
    ip: str
    mac: str | None = None
    hostname: str | None = None
    force: bool = False


class DescriptionUpdate(BaseModel):
    description: str


class ScheduleCreate(BaseModel):
    day_of_week: str
    start_time: str
    end_time: str


class ScheduleUpdate(BaseModel):
    day_of_week: str | None = None
    start_time: str | None = None
    end_time: str | None = None


# --- Auth ---

@router.post("/login")
async def login(body: LoginRequest, response: Response):
    if not check_password(body.password):
        return {"ok": False, "error": "Wrong password"}
    cookie = create_session_cookie()
    response.set_cookie(COOKIE_NAME, cookie, max_age=86400, httponly=True, samesite="lax")
    return {"ok": True}


# --- Targets ---

@router.get("/targets")
async def list_targets(request: Request):
    require_auth(request)
    targets = await get_all_targets()
    all_stats = _traffic.get_all_stats() if _traffic else {}
    for t in targets:
        blocker = _manager.get_blocker(t["id"])
        t["is_blocking"] = blocker.is_blocking if blocker else False
        t["is_monitoring"] = blocker.is_monitoring if blocker else False
        t["target_ip"] = blocker.target_ip if blocker else t.get("ip")
        t["schedules"] = await get_schedules_for_target(t["id"])
        t["traffic"] = all_stats.get(t["id"])
        t["dns_blocked"] = bool(t.get("dns_blocked"))
        # Add vendor info from OUI lookup
        vendor, device_type = lookup_vendor(t["mac"])
        t["vendor"] = vendor
        t["device_type"] = device_type
    return targets


@router.post("/targets")
async def add_target(body: AddTargetRequest, request: Request):
    require_auth(request)
    mac = body.mac
    hostname = body.hostname
    # If no MAC provided, resolve it from the IP via ARP
    if not mac:
        mac = await asyncio.to_thread(resolve_mac, body.ip)
        if not mac:
            return {"ok": False, "error": f"Could not resolve MAC for {body.ip} — is the device online?"}
    # If no hostname provided, try to resolve it
    if not hostname:
        hostname = await asyncio.to_thread(resolve_hostname, body.ip)
    # Check for changes vs cached device (unless force=True)
    if not body.force:
        cached = await get_lan_device_by_mac(mac)
        if cached:
            changes = []
            if cached["hostname"] and hostname and cached["hostname"] != hostname:
                changes.append(f"Hostname changed: {cached['hostname']} \u2192 {hostname}")
            if cached["ip"] and body.ip and cached["ip"] != body.ip:
                changes.append(f"IP changed: {cached['ip']} \u2192 {body.ip}")
            if changes:
                return {"ok": False, "confirm": True, "changes": changes,
                        "mac": mac, "ip": body.ip, "hostname": hostname}
    existing = await get_target_by_mac(mac)
    if existing:
        return {"ok": False, "error": "Target with this MAC already exists"}
    try:
        target_id = await db_add_target(mac, body.ip, hostname)
        await asyncio.to_thread(_manager.add_target, target_id, mac)
        await add_log(f"target added: {mac}", "manual", target_id=target_id)
        return {"ok": True, "id": target_id}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.delete("/targets/{target_id}")
async def delete_target(target_id: int, request: Request):
    require_auth(request)
    target = await get_target(target_id)
    if not target:
        return {"ok": False, "error": "Not found"}
    # Clean up DNS block if active
    if target.get("dns_blocked"):
        client = get_pihole_client()
        if client:
            blocker = _manager.get_blocker(target_id) if _manager else None
            ip = blocker.target_ip if blocker else target.get("ip")
            if ip:
                try:
                    await client.dns_unblock_device(ip)
                except Exception:
                    pass
    await asyncio.to_thread(_traffic.remove_target, target_id)
    await _manager.remove_target(target_id)
    await db_remove_target(target_id)
    await add_log(f"target removed: {target['mac']}", "manual", target_id=target_id)
    return {"ok": True}


# --- Per-target actions ---

@router.post("/targets/{target_id}/block")
async def block_target(target_id: int, request: Request):
    require_auth(request)
    blocker = _manager.get_blocker(target_id)
    if not blocker:
        return {"ok": False, "error": "Target not found"}
    await blocker.block()
    await update_target(target_id, is_blocking=1, override="block")
    await add_log("blocked", "manual", target_id=target_id)
    return {"ok": True}


@router.post("/targets/{target_id}/unblock")
async def unblock_target(target_id: int, request: Request):
    require_auth(request)
    blocker = _manager.get_blocker(target_id)
    if not blocker:
        return {"ok": False, "error": "Target not found"}
    await blocker.unblock()
    await update_target(target_id, is_blocking=0, override="unblock")
    await add_log("unblocked", "manual", target_id=target_id)
    return {"ok": True}


@router.post("/targets/{target_id}/clear-override")
async def clear_override(target_id: int, request: Request):
    require_auth(request)
    blocker = _manager.get_blocker(target_id)
    if not blocker:
        return {"ok": False, "error": "Target not found"}
    await update_target(target_id, override="none")
    await add_log("override cleared", "manual", target_id=target_id)
    # Re-evaluate schedule
    should_block = await evaluate_schedule_for_target(target_id)
    if should_block and not blocker.is_blocking:
        await blocker.block()
        await update_target(target_id, is_blocking=1)
        await add_log("blocked", "schedule", target_id=target_id)
    elif not should_block and blocker.is_blocking:
        await blocker.unblock()
        await update_target(target_id, is_blocking=0)
        await add_log("unblocked", "schedule", target_id=target_id)
    return {"ok": True, "is_blocking": blocker.is_blocking}


@router.post("/targets/{target_id}/monitor")
async def start_monitor(target_id: int, request: Request):
    require_auth(request)
    blocker = _manager.get_blocker(target_id)
    if not blocker:
        return {"ok": False, "error": "Target not found"}
    await blocker.start_monitor()
    await asyncio.to_thread(
        _traffic.add_target, target_id, blocker.target_mac, blocker.target_ip
    )
    await update_target(target_id, is_monitoring=1)
    await add_log("monitoring started", "manual", target_id=target_id)
    return {"ok": True}


@router.post("/targets/{target_id}/unmonitor")
async def stop_monitor(target_id: int, request: Request):
    require_auth(request)
    blocker = _manager.get_blocker(target_id)
    if not blocker:
        return {"ok": False, "error": "Target not found"}
    await blocker.stop_monitor()
    await asyncio.to_thread(_traffic.remove_target, target_id)
    await update_target(target_id, is_monitoring=0)
    await add_log("monitoring stopped", "manual", target_id=target_id)
    return {"ok": True}


@router.patch("/targets/{target_id}/description")
async def set_description(target_id: int, body: DescriptionUpdate, request: Request):
    require_auth(request)
    target = await get_target(target_id)
    if not target:
        return {"ok": False, "error": "Not found"}
    await update_target(target_id, description=body.description or None)
    return {"ok": True}


# --- Schedules ---

@router.get("/targets/{target_id}/schedules")
async def list_schedules(target_id: int, request: Request):
    require_auth(request)
    return await get_schedules_for_target(target_id)


@router.post("/targets/{target_id}/schedules")
async def create_schedule(target_id: int, body: ScheduleCreate, request: Request):
    require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        "INSERT INTO schedule_rules (target_id, day_of_week, start_time, end_time) VALUES (?, ?, ?, ?)",
        (target_id, body.day_of_week.lower(), body.start_time, body.end_time),
    )
    await db.commit()
    await add_log(
        f"schedule added: {body.day_of_week} {body.start_time}-{body.end_time}",
        "manual", target_id=target_id,
    )
    return {"ok": True, "id": cursor.lastrowid}


@router.put("/schedules/{rule_id}")
async def update_schedule(rule_id: int, body: ScheduleUpdate, request: Request):
    require_auth(request)
    db = await get_db()
    fields, values = [], []
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
    rule = await get_schedule(rule_id)
    db = await get_db()
    await db.execute("DELETE FROM schedule_rules WHERE id = ?", (rule_id,))
    await db.commit()
    if rule:
        await add_log(f"schedule {rule_id} deleted", "manual", target_id=rule["target_id"])
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


# --- LAN Scan ---

@router.get("/lan-devices")
async def list_lan_devices(request: Request):
    require_auth(request)
    devices = await get_all_lan_devices()
    targets = await get_all_targets()
    known_macs = {t["mac"].lower() for t in targets}
    for dev in devices:
        dev["is_target"] = dev["mac"].lower() in known_macs
    return devices


@router.post("/scan")
async def scan_lan(request: Request):
    require_auth(request)
    # Run ARP scan and DHCP fetch in parallel
    arp_task = asyncio.to_thread(full_scan)
    dhcp_task = fetch_pihole_devices()
    devices, dhcp_devices = await asyncio.gather(arp_task, dhcp_task)

    # Merge DHCP devices into ARP results (DHCP fills gaps)
    seen_macs = {d["mac"] for d in devices}
    for dd in dhcp_devices:
        if dd["mac"] in seen_macs:
            # Update hostname if ARP scan didn't find one
            for d in devices:
                if d["mac"] == dd["mac"] and not d.get("hostname") and dd.get("hostname"):
                    d["hostname"] = dd["hostname"]
        else:
            # Device only found via DHCP
            vendor, device_type = lookup_vendor(dd["mac"])
            dd["vendor"] = vendor
            dd["device_type"] = device_type
            devices.append(dd)

    # Upsert found devices into cache
    for dev in devices:
        await upsert_lan_device(dev["mac"], dev["ip"], dev.get("hostname"),
                                dev.get("vendor"), dev.get("device_type"))
    # Return ALL cached devices, not just current scan results
    all_devices = await get_all_lan_devices()
    targets = await get_all_targets()
    known_macs = {t["mac"].lower() for t in targets}
    for dev in all_devices:
        dev["is_target"] = dev["mac"].lower() in known_macs
    return all_devices


# --- Audit Log ---

@router.get("/log")
async def get_log(request: Request):
    require_auth(request)
    db = await get_db()
    cursor = await db.execute(
        "SELECT l.*, t.hostname, t.mac as target_mac FROM audit_log l "
        "LEFT JOIN targets t ON l.target_id = t.id "
        "ORDER BY l.id DESC LIMIT 50"
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# --- Pi-hole Integration ---

@router.get("/pihole/status")
async def pihole_status(request: Request):
    require_auth(request)
    client = get_pihole_client()
    if not client:
        return {"configured": False, "connected": False}
    connected = await client.test_connection()
    return {"configured": True, "connected": connected}


@router.get("/targets/{target_id}/dns-queries")
async def get_dns_queries(target_id: int, request: Request):
    require_auth(request)
    client = get_pihole_client()
    if not client:
        return {"ok": False, "error": "Pi-hole not configured"}
    target = await get_target(target_id)
    if not target:
        return {"ok": False, "error": "Target not found"}
    blocker = _manager.get_blocker(target_id) if _manager else None
    ip = blocker.target_ip if blocker else target.get("ip")
    if not ip:
        return {"ok": False, "error": "No IP address for this target"}
    queries = await client.get_queries(client_ip=ip, limit=100)
    return {"ok": True, "queries": queries}


@router.post("/targets/{target_id}/dns-block")
async def dns_block_target(target_id: int, request: Request):
    require_auth(request)
    client = get_pihole_client()
    if not client:
        return {"ok": False, "error": "Pi-hole not configured"}
    target = await get_target(target_id)
    if not target:
        return {"ok": False, "error": "Target not found"}
    blocker = _manager.get_blocker(target_id) if _manager else None
    ip = blocker.target_ip if blocker else target.get("ip")
    if not ip:
        return {"ok": False, "error": "No IP address for this target"}
    await client.dns_block_device(ip)
    await update_target(target_id, dns_blocked=1)
    await add_log("DNS blocked", "manual", target_id=target_id)
    return {"ok": True}


@router.post("/targets/{target_id}/dns-unblock")
async def dns_unblock_target(target_id: int, request: Request):
    require_auth(request)
    client = get_pihole_client()
    if not client:
        return {"ok": False, "error": "Pi-hole not configured"}
    target = await get_target(target_id)
    if not target:
        return {"ok": False, "error": "Target not found"}
    blocker = _manager.get_blocker(target_id) if _manager else None
    ip = blocker.target_ip if blocker else target.get("ip")
    if not ip:
        return {"ok": False, "error": "No IP address for this target"}
    await client.dns_unblock_device(ip)
    await update_target(target_id, dns_blocked=0)
    await add_log("DNS unblocked", "manual", target_id=target_id)
    return {"ok": True}
