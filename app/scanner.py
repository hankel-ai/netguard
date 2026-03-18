import logging
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import Ether, ARP, srp, conf, get_if_hwaddr

from app.config import settings

logger = logging.getLogger("netguard.scanner")


def scan_network() -> list[dict]:
    """ARP scan the local /24 subnet. Returns list of {mac, ip}."""
    conf.verb = 0
    network = settings.gateway_ip.rsplit(".", 1)[0] + ".0/24"
    logger.info("Scanning %s", network)
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
        timeout=5,
        iface=settings.interface,
    )
    # Filter out gateway and ourselves
    our_mac = get_if_hwaddr(settings.interface).lower()
    gateway_ip = settings.gateway_ip
    devices = []
    for sent, recv in ans:
        mac = recv.hwsrc.lower()
        ip = recv.psrc
        if mac == our_mac or ip == gateway_ip:
            continue
        devices.append({"mac": mac, "ip": ip})
    logger.info("Found %d devices (excluding gateway and self)", len(devices))
    return devices


def resolve_hostname(ip: str) -> str | None:
    """Try to resolve hostname via reverse DNS, then NetBIOS."""
    # Reverse DNS
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    # NetBIOS via nmblookup
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if "<00>" in line and "GROUP" not in line:
                    name = line.split()[0]
                    if name and name != "*":
                        return name
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def full_scan() -> list[dict]:
    """Scan network and resolve hostnames in parallel."""
    devices = scan_network()

    # Resolve hostnames concurrently (max 20 threads, 3s timeout each)
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(resolve_hostname, d["ip"]): d for d in devices}
        for future in as_completed(futures):
            dev = futures[future]
            try:
                dev["hostname"] = future.result()
            except Exception:
                dev["hostname"] = None

    # Sort: devices with hostnames first, then by IP
    devices.sort(key=lambda d: (d["hostname"] is None, d["ip"]))
    return devices
