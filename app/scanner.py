import logging
import socket
import subprocess

from scapy.all import Ether, ARP, srp, conf

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
    devices = []
    for sent, recv in ans:
        devices.append({"mac": recv.hwsrc.lower(), "ip": recv.psrc})
    logger.info("Found %d devices", len(devices))
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
            capture_output=True, text=True, timeout=5,
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
    """Scan network and resolve hostnames. Returns [{mac, ip, hostname}]."""
    devices = scan_network()
    for dev in devices:
        dev["hostname"] = resolve_hostname(dev["ip"])
    return devices
