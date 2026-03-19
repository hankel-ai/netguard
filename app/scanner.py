import logging
import re
import socket
import struct
import subprocess
import time
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


def resolve_mac(ip: str) -> str | None:
    """Send targeted ARP request to resolve MAC for a single IP."""
    conf.verb = 0
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        timeout=3,
        iface=settings.interface,
    )
    if ans:
        return ans[0][1].hwsrc.lower()
    return None


def _resolve_rdns(ip: str) -> str | None:
    """Reverse DNS lookup."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError):
        pass
    return None


def _resolve_netbios(ip: str) -> str | None:
    """NetBIOS name via nmblookup."""
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


def _resolve_mdns(ip: str) -> str | None:
    """mDNS reverse lookup via avahi-resolve or zeroconf."""
    # Try avahi-resolve-address first (fast, no import overhead)
    try:
        result = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Output format: "192.168.1.100\tDeviceName.local"
            parts = result.stdout.strip().split("\t")
            if len(parts) >= 2:
                name = parts[1].rstrip(".")
                # Strip .local suffix for cleaner display
                if name.lower().endswith(".local"):
                    name = name[:-6]
                return name
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: zeroconf PTR query
    try:
        from zeroconf import Zeroconf, ServiceBrowser
        # Build reverse pointer name: 100.1.168.192.in-addr.arpa.
        octets = ip.split(".")
        ptr_name = ".".join(reversed(octets)) + ".in-addr.arpa."

        zc = Zeroconf()
        try:
            info = zc.cache.entries_with_name(ptr_name)
            if info:
                for entry in info:
                    name = str(entry.alias) if hasattr(entry, "alias") else str(entry)
                    if name and name.lower().endswith(".local."):
                        name = name[:-7]
                    elif name and name.lower().endswith(".local"):
                        name = name[:-6]
                    if name:
                        return name
        finally:
            zc.close()
    except Exception:
        pass

    return None


def _ssdp_discover() -> dict[str, str]:
    """Send SSDP M-SEARCH and collect friendly names. Returns {ip: friendly_name}."""
    results = {}
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(3)
        sock.sendto(msearch, ("239.255.255.250", 1900))

        locations = {}
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                text = data.decode("utf-8", errors="replace")
                ip = addr[0]
                # Extract LOCATION header for fetching device description
                for line in text.splitlines():
                    if line.upper().startswith("LOCATION:"):
                        url = line.split(":", 1)[1].strip()
                        if ip not in locations:
                            locations[ip] = url
                        break
            except socket.timeout:
                break
        sock.close()

        # Fetch device descriptions from LOCATION URLs
        import urllib.request
        for ip, url in locations.items():
            try:
                req = urllib.request.Request(url, method="GET")
                with urllib.request.urlopen(req, timeout=2) as resp:
                    xml = resp.read().decode("utf-8", errors="replace")
                    # Extract <friendlyName> from UPnP XML
                    m = re.search(r"<friendlyName>([^<]+)</friendlyName>", xml)
                    if m:
                        results[ip] = m.group(1).strip()
            except Exception:
                pass

    except Exception:
        logger.debug("SSDP discovery failed", exc_info=True)

    return results


# Module-level SSDP cache (refreshed each full_scan)
_ssdp_names: dict[str, str] = {}


def resolve_hostname(ip: str) -> str | None:
    """Try multiple methods to resolve a device name: rDNS -> mDNS -> NetBIOS -> SSDP."""
    # 1. Reverse DNS
    name = _resolve_rdns(ip)
    if name:
        return name

    # 2. mDNS (Bonjour/Avahi)
    name = _resolve_mdns(ip)
    if name:
        return name

    # 3. NetBIOS
    name = _resolve_netbios(ip)
    if name:
        return name

    # 4. SSDP/UPnP (from cached discovery)
    name = _ssdp_names.get(ip)
    if name:
        return name

    return None


def full_scan() -> list[dict]:
    """Scan network and resolve hostnames in parallel."""
    global _ssdp_names

    devices = scan_network()

    # Run SSDP discovery once for all devices
    try:
        _ssdp_names = _ssdp_discover()
        logger.info("SSDP discovered %d device names", len(_ssdp_names))
    except Exception:
        logger.debug("SSDP discovery failed", exc_info=True)
        _ssdp_names = {}

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
