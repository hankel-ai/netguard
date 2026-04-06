import html
import logging
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import Ether, ARP, srp, conf, get_if_hwaddr

from app.config import settings
from app.oui import lookup_vendor

logger = logging.getLogger("netguard.scanner")


def get_online_ips() -> set[str]:
    """Read /proc/net/arp for IPs with valid MAC entries (works even if ping blocked)."""
    online = set()
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 6 and parts[2] != "0x0":
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00":
                        online.add(parts[0])
    except Exception:
        pass
    return online


def arp_ping_ips(ips: list[str]) -> set[str]:
    """Send unicast ARP probes to specific IPs and return those that respond."""
    if not ips:
        return set()
    conf.verb = 0
    alive = set()
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
            timeout=2, iface=settings.interface,
        )
        for sent, recv in ans:
            alive.add(recv.psrc)
    except Exception:
        pass
    return alive


def _ping_sweep(network_prefix: str):
    """Send a fast ping sweep to wake up sleeping devices before ARP scan."""
    try:
        # fping is fastest, but fall back to parallel ping
        subprocess.run(
            ["fping", "-a", "-q", "-c1", "-t100", "-g", f"{network_prefix}.0/24"],
            capture_output=True, timeout=10,
        )
    except FileNotFoundError:
        # Fallback: use native ping in parallel via subprocess
        try:
            subprocess.run(
                ["bash", "-c",
                 f"for i in $(seq 1 254); do ping -c1 -W1 {network_prefix}.$i &>/dev/null & done; wait"],
                capture_output=True, timeout=15,
            )
        except Exception:
            pass
    except Exception:
        pass


def _read_arp_cache() -> list[dict]:
    """Read the system ARP cache from /proc/net/arp for additional devices."""
    devices = []
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 6 and parts[2] != "0x0":  # flags != incomplete
                    ip = parts[0]
                    mac = parts[3].lower()
                    if mac != "00:00:00:00:00:00":
                        devices.append({"mac": mac, "ip": ip})
    except Exception:
        pass
    return devices


def scan_network() -> list[dict]:
    """ARP scan the local /24 subnet. Returns list of {mac, ip}."""
    conf.verb = 0
    network_prefix = settings.gateway_ip.rsplit(".", 1)[0]
    network = network_prefix + ".0/24"
    logger.info("Scanning %s", network)

    # Ping sweep first to wake sleeping devices (especially WiFi)
    _ping_sweep(network_prefix)

    # Send two ARP rounds for better coverage
    seen = {}
    for attempt in range(2):
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=4,
            iface=settings.interface,
        )
        for sent, recv in ans:
            mac = recv.hwsrc.lower()
            ip = recv.psrc
            seen[mac] = ip

    # Also check system ARP cache for devices that responded to ping but not ARP broadcast
    for dev in _read_arp_cache():
        if dev["mac"] not in seen:
            seen[dev["mac"]] = dev["ip"]

    # Filter out gateway and ourselves
    our_mac = get_if_hwaddr(settings.interface).lower()
    gateway_ip = settings.gateway_ip
    devices = []
    for mac, ip in seen.items():
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


def _mdns_discover() -> dict[str, str]:
    """Browse mDNS services to collect device names. Returns {ip: hostname}."""
    from zeroconf import Zeroconf, IPVersion, ServiceBrowser

    results = {}

    class Listener:
        def add_service(self, zc, type_, name):
            try:
                info = zc.get_service_info(type_, name)
                if info and info.server:
                    hostname = info.server.rstrip(".")
                    if hostname.lower().endswith(".local"):
                        hostname = hostname[:-6]
                    if hostname:
                        for addr in info.parsed_addresses():
                            if ":" not in addr:  # IPv4 only
                                results.setdefault(addr, hostname)
            except Exception:
                pass

        def remove_service(self, *a):
            pass

        def update_service(self, *a):
            pass

    services = [
        "_companion-link._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_apple-mobdev2._tcp.local.",
        "_sleep-proxy._udp.local.",
        "_homekit._tcp.local.",
        "_googlecast._tcp.local.",
        "_http._tcp.local.",
        "_ipp._tcp.local.",
        "_smb._tcp.local.",
        "_spotify-connect._tcp.local.",
    ]

    try:
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        listener = Listener()
        browsers = []
        for svc in services:
            try:
                browsers.append(ServiceBrowser(zc, svc, listener))
            except Exception:
                pass
        time.sleep(5)
        zc.close()
    except Exception:
        logger.debug("mDNS discovery failed", exc_info=True)

    return results


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
                        results[ip] = html.unescape(m.group(1).strip())
            except Exception:
                pass

    except Exception:
        logger.debug("SSDP discovery failed", exc_info=True)

    return results


# Module-level discovery caches (refreshed each full_scan)
_ssdp_names: dict[str, str] = {}
_mdns_names: dict[str, str] = {}


def resolve_hostname(ip: str) -> str | None:
    """Try multiple methods to resolve a device name."""
    # 1. Reverse DNS (via Pi-hole dnsmasq — fast, covers DHCP hostnames)
    name = _resolve_rdns(ip)
    if name:
        return name

    # 2. mDNS service browse (from cached discovery — Apple devices, Chromecast, etc.)
    name = _mdns_names.get(ip)
    if name:
        return name

    # 3. NetBIOS (Windows devices)
    name = _resolve_netbios(ip)
    if name:
        return name

    # 4. SSDP/UPnP (from cached discovery — Roku, smart TVs, etc.)
    name = _ssdp_names.get(ip)
    if name:
        return name

    return None


async def fetch_pihole_devices() -> list[dict]:
    """Fetch device list from Pi-hole DHCP leases. Returns list of {mac, ip, hostname}."""
    from app.pihole import get_pihole_client
    client = get_pihole_client()
    if not client:
        return []
    try:
        leases = await client.get_dhcp_leases()
        devices = []
        for lease in leases:
            mac = (lease.get("hwaddr") or lease.get("mac") or "").lower()
            ip = lease.get("ip") or lease.get("address") or ""
            raw_name = lease.get("name") or lease.get("hostname") or None
            hostname = raw_name if raw_name and raw_name != "*" else None
            if mac and ip:
                devices.append({"mac": mac, "ip": ip, "hostname": hostname})
        logger.info("Pi-hole DHCP: %d leases", len(devices))
        return devices
    except Exception:
        logger.warning("Failed to fetch Pi-hole DHCP leases", exc_info=True)
        return []


def full_scan() -> list[dict]:
    """Scan network and resolve hostnames in parallel."""
    global _ssdp_names, _mdns_names

    devices = scan_network()

    # Run mDNS and SSDP discovery (broadcast once, cache results)
    try:
        _mdns_names = _mdns_discover()
        logger.info("mDNS discovered %d device names", len(_mdns_names))
    except Exception:
        logger.debug("mDNS discovery failed", exc_info=True)
        _mdns_names = {}

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

    # Resolve vendor and device type from MAC OUI
    for dev in devices:
        vendor, device_type = lookup_vendor(dev["mac"])
        dev["vendor"] = vendor
        dev["device_type"] = device_type

    # Sort: devices with hostnames first, then by IP
    devices.sort(key=lambda d: (d["hostname"] is None, d["ip"]))
    return devices
