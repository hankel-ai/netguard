import asyncio
import logging
import subprocess
import threading

from scapy.all import Ether, ARP, sendp, srp, conf

from app.config import settings

logger = logging.getLogger("netguard.arp")


class ArpBlocker:
    def __init__(self):
        self.target_mac: str = settings.target_mac.lower()
        self.gateway_ip: str = settings.gateway_ip
        self.interface: str = settings.interface
        self.arp_interval: float = settings.arp_interval
        self.gateway_mac: str | None = None
        self.target_ip: str | None = None
        self._spoofing: bool = False
        self._spoof_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def discover_gateway_mac(self) -> str:
        """Discover gateway MAC via ARP request."""
        conf.verb = 0
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip),
            timeout=3,
            iface=self.interface,
        )
        if not ans:
            raise RuntimeError(f"Could not resolve MAC for gateway {self.gateway_ip}")
        mac = ans[0][1].hwsrc.lower()
        logger.info("Gateway MAC: %s", mac)
        return mac

    def discover_target_ip(self) -> str | None:
        """Find target IP from /proc/net/arp or subnet scan."""
        # Try /proc/net/arp first
        try:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].lower() == self.target_mac:
                        logger.info("Target IP from ARP table: %s", parts[0])
                        return parts[0]
        except FileNotFoundError:
            pass

        # Fallback: scan the /24 subnet
        network = self.gateway_ip.rsplit(".", 1)[0] + ".0/24"
        logger.info("Scanning %s for target MAC %s", network, self.target_mac)
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=5,
            iface=self.interface,
        )
        for sent, recv in ans:
            if recv.hwsrc.lower() == self.target_mac:
                logger.info("Target IP from scan: %s", recv.psrc)
                return recv.psrc
        logger.warning("Could not discover target IP")
        return None

    def _add_iptables_rule(self):
        subprocess.run(
            [
                "iptables", "-C", "FORWARD",
                "-m", "mac", "--mac-source", self.target_mac.upper(),
                "-j", "DROP",
            ],
            capture_output=True,
        )
        # -C returns 0 if rule exists; add only if missing
        result = subprocess.run(
            [
                "iptables", "-C", "FORWARD",
                "-m", "mac", "--mac-source", self.target_mac.upper(),
                "-j", "DROP",
            ],
            capture_output=True,
        )
        if result.returncode != 0:
            subprocess.run(
                [
                    "iptables", "-A", "FORWARD",
                    "-m", "mac", "--mac-source", self.target_mac.upper(),
                    "-j", "DROP",
                ],
                check=True,
            )
            logger.info("iptables DROP rule added")

    def _remove_iptables_rule(self):
        while True:
            result = subprocess.run(
                [
                    "iptables", "-D", "FORWARD",
                    "-m", "mac", "--mac-source", self.target_mac.upper(),
                    "-j", "DROP",
                ],
                capture_output=True,
            )
            if result.returncode != 0:
                break
        logger.info("iptables DROP rule(s) removed")

    def _spoof_loop(self):
        """Continuously send spoofed ARP replies in a background thread."""
        if not self.target_ip:
            logger.error("Cannot spoof: target IP unknown")
            return
        # Tell the target that the gateway IP is at our MAC
        pkt = Ether(dst=self.target_mac) / ARP(
            op="is-at",
            psrc=self.gateway_ip,
            pdst=self.target_ip,
            hwdst=self.target_mac,
        )
        logger.info("Starting ARP spoof loop (target=%s)", self.target_ip)
        while not self._stop_event.is_set():
            sendp(pkt, iface=self.interface, verbose=False)
            self._stop_event.wait(self.arp_interval)

    def _send_corrective_arp(self, count: int = 5):
        """Restore correct gateway ARP entry on the target."""
        if not self.target_ip or not self.gateway_mac:
            return
        pkt = Ether(dst=self.target_mac) / ARP(
            op="is-at",
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac,
            pdst=self.target_ip,
            hwdst=self.target_mac,
        )
        for _ in range(count):
            sendp(pkt, iface=self.interface, verbose=False)
        # Also send a broadcast corrective
        bcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op="is-at",
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac,
        )
        for _ in range(count):
            sendp(bcast, iface=self.interface, verbose=False)
        logger.info("Sent %d corrective ARP packets", count)

    async def block(self):
        if self._spoofing:
            return
        self._add_iptables_rule()
        self._stop_event.clear()
        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()
        self._spoofing = True
        logger.info("Blocking ACTIVE")

    async def unblock(self):
        if not self._spoofing:
            # Still clean up iptables in case of leftover rules
            self._remove_iptables_rule()
            return
        self._stop_event.set()
        if self._spoof_thread:
            self._spoof_thread.join(timeout=5)
            self._spoof_thread = None
        self._spoofing = False
        self._remove_iptables_rule()
        self._send_corrective_arp()
        logger.info("Blocking INACTIVE")

    @property
    def is_blocking(self) -> bool:
        return self._spoofing

    def init(self):
        """Run discovery (call from startup, in a thread)."""
        self.gateway_mac = self.discover_gateway_mac()
        self.target_ip = self.discover_target_ip()
