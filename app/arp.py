import asyncio
import logging
import subprocess
import threading

from scapy.all import (
    Ether, ARP, IPv6,
    ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr,
    sendp, srp, sniff, conf, get_if_hwaddr,
)

from app.config import settings

logger = logging.getLogger("netguard.arp")


class TargetBlocker:
    """Manages ARP + NDP spoofing for a single target."""

    def __init__(self, target_id: int, target_mac: str, gateway_ip: str,
                 gateway_mac: str, our_mac: str, interface: str,
                 arp_interval: float, gateway_ll_addr: str | None):
        self.target_id = target_id
        self.target_mac = target_mac.lower()
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.our_mac = our_mac
        self.interface = interface
        self.arp_interval = arp_interval
        self.gateway_ll_addr = gateway_ll_addr
        self.target_ip: str | None = None
        self._spoofing = False
        self._spoof_thread: threading.Thread | None = None
        self._ndp_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def discover_target_ip(self) -> str | None:
        try:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3].lower() == self.target_mac:
                        self.target_ip = parts[0]
                        return self.target_ip
        except FileNotFoundError:
            pass
        network = self.gateway_ip.rsplit(".", 1)[0] + ".0/24"
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=5, iface=self.interface,
        )
        for sent, recv in ans:
            if recv.hwsrc.lower() == self.target_mac:
                self.target_ip = recv.psrc
                return self.target_ip
        return None

    # --- Firewall ---

    def _add_firewall_rule(self, cmd: str):
        mac = self.target_mac.upper()
        check = subprocess.run(
            [cmd, "-C", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
            capture_output=True,
        )
        if check.returncode != 0:
            subprocess.run(
                [cmd, "-A", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                check=True,
            )

    def _remove_firewall_rule(self, cmd: str):
        mac = self.target_mac.upper()
        while True:
            result = subprocess.run(
                [cmd, "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                capture_output=True,
            )
            if result.returncode != 0:
                break

    def _add_all_rules(self):
        self._add_firewall_rule("iptables")
        self._add_firewall_rule("ip6tables")

    def _remove_all_rules(self):
        self._remove_firewall_rule("iptables")
        self._remove_firewall_rule("ip6tables")

    # --- Spoof loops ---

    def _spoof_loop(self):
        if not self.target_ip:
            logger.error("[%s] Cannot ARP spoof: target IP unknown", self.target_mac)
            return
        pkt = Ether(dst=self.target_mac) / ARP(
            op="is-at", psrc=self.gateway_ip,
            pdst=self.target_ip, hwdst=self.target_mac,
        )
        while not self._stop_event.is_set():
            sendp(pkt, iface=self.interface, verbose=False)
            self._stop_event.wait(self.arp_interval)

    def _ndp_spoof_loop(self):
        if not self.gateway_ll_addr:
            return
        na_pkt = (
            Ether(dst=self.target_mac, src=self.our_mac)
            / IPv6(src=self.gateway_ll_addr, dst="ff02::1")
            / ICMPv6ND_NA(tgt=self.gateway_ll_addr, R=1, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=self.our_mac)
        )
        ra_pkt = (
            Ether(dst=self.target_mac, src=self.our_mac)
            / IPv6(src=self.gateway_ll_addr, dst="ff02::1")
            / ICMPv6ND_RA(routerlifetime=0)
            / ICMPv6NDOptSrcLLAddr(lladdr=self.our_mac)
        )
        while not self._stop_event.is_set():
            sendp(na_pkt, iface=self.interface, verbose=False)
            sendp(ra_pkt, iface=self.interface, verbose=False)
            self._stop_event.wait(self.arp_interval)

    # --- Corrective ---

    def _send_corrective_arp(self, count: int = 5):
        if not self.target_ip or not self.gateway_mac:
            return
        pkt = Ether(dst=self.target_mac) / ARP(
            op="is-at", psrc=self.gateway_ip, hwsrc=self.gateway_mac,
            pdst=self.target_ip, hwdst=self.target_mac,
        )
        bcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op="is-at", psrc=self.gateway_ip, hwsrc=self.gateway_mac,
        )
        for _ in range(count):
            sendp(pkt, iface=self.interface, verbose=False)
            sendp(bcast, iface=self.interface, verbose=False)

    def _send_corrective_ndp(self, count: int = 5):
        if not self.gateway_ll_addr or not self.gateway_mac:
            return
        pkt = (
            Ether(dst=self.target_mac, src=self.gateway_mac)
            / IPv6(src=self.gateway_ll_addr, dst="ff02::1")
            / ICMPv6ND_NA(tgt=self.gateway_ll_addr, R=1, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=self.gateway_mac)
        )
        for _ in range(count):
            sendp(pkt, iface=self.interface, verbose=False)

    # --- Public API ---

    async def block(self):
        if self._spoofing:
            return
        self._add_all_rules()
        self._stop_event.clear()
        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()
        if self.gateway_ll_addr:
            self._ndp_thread = threading.Thread(target=self._ndp_spoof_loop, daemon=True)
            self._ndp_thread.start()
        self._spoofing = True
        logger.info("[%s] Blocking ACTIVE", self.target_mac)

    async def unblock(self):
        if not self._spoofing:
            self._remove_all_rules()
            return
        self._stop_event.set()
        if self._spoof_thread:
            self._spoof_thread.join(timeout=5)
            self._spoof_thread = None
        if self._ndp_thread:
            self._ndp_thread.join(timeout=5)
            self._ndp_thread = None
        self._spoofing = False
        self._remove_all_rules()
        self._send_corrective_arp()
        self._send_corrective_ndp()
        logger.info("[%s] Blocking INACTIVE", self.target_mac)

    @property
    def is_blocking(self) -> bool:
        return self._spoofing


class BlockerManager:
    """Manages TargetBlocker instances for all targets."""

    def __init__(self):
        self.gateway_ip = settings.gateway_ip
        self.interface = settings.interface
        self.arp_interval = settings.arp_interval
        self.gateway_mac: str | None = None
        self.gateway_ll_addr: str | None = None
        self.our_mac: str | None = None
        self._blockers: dict[int, TargetBlocker] = {}
        self._lock = threading.Lock()

    def init(self):
        """Discover gateway (run once at startup, in a thread)."""
        conf.verb = 0
        # Gateway MAC
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.gateway_ip),
            timeout=3, iface=self.interface,
        )
        if not ans:
            raise RuntimeError(f"Could not resolve gateway MAC for {self.gateway_ip}")
        self.gateway_mac = ans[0][1].hwsrc.lower()
        logger.info("Gateway MAC: %s", self.gateway_mac)

        # Our MAC
        self.our_mac = get_if_hwaddr(self.interface)
        logger.info("Our MAC: %s", self.our_mac)

        # Gateway IPv6 link-local
        try:
            pkts = sniff(
                iface=self.interface,
                filter="icmp6 and ip6[40] == 134",
                timeout=10, count=1,
            )
            if pkts:
                self.gateway_ll_addr = pkts[0][IPv6].src
                logger.info("Gateway IPv6 LL (sniffed): %s", self.gateway_ll_addr)
        except Exception:
            pass
        if not self.gateway_ll_addr:
            parts = self.gateway_mac.split(":")
            parts[0] = f"{int(parts[0], 16) ^ 0x02:02x}"
            eui = f"{parts[0]}{parts[1]}:{parts[2]}ff:fe{parts[3]}:{parts[4]}{parts[5]}"
            self.gateway_ll_addr = f"fe80::{eui}"
            logger.info("Gateway IPv6 LL (derived): %s", self.gateway_ll_addr)

    def add_target(self, target_id: int, mac: str) -> TargetBlocker:
        blocker = TargetBlocker(
            target_id=target_id,
            target_mac=mac,
            gateway_ip=self.gateway_ip,
            gateway_mac=self.gateway_mac,
            our_mac=self.our_mac,
            interface=self.interface,
            arp_interval=self.arp_interval,
            gateway_ll_addr=self.gateway_ll_addr,
        )
        blocker.discover_target_ip()
        with self._lock:
            self._blockers[target_id] = blocker
        logger.info("Added target %d (%s) IP=%s", target_id, mac, blocker.target_ip)
        return blocker

    async def remove_target(self, target_id: int):
        with self._lock:
            blocker = self._blockers.pop(target_id, None)
        if blocker:
            await blocker.unblock()

    def get_blocker(self, target_id: int) -> TargetBlocker | None:
        return self._blockers.get(target_id)

    async def shutdown(self):
        with self._lock:
            blockers = list(self._blockers.values())
        for b in blockers:
            await b.unblock()
        logger.info("All targets unblocked")
