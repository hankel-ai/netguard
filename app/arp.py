import asyncio
import logging
import subprocess
import threading

from scapy.all import (
    Ether, ARP, IPv6,
    ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr,
    ICMPv6NDOptPrefixInfo,
    sendp, srp, sniff, conf, get_if_hwaddr,
)

from app.config import settings

logger = logging.getLogger("netguard.arp")


class ArpBlocker:
    def __init__(self):
        self.target_mac: str = settings.target_mac.lower()
        self.gateway_ip: str = settings.gateway_ip
        self.interface: str = settings.interface
        self.arp_interval: float = settings.arp_interval
        self.gateway_mac: str | None = None
        self.gateway_ll_addr: str | None = None  # gateway's IPv6 link-local
        self.our_mac: str | None = None  # this host's MAC on the interface
        self.target_ip: str | None = None
        self.target_ll_addr: str | None = None  # target's IPv6 link-local
        self._spoofing: bool = False
        self._spoof_thread: threading.Thread | None = None
        self._ndp_thread: threading.Thread | None = None
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

    def discover_gateway_ipv6_ll(self) -> str | None:
        """Discover gateway's IPv6 link-local by sniffing for Router Advertisements."""
        logger.info("Listening for IPv6 Router Advertisement (up to 10s)...")
        try:
            pkts = sniff(
                iface=self.interface,
                filter="icmp6 and ip6[40] == 134",  # RA type
                timeout=10,
                count=1,
            )
            if pkts:
                ra = pkts[0]
                src_ip = ra[IPv6].src
                logger.info("Gateway IPv6 link-local: %s", src_ip)
                return src_ip
        except Exception as e:
            logger.warning("Could not sniff RA: %s", e)
        # Fallback: derive from gateway MAC using EUI-64
        if self.gateway_mac:
            ll = self._mac_to_ll(self.gateway_mac)
            logger.info("Gateway IPv6 link-local (derived from MAC): %s", ll)
            return ll
        logger.warning("Could not determine gateway IPv6 link-local")
        return None

    @staticmethod
    def _mac_to_ll(mac: str) -> str:
        """Convert MAC to IPv6 link-local via modified EUI-64."""
        parts = mac.split(":")
        # Flip the 7th bit of the first octet
        parts[0] = f"{int(parts[0], 16) ^ 0x02:02x}"
        eui64 = f"{parts[0]}{parts[1]}:{parts[2]}ff:fe{parts[3]}:{parts[4]}{parts[5]}"
        return f"fe80::{eui64}"

    def _add_firewall_rule(self, cmd: str):
        """Add a FORWARD DROP rule if not already present. cmd is 'iptables' or 'ip6tables'."""
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
            logger.info("%s DROP rule added", cmd)

    def _remove_firewall_rule(self, cmd: str):
        """Remove all FORWARD DROP rules for target MAC. cmd is 'iptables' or 'ip6tables'."""
        mac = self.target_mac.upper()
        while True:
            result = subprocess.run(
                [cmd, "-D", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"],
                capture_output=True,
            )
            if result.returncode != 0:
                break
        logger.info("%s DROP rule(s) removed", cmd)

    def _add_iptables_rule(self):
        self._add_firewall_rule("iptables")
        self._add_firewall_rule("ip6tables")

    def _remove_iptables_rule(self):
        self._remove_firewall_rule("iptables")
        self._remove_firewall_rule("ip6tables")

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

    def _ndp_spoof_loop(self):
        """Poison target's IPv6 neighbor cache: gateway's link-local -> our MAC."""
        if not self.gateway_ll_addr:
            logger.warning("No gateway IPv6 link-local — IPv6 NDP spoofing inactive")
            return

        # Fake Neighbor Advertisement: "gateway's link-local is at OUR MAC"
        # Sent to ff02::1 (all-nodes multicast) — every host listens on it.
        # Unicast to target MAC at L2 so only it receives the frame.
        # R=1 (router), S=0 (unsolicited), O=1 (override) to force cache update.
        na_pkt = (
            Ether(dst=self.target_mac, src=self.our_mac)
            / IPv6(src=self.gateway_ll_addr, dst="ff02::1")
            / ICMPv6ND_NA(tgt=self.gateway_ll_addr, R=1, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=self.our_mac)
        )

        # Also send spoofed RA with lifetime=0 to kill the default route
        ra_pkt = (
            Ether(dst=self.target_mac, src=self.our_mac)
            / IPv6(src=self.gateway_ll_addr, dst="ff02::1")
            / ICMPv6ND_RA(routerlifetime=0)
            / ICMPv6NDOptSrcLLAddr(lladdr=self.our_mac)
        )

        logger.info(
            "Starting NDP spoof loop (gateway_ll=%s -> our_mac=%s)",
            self.gateway_ll_addr, self.our_mac,
        )
        while not self._stop_event.is_set():
            sendp(na_pkt, iface=self.interface, verbose=False)
            sendp(ra_pkt, iface=self.interface, verbose=False)
            self._stop_event.wait(self.arp_interval)

    def _send_corrective_ndp(self, count: int = 5):
        """Restore correct gateway neighbor entry on the target."""
        if not self.gateway_ll_addr or not self.gateway_mac:
            return
        # Correct NA: gateway's link-local -> gateway's real MAC
        na_pkt = (
            Ether(dst=self.target_mac, src=self.gateway_mac)
            / IPv6(src=self.gateway_ll_addr, dst="ff02::1")
            / ICMPv6ND_NA(tgt=self.gateway_ll_addr, R=1, S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=self.gateway_mac)
        )
        for _ in range(count):
            sendp(na_pkt, iface=self.interface, verbose=False)
        logger.info("Sent %d corrective NDP packets", count)

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
        if self.gateway_ll_addr:
            self._ndp_thread = threading.Thread(target=self._ndp_spoof_loop, daemon=True)
            self._ndp_thread.start()
        self._spoofing = True
        logger.info("Blocking ACTIVE (IPv4 + IPv6)")

    async def unblock(self):
        if not self._spoofing:
            # Still clean up iptables in case of leftover rules
            self._remove_iptables_rule()
            return
        self._stop_event.set()
        if self._spoof_thread:
            self._spoof_thread.join(timeout=5)
            self._spoof_thread = None
        if self._ndp_thread:
            self._ndp_thread.join(timeout=5)
            self._ndp_thread = None
        self._spoofing = False
        self._remove_iptables_rule()
        self._send_corrective_arp()
        self._send_corrective_ndp()
        logger.info("Blocking INACTIVE (IPv4 + IPv6)")

    @property
    def is_blocking(self) -> bool:
        return self._spoofing

    def init(self):
        """Run discovery (call from startup, in a thread)."""
        self.gateway_mac = self.discover_gateway_mac()
        self.target_ip = self.discover_target_ip()
        self.our_mac = get_if_hwaddr(self.interface)
        logger.info("Our MAC: %s", self.our_mac)
        self.gateway_ll_addr = self.discover_gateway_ipv6_ll()
        self.target_ll_addr = self._mac_to_ll(self.target_mac)
        logger.info("Target IPv6 link-local (derived): %s", self.target_ll_addr)
